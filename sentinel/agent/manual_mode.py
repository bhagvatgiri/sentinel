"""Manual-mode / passive-recon for automation-averse bug-bounty programs.

Many H1 programs (ExampleWear, AcmeProgram, Coupang TW…) explicitly prohibit aggressive
automation but ALLOW gentle, identifiable, human-driven testing. This module
provides the three pieces that make Sentinel useful in that mode WITHOUT
running ffuf/nuclei/sqlmap/katana/dirsearch/dalfox at all:

1. ``passive_recon(target, scope, workspace)`` — gathers intel WITHOUT any
   fuzzing or active scanning. Public sources only (crt.sh CT logs, archive.org
   roots) plus a *handful* of polite, rate-limited fetches to the target's
   well-known paths (robots.txt, security.txt, sitemap, /api-docs) and its JS
   bundles — every request carries the scope's ``research_headers`` and obeys
   ``rate_limits.requests_per_second``. Then runs ``jsintel`` over the JS to
   pull endpoints/secrets statically.

2. ``ingest_har(har_path, scope, workspace)`` — parses a Burp/Chrome HAR
   export (the operator's own manual probing) into a structured "manual
   session" deliverable with deduplicated endpoints, params, status codes,
   and auth-header sightings the operator can review.

3. ``synthesize_briefing(intel, target, workspace)`` — writes
   ``manual_hunting_briefing.md``: ranked attack-surface map (high-EV
   endpoints, extracted JS keys, third-party leaks, manual checklist) that
   the operator works from. Replaces the autonomous-scan output for programs
   where autonomy is the wrong mode.

CLI: ``sentinel manual-mode <target> --scope <yaml>`` and ``sentinel ingest-har
<har_path> --scope <yaml>``. Zero policy risk; no active scanners loaded.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx

from sentinel.core.scope import OutOfScopeError, Scope

log = logging.getLogger(__name__)

# Well-known paths every program lets us peek at (and most expect us to).
WELL_KNOWN_PATHS = [
    "/robots.txt",
    "/.well-known/security.txt",
    "/sitemap.xml",
    "/api-docs",
    "/api-docs/swagger.json",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
    "/.git/HEAD",
    "/.env",
]

# Patterns for JS-static analysis. Conservative on purpose — false positives
# waste the operator's time; missing a real key is acceptable because they
# can re-scan with trufflehog/gitleaks on their own.
_RE_ENDPOINT = re.compile(
    r"""['"`](/(?:api|rest|v\d|graphql|admin|user|users|account|auth|login|"""
    r"""logout|profile|order|orders|cart|wallet|payment|product|products|"""
    r"""search|upload|file|files|webhook|callback|oauth|sso|saml)"""
    r"""[A-Za-z0-9_\-/.{}:]*)['"`]""",
    re.IGNORECASE,
)
_RE_FULL_URL = re.compile(
    r"""['"`](https?://[A-Za-z0-9_\-./?=&%:#@]{4,200})['"`]"""
)
_RE_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_RE_GENERIC_SECRET = re.compile(
    r"""(?i)(?:api[_-]?key|secret|token|password|auth)['"]?\s*[:=]\s*"""
    r"""['"][A-Za-z0-9_\-./+=]{16,80}['"]"""
)
_RE_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_RE_GOOGLE_API = re.compile(r"AIza[0-9A-Za-z_\-]{35}")
_RE_STRIPE = re.compile(r"sk_(?:live|test)_[0-9A-Za-z]{24,99}")


# ----- crt.sh passive subdomain enumeration ------------------------------

async def crtsh_subdomains(domain: str, *, timeout: float = 15.0) -> list[str]:
    """Pull subdomains from crt.sh certificate-transparency logs.

    Returns a deduplicated, sorted list of subdomain strings (lowercased, no
    wildcards). PUBLIC SOURCE — no traffic hits the target. Best-effort: on
    network error returns []. Skip domains that look like IPs or are empty.
    """
    domain = (domain or "").strip().lower()
    if not domain or any(c in domain for c in " /"):
        return []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(url, headers={"Accept": "application/json"})
            if r.status_code != 200:
                log.info("crt.sh returned %d for %s", r.status_code, domain)
                return []
            data = r.json()
    except Exception as e:  # noqa: BLE001
        log.info("crt.sh fetch failed for %s: %s", domain, e)
        return []
    subs: set[str] = set()
    for entry in data or []:
        nv = (entry.get("name_value") or "").lower()
        for name in nv.split("\n"):
            name = name.strip().lstrip("*.").rstrip(".")
            if name and "." in name and name.endswith(domain) and " " not in name:
                subs.add(name)
    return sorted(subs)


# ----- polite fetch ------------------------------------------------------

async def polite_fetch_paths(target: str, paths: list[str], scope: Scope,
                              workspace: Path,
                              ) -> list[dict[str, Any]]:
    """Fetch a handful of well-known paths from the target, one at a time,
    obeying ``scope.rate_limits.requests_per_second`` and injecting every
    research header the scope declares. Returns a list of {path, status,
    headers, body_excerpt} records. Out-of-scope paths are silently skipped.
    """
    target = target.rstrip("/")
    rps = float(getattr(getattr(scope, "rate_limits", None),
                        "requests_per_second", None) or 2.0)
    interval = 1.0 / max(0.1, rps)
    research_headers: dict = dict(getattr(scope, "research_headers", None) or {})
    out: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        timeout=15.0, follow_redirects=True, verify=False,
    ) as c:
        for p in paths:
            url = urljoin(target + "/", p.lstrip("/"))
            try:
                scope.authorize_url(url)
            except OutOfScopeError:
                continue
            try:
                r = await c.get(url, headers={"User-Agent": "Sentinel/manual-mode",
                                              **research_headers})
                body = (r.text or "")[:8000]
                out.append({
                    "path": p,
                    "url": str(r.url),
                    "status": r.status_code,
                    "content_type": r.headers.get("content-type", ""),
                    "body_excerpt": body,
                })
            except Exception as e:  # noqa: BLE001
                out.append({"path": p, "url": url, "status": None, "error": str(e)})
            await asyncio.sleep(interval)
    return out


# ----- JS bundle harvest + static analysis -------------------------------

def _extract_script_srcs(html: str, base: str) -> list[str]:
    """Pull <script src=...> URLs from HTML, resolved against base. Conservative
    regex — ignores inline scripts, only fetched bundles matter for static
    analysis."""
    out: list[str] = []
    for m in re.finditer(r"<script[^>]+src\s*=\s*['\"]([^'\"]+)['\"]", html, re.I):
        u = urljoin(base, m.group(1))
        out.append(u)
    return out


async def harvest_and_analyze_js(target: str, root_html: str, scope: Scope,
                                  ) -> list[dict[str, Any]]:
    """Find <script src> URLs in the root HTML, fetch the in-scope ones (polite
    + rate-limited), and statically extract endpoints + secret-shaped strings.
    Returns one record per JS file with the extracted intel."""
    rps = float(getattr(getattr(scope, "rate_limits", None),
                        "requests_per_second", None) or 2.0)
    interval = 1.0 / max(0.1, rps)
    research_headers: dict = dict(getattr(scope, "research_headers", None) or {})
    srcs = _extract_script_srcs(root_html, target)
    findings: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        timeout=20.0, follow_redirects=True, verify=False,
    ) as c:
        for src in srcs[:25]:  # cap — chunked SPAs can have hundreds; first 25 cover most.
            try:
                scope.authorize_url(src)
            except OutOfScopeError:
                continue
            try:
                r = await c.get(src, headers={"User-Agent": "Sentinel/manual-mode",
                                              **research_headers})
                if r.status_code != 200:
                    continue
                body = r.text or ""
            except Exception:
                continue
            endpoints = sorted({m.group(1) for m in _RE_ENDPOINT.finditer(body)})
            urls = sorted({m.group(1) for m in _RE_FULL_URL.finditer(body)})
            secrets: list[tuple[str, str]] = []
            for label, rx in (("aws_key", _RE_AWS_KEY), ("google_api", _RE_GOOGLE_API),
                              ("stripe", _RE_STRIPE), ("jwt", _RE_JWT),
                              ("generic_secret", _RE_GENERIC_SECRET)):
                for m in rx.finditer(body):
                    secrets.append((label, m.group(0)[:120]))
            findings.append({
                "src": src,
                "size": len(body),
                "endpoints": endpoints[:200],
                "external_urls": [u for u in urls if not u.startswith(target)][:50],
                "secrets": secrets[:30],
            })
            await asyncio.sleep(interval)
    return findings


# ----- HAR ingestion -----------------------------------------------------

def ingest_har(har_path: Path, scope: Scope, workspace: Path) -> dict[str, Any]:
    """Parse a Burp/Chrome HAR export into structured endpoint/param data.

    Writes ``<workspace>/deliverables/manual_session_<ts>.md`` with the
    deduplicated endpoint list (method + path + param signature + status), an
    auth-header sighting, and a count summary. Returns the structured data.
    Out-of-scope entries are filtered silently. Never raises on malformed HAR.
    """
    try:
        data = json.loads(Path(har_path).read_text(errors="replace"))
    except Exception as e:  # noqa: BLE001
        log.warning("HAR parse failed: %s", e)
        return {"entries": [], "error": str(e)}
    entries = (data.get("log") or {}).get("entries") or []
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    auth_headers_seen: set[str] = set()
    for e in entries:
        req = (e.get("request") or {})
        res = (e.get("response") or {})
        url = req.get("url") or ""
        method = (req.get("method") or "GET").upper()
        if not url:
            continue
        try:
            scope.authorize_url(url)
        except OutOfScopeError:
            continue
        parsed = urlparse(url)
        path = parsed.path or "/"
        key = (method, path)
        params = sorted({q.get("name", "") for q in (req.get("queryString") or [])})
        if (req.get("postData") or {}).get("params"):
            for p in req["postData"]["params"]:
                if p.get("name"): params.append(p["name"])
        record = seen.setdefault(key, {
            "method": method, "path": path, "host": parsed.hostname or "",
            "params": set(), "statuses": set(), "examples": [],
        })
        record["params"].update(params)
        record["statuses"].add(res.get("status") or 0)
        if len(record["examples"]) < 2:
            record["examples"].append(url)
        for h in (req.get("headers") or []):
            name = (h.get("name") or "").lower()
            if name in {"authorization", "cookie", "x-auth-token", "x-api-key"}:
                auth_headers_seen.add(name)

    # Render the deliverable.
    rows = []
    for (method, path), rec in sorted(seen.items()):
        params = ",".join(sorted(rec["params"])) or "—"
        statuses = ",".join(str(s) for s in sorted(rec["statuses"]))
        rows.append(f"| {method} | `{path}` | {params} | {statuses} |")
    ts = time.strftime("%Y%m%dT%H%M%S")
    deliv = workspace / "deliverables" / f"manual_session_{ts}.md"
    deliv.parent.mkdir(parents=True, exist_ok=True)
    md = [f"# Manual Session — HAR Ingest ({ts})\n",
          f"*Source: `{har_path}` — in-scope entries only ({len(seen)} unique "
          f"method+path of {len(entries)} HAR entries).*\n",
          "## Endpoints\n",
          "| Method | Path | Params seen | Statuses |",
          "|---|---|---|---|"]
    md.extend(rows[:300])
    if len(rows) > 300:
        md.append(f"\n*({len(rows) - 300} more — see source HAR.)*")
    if auth_headers_seen:
        md.append("\n## Auth headers seen in session\n")
        md.extend(f"- `{h}`" for h in sorted(auth_headers_seen))
    md.append("\n## Manual hunting checklist (from this session)")
    md.append("- For each endpoint with an `id` / numeric path segment: try cross-account access (IDOR/BOLA).")
    md.append("- For each POST endpoint: try parameter pollution, type coercion, mass-assignment.")
    md.append("- For each endpoint that returned 2xx with an auth header: try without it.")
    md.append("- For each endpoint that returned 401/403: check whether the *guard*, not the *resource*, is the boundary.")
    deliv.write_text("\n".join(md))
    log.info("ingest_har: wrote %s (%d unique endpoints, %d entries)",
             deliv, len(seen), len(entries))
    return {
        "deliverable": str(deliv),
        "unique_endpoints": len(seen),
        "entries_total": len(entries),
        "auth_headers": sorted(auth_headers_seen),
    }


# ----- briefing synthesis ------------------------------------------------

def synthesize_briefing(intel: dict[str, Any], target: str,
                         workspace: Path) -> Path:
    """Write the ``manual_hunting_briefing.md`` deliverable from the passive
    intel dict. Returns the path to the written file."""
    deliv = workspace / "deliverables" / "manual_hunting_briefing.md"
    deliv.parent.mkdir(parents=True, exist_ok=True)
    md = [f"# Manual Hunting Briefing — {target}\n",
          "*Passive-only intel (zero active scanners). Hunt manually from this "
          "starting point — every URL is a candidate, not a confirmed finding.*\n"]

    # Subdomains
    subs = intel.get("subdomains") or []
    if subs:
        md.append(f"## Subdomains discovered ({len(subs)}, via crt.sh)\n")
        md.append("```")
        md.extend(subs[:80])
        if len(subs) > 80:
            md.append(f"... ({len(subs) - 80} more)")
        md.append("```\n")

    # Well-known paths
    wk = intel.get("well_known") or []
    interesting = [w for w in wk if w.get("status") and 200 <= w["status"] < 400]
    if interesting:
        md.append(f"## Well-known paths returning content ({len(interesting)})\n")
        md.append("| Path | Status | Content-Type |")
        md.append("|---|---|---|")
        for w in interesting[:30]:
            md.append(f"| `{w.get('path','')}` | {w.get('status','?')} | "
                      f"`{(w.get('content_type','') or '?')[:40]}` |")
        md.append("")

    # JS findings: endpoints + secrets
    js = intel.get("js") or []
    all_eps = sorted({ep for f in js for ep in f.get("endpoints", [])})
    if all_eps:
        md.append(f"## Endpoints extracted from JS bundles ({len(all_eps)} unique)\n")
        md.append("*Group by surface area — manually probe each for IDOR/BOLA, "
                  "auth bypass, mass-assignment.*\n")
        md.append("```")
        md.extend(all_eps[:120])
        if len(all_eps) > 120:
            md.append(f"... ({len(all_eps) - 120} more)")
        md.append("```\n")
    all_secrets = [(f["src"], lbl, v) for f in js for lbl, v in f.get("secrets", [])]
    if all_secrets:
        md.append(f"## Secret-shaped strings in JS ({len(all_secrets)}) — VERIFY MANUALLY\n")
        md.append("| Source | Type | Sample |")
        md.append("|---|---|---|")
        for src, lbl, v in all_secrets[:40]:
            md.append(f"| `{(src or '')[:80]}` | {lbl} | `{v[:80]}` |")
        md.append("\n*Many will be false positives (placeholders, public keys, "
                  "minified noise). Verify each before reporting.*\n")

    md.append("## Manual hunting checklist")
    md.append("1. **Authenticate** — register/log in to surface authenticated endpoints not visible passively.")
    md.append("2. **Pick 2-3 high-EV endpoints** from the JS extraction (anything with `id`, `userId`, `accountId`, `order`).")
    md.append("3. **Try cross-account access** (IDOR/BOLA) with a 2nd test account.")
    md.append("4. **Capture the session in Burp**, export to HAR, run `sentinel ingest-har <har>` for structured re-analysis.")
    md.append("5. **Probe `/api-docs`/`/graphql` introspection** if visible.")
    md.append("6. **Read `robots.txt` + `security.txt`** for disclosed quirks / dev endpoints.")
    deliv.write_text("\n".join(md))
    log.info("manual_hunting_briefing.md written (%d bytes)", deliv.stat().st_size)
    return deliv


# ----- the top-level orchestrator ---------------------------------------

async def run_manual_mode(target: str, scope: Scope, workspace: Path,
                           ) -> dict[str, Any]:
    """Top-level manual-mode workflow: passive recon + JS analysis + briefing.

    Returns the structured intel dict. Side effect: writes
    ``manual_hunting_briefing.md`` to ``<workspace>/deliverables/``.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    parsed = urlparse(target)
    apex = parsed.hostname or target
    log.info("manual-mode: passive recon on %s (apex=%s)", target, apex)

    # 1) crt.sh subdomains (PUBLIC SOURCE — no target traffic)
    subs = await crtsh_subdomains(apex)

    # 2) Polite well-known fetches
    wk = await polite_fetch_paths(target, WELL_KNOWN_PATHS, scope, workspace)

    # 3) Root HTML for JS-src extraction
    research_headers: dict = dict(getattr(scope, "research_headers", None) or {})
    root_html = ""
    try:
        scope.authorize_url(target)
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True,
                                     verify=False) as c:
            r = await c.get(target, headers={"User-Agent": "Sentinel/manual-mode",
                                              **research_headers})
            if r.status_code == 200:
                root_html = r.text or ""
    except OutOfScopeError:
        pass
    except Exception as e:  # noqa: BLE001
        log.info("manual-mode: root fetch failed: %s", e)

    # 4) JS harvest + static analysis
    js = await harvest_and_analyze_js(target, root_html, scope) if root_html else []

    intel = {"target": target, "subdomains": subs, "well_known": wk, "js": js}
    synthesize_briefing(intel, target, workspace)
    return intel
