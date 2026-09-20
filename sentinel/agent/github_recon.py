"""GitHub recon — passive intel from a target's public repos.

Implements the workflow from the "frontend recon without touching the app"
article: enumerate the target's GitHub org(s), walk public repos + their
commit history, surface leaked secrets / internal endpoints / config files
that the target accidentally shipped publicly. Zero traffic to the target's
production app — pure GitHub data. Fits every program policy (automation-
averse and automation-friendly alike); often the highest-EV passive vector.

Delegates the actual secret detection to ``trufflehog`` (binary on PATH —
already in Sentinel's tool inventory) which walks commit history including
deleted code. Falls back to a graceful "tool missing" message if absent.

Public API:
  - ``derive_org_candidates(target)``  — guess org names from a target URL.
  - ``enumerate_org_repos(org, token)`` — list public repos via GitHub API.
  - ``run_trufflehog_org(org, work_dir, token, max_repos)`` — scan an org.
  - ``synthesize_github_briefing(scan, target, workspace)`` — write the deliverable.
  - ``run_github_recon(target, workspace, *, orgs=None, token=None)`` — orchestrator.

CLI: wired via ``sentinel github-recon <target> --scope <yaml>`` and called
as a pre-recon step by ``sentinel manual-mode`` + ``sentinel scan-autonomous``
when ``--github-recon`` (or the operator-provided org) is set.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

log = logging.getLogger(__name__)


# ----- org-name derivation -----------------------------------------------

def derive_org_candidates(target: str) -> list[str]:
    """Best-effort guess of a target's GitHub org handle(s) from its URL.

    ``https://api.coupang.com`` → ``['coupang']``.
    ``https://staging.acme-corp.com`` → ``['acme-corp', 'acmecorp']``.
    Returns up to 4 candidates ordered most-likely first. The operator can
    always override via ``--github-org`` on the CLI — this is just a sane
    default so a no-flag invocation does something useful.
    """
    host = urlparse(target if "://" in target else f"https://{target}").hostname or ""
    if not host:
        return []
    # strip common subdomains
    parts = host.lower().split(".")
    parts = [p for p in parts if p not in
             {"www", "api", "app", "auth", "staging", "dev", "admin", "m",
              "secure", "login", "portal", "test", "demo"}]
    if not parts:
        return []
    apex = parts[-2] if len(parts) >= 2 else parts[0]
    out = [apex]
    # Hyphen variant: "acme-corp" ↔ "acmecorp"
    if "-" in apex:
        out.append(apex.replace("-", ""))
    else:
        # No-hyphen → no variant.
        pass
    # ".co" / ".io" / ".dev" company TLDs often = single word
    if len(parts) >= 2 and parts[-1] in {"co", "io", "dev", "ai", "app"}:
        out.append(parts[-2])
    # dedupe-preserve-order
    seen: set[str] = set()
    return [o for o in out if not (o in seen or seen.add(o))][:4]


# ----- GitHub API enumeration --------------------------------------------

GH_API = "https://api.github.com"


def _gh_headers(token: Optional[str]) -> dict:
    h = {"Accept": "application/vnd.github+json",
         "User-Agent": "Sentinel/github-recon",
         "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def enumerate_org_repos(org: str, token: Optional[str] = None,
                        *, max_repos: int = 200, timeout: float = 15.0,
                        ) -> list[dict[str, Any]]:
    """List public repos for ``org`` via the GitHub API.

    Without a token: ~60 req/hr rate limit (enough for a few orgs but rough).
    With a token: ~5000/hr. Returns ``[]`` if the org doesn't exist (404),
    has no public repos, or the API is rate-limited. Best-effort — never raises.
    """
    repos: list[dict[str, Any]] = []
    page = 1
    try:
        with httpx.Client(timeout=timeout, headers=_gh_headers(token)) as c:
            while len(repos) < max_repos:
                url = f"{GH_API}/orgs/{org}/repos"
                r = c.get(url, params={"per_page": 100, "page": page,
                                       "type": "public"})
                if r.status_code == 404:
                    # Try /users/{org} fallback — sometimes a personal account.
                    if page == 1:
                        r = c.get(f"{GH_API}/users/{org}/repos",
                                  params={"per_page": 100, "page": page})
                        if r.status_code != 200:
                            return []
                    else:
                        break
                elif r.status_code == 403:
                    log.info("github API rate-limited for org=%s page=%d", org, page)
                    break
                elif r.status_code != 200:
                    log.info("github API %d for org=%s page=%d", r.status_code, org, page)
                    break
                batch = r.json() or []
                if not isinstance(batch, list) or not batch:
                    break
                repos.extend(batch)
                if len(batch) < 100:
                    break
                page += 1
    except Exception as e:  # noqa: BLE001
        log.info("github API error for %s: %s", org, e)
    # Keep just the fields we care about; sort archived last + recent first.
    out = []
    for r in repos[:max_repos]:
        if not isinstance(r, dict):
            continue
        out.append({
            "name": r.get("name", ""),
            "full_name": r.get("full_name", ""),
            "url": r.get("html_url", ""),
            "description": (r.get("description") or "")[:200],
            "stars": int(r.get("stargazers_count") or 0),
            "archived": bool(r.get("archived")),
            "pushed_at": r.get("pushed_at", ""),
        })
    out.sort(key=lambda r: (r["archived"], r["pushed_at"]), reverse=False)
    return out


# ----- trufflehog wrapper ------------------------------------------------

def _trufflehog_available() -> bool:
    return shutil.which("trufflehog") is not None


def run_trufflehog_org(org: str, work_dir: Path, *, token: Optional[str] = None,
                       max_repos: int = 50, timeout_sec: int = 1800,
                       ) -> dict[str, Any]:
    """Run ``trufflehog github --org=<org>`` and parse its JSON output.

    Returns ``{available, ok, findings, raw_path, error?}``. ``findings`` is a
    list of normalised ``{detector, repo, file, line, secret_excerpt, verified}``
    dicts. The raw trufflehog output is also persisted at ``raw_path`` for
    operator review. Best-effort: tool-missing / timeout / parse-error degrade
    cleanly to ``ok=False`` with an explanation, never raise.
    """
    if not _trufflehog_available():
        return {"available": False, "ok": False, "findings": [],
                "error": "trufflehog not on PATH; install with `brew install trufflehog`"}
    work_dir.mkdir(parents=True, exist_ok=True)
    raw_path = work_dir / "trufflehog_raw.jsonl"
    cmd = ["trufflehog", "github", f"--org={org}", "--json",
           f"--max-depth={max_repos}"]
    env = os.environ.copy()
    if token:
        env["GITHUB_TOKEN"] = token
    try:
        with raw_path.open("wb") as out:
            r = subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE,
                                env=env, timeout=timeout_sec, check=False)
    except subprocess.TimeoutExpired:
        return {"available": True, "ok": False, "findings": [],
                "error": f"trufflehog timed out after {timeout_sec}s "
                          f"(org may be very large — try --max-repos lower)"}
    except Exception as e:  # noqa: BLE001
        return {"available": True, "ok": False, "findings": [],
                "error": f"trufflehog launch failed: {e}"}
    findings: list[dict[str, Any]] = []
    try:
        for line in raw_path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            src = d.get("SourceMetadata", {}).get("Data", {}).get("Github", {})
            findings.append({
                "detector": d.get("DetectorName", "?"),
                "repo": src.get("repository", "?"),
                "file": src.get("file", "?"),
                "line": int(src.get("line") or 0),
                "commit": (src.get("commit") or "")[:12],
                "verified": bool(d.get("Verified")),
                "secret_excerpt": (d.get("Raw") or "")[:80],
            })
    except Exception as e:  # noqa: BLE001
        return {"available": True, "ok": False, "findings": [],
                "raw_path": str(raw_path),
                "error": f"trufflehog output parse failed: {e}"}
    return {"available": True, "ok": True, "findings": findings,
            "raw_path": str(raw_path),
            "stderr_tail": (r.stderr or b"").decode("utf-8", errors="replace")[-500:]}


# ----- briefing ---------------------------------------------------------

def synthesize_github_briefing(scan: dict[str, Any], target: str,
                                workspace: Path) -> Path:
    """Write ``<workspace>/deliverables/github_leaks_briefing.md`` from the
    aggregated scan result. Returns the written path."""
    deliv = workspace / "deliverables" / "github_leaks_briefing.md"
    deliv.parent.mkdir(parents=True, exist_ok=True)
    md = [f"# GitHub Recon Briefing — {target}\n",
          "*Passive intel from public GitHub repos. Zero traffic to the target's "
          "production app. Every finding here is a candidate — verify each "
          "secret/endpoint manually before reporting.*\n"]

    orgs = scan.get("orgs_scanned") or []
    md.append(f"## Orgs scanned: {', '.join(orgs) or '(none)'}\n")

    repos = scan.get("repos") or []
    if repos:
        md.append(f"## Public repos discovered ({len(repos)})\n")
        md.append("| Repo | Stars | Last push | Archived |")
        md.append("|---|---|---|---|")
        for r in repos[:30]:
            md.append(f"| [{r['full_name']}]({r['url']}) | {r['stars']} | "
                       f"{(r.get('pushed_at','') or '?')[:10]} | "
                       f"{'yes' if r.get('archived') else 'no'} |")
        if len(repos) > 30:
            md.append(f"\n*({len(repos) - 30} more — see ``trufflehog_raw.jsonl``)*\n")

    th = scan.get("trufflehog") or {}
    findings = th.get("findings") or []
    if not th.get("available"):
        md.append("\n## trufflehog: NOT INSTALLED\n")
        md.append("```\nbrew install trufflehog   # or: pipx install trufflehog\n```")
    elif not th.get("ok"):
        md.append("\n## trufflehog: failed\n")
        md.append(f"`{th.get('error','?')}`")
    elif not findings:
        md.append("\n## trufflehog: 0 findings\n")
        md.append("*Either the org is clean, or scope was too narrow. Try a "
                   "different org candidate.*")
    else:
        verified = [f for f in findings if f.get("verified")]
        md.append(f"\n## trufflehog findings — {len(findings)} raw / "
                   f"{len(verified)} VERIFIED live\n")
        md.append("**Verified-live findings (highest priority — actually authenticate):**\n")
        md.append("| Detector | Repo | File:Line | Commit | Excerpt |")
        md.append("|---|---|---|---|---|")
        for f in (verified or findings[:30]):
            md.append(f"| {f['detector']} | `{f['repo']}` | `{f['file']}:{f['line']}` "
                       f"| `{f['commit']}` | `{f['secret_excerpt']}` |")
        if not verified and len(findings) > 30:
            md.append(f"\n*({len(findings) - 30} more in trufflehog_raw.jsonl)*")

    md.append("\n## Manual hunting checklist (from this scan)")
    md.append("1. **Test every VERIFIED secret** — does it still authenticate against the target?")
    md.append("2. **Check unverified findings by detector type** — `aws_key`, `slack_webhook`, "
              "`stripe`, `database_url` are usually live even if unverified.")
    md.append("3. **Read the commit history of high-star repos** — old deleted code often "
              "leaks internal URLs (config files, CI/CD scripts, docker-compose).")
    md.append("4. **Search the `.github/workflows/` of each repo** — CI configs sometimes "
              "leak secrets in `env:` blocks or `if:` conditions.")
    md.append("5. **For any internal-looking URL found**, check whether it's in your scope "
              "before probing.")
    deliv.write_text("\n".join(md))
    log.info("github_leaks_briefing.md written (%d bytes, %d trufflehog findings)",
             deliv.stat().st_size, len(findings))
    return deliv


# ----- orchestrator -----------------------------------------------------

def run_github_recon(target: str, workspace: Path, *,
                     orgs: Optional[list[str]] = None,
                     token: Optional[str] = None,
                     max_repos: int = 50) -> dict[str, Any]:
    """Top-level: derive orgs (or accept operator-supplied), enumerate repos,
    run trufflehog, write the briefing. Returns the aggregated scan dict."""
    workspace.mkdir(parents=True, exist_ok=True)
    if not orgs:
        orgs = derive_org_candidates(target)
    if not orgs:
        log.info("github-recon: no org candidates for %s — skipping", target)
        return {"orgs_scanned": [], "repos": [], "trufflehog":
                {"available": _trufflehog_available(), "ok": False,
                 "findings": [], "error": "no org candidates derivable"}}

    log.info("github-recon: scanning orgs %s (target=%s)", orgs, target)
    repos: list[dict[str, Any]] = []
    for org in orgs:
        rs = enumerate_org_repos(org, token=token, max_repos=max_repos)
        log.info("github-recon: org=%s → %d public repos", org, len(rs))
        repos.extend(rs)

    # Run trufflehog on each org. (It walks repos itself, so we don't iterate.)
    th: dict[str, Any] = {"available": _trufflehog_available(), "ok": True,
                          "findings": [], "by_org": {}}
    if not th["available"]:
        th = {"available": False, "ok": False, "findings": [],
              "error": "trufflehog not on PATH"}
    else:
        for org in orgs:
            r = run_trufflehog_org(org, workspace / f".github-recon-{org}",
                                    token=token, max_repos=max_repos)
            th["by_org"][org] = {"ok": r.get("ok"), "n": len(r.get("findings") or []),
                                 "error": r.get("error")}
            if r.get("findings"):
                th["findings"].extend(r["findings"])
            if not r.get("ok") and not r.get("findings"):
                th["ok"] = False
                th["error"] = r.get("error")

    scan = {"target": target, "orgs_scanned": orgs, "repos": repos,
            "trufflehog": th, "ts": time.time()}
    synthesize_github_briefing(scan, target, workspace)
    return scan
