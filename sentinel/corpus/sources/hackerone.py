"""HackerOne hacktivity source — pull publicly disclosed bug bounty reports.

Uses the official HackerOne API (`/v1/hackers/hacktivity`) with the user's
API token.

KNOWN LIMITATION (verified 2026-XX-XX against live API):
The H1 REST API does NOT expose report body content (`vulnerability_information`)
to third-party authenticated callers. Both `/v1/hackers/hacktivity` (list) and
`/v1/hackers/reports/{id}` (detail with `?include=activities,summaries`) return
the field as None / empty for every disclosed report. As a result this source
only ingests METADATA: title, program, severity, CWE/CVE refs, bounty, URL.
The `--hackerone-full-bodies` flag spins through 4,950 per-report fetches and
caches them, but the cached JSONs have no body content. Tests in
tests/test_hackerone_full_bodies.py mock vulnerability_information as present,
so the gap was hidden until live verification.

Practical body-retrieval paths (none implemented here):
  1. Playwright/CloakBrowser scrape of public hackerone.com/reports/<id> pages
     (SPA-rendered — vanilla curl returns a 3.6KB JS shell)
  2. Reverse-engineer H1's internal GraphQL endpoint (ToS-grey, brittle)
  3. Ingest a community hacktivity-mirror dataset on GitHub

Authentication:
- HACKERONE_API_USERNAME and HACKERONE_API_TOKEN env vars, OR
- a key=value file at ~/.config/sentinel/hackerone.env

Rate-limit:
- HackerOne allows 600 req/min = 10 rps. We default to 5 rps to be polite
  and to leave headroom for retries.

Pagination:
- The API uses `page[number]=N` and `page[size]=N` (max 100 per page).
- Stops when a page returns < page_size items.

Idempotent: Document.id is derived from the report number, so re-ingest
upserts existing chunks instead of duplicating.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable, Optional

from sentinel.corpus.document import Document
from sentinel.corpus.sources.base import Source


log = logging.getLogger(__name__)


HACKERONE_API_BASE = "https://api.hackerone.com/v1/hackers/hacktivity"
HACKERONE_REPORT_BASE = "https://api.hackerone.com/v1/hackers/reports/"
DEFAULT_PAGE_SIZE = 100  # HackerOne ignores this and caps at 50 per page
DEFAULT_RATE_LIMIT_RPS = 5.0
# Per-report fetch is gentler — disclosed-body downloads are not the
# hacktivity-list endpoint, and we don't want to thump H1 with 5 rps just
# to backfill bodies. Defaults to 1 rps.
DEFAULT_FULL_BODY_RPS = 1.0
# HackerOne hacktivity API caps pagination at page 99 (HTTP 400 beyond that).
# At ~50 disclosed items per page that's a ceiling of ~4,950 most-recent
# disclosed reports — that's the entire reachable hacktivity backlog.
HACKERONE_MAX_PAGE = 99
# Subdirectory under work_dir where per-report JSON bodies are cached so
# subsequent ingest runs can skip already-downloaded reports.
FULL_BODIES_DIR = "full-bodies"


class HackerOneCredsError(RuntimeError):
    pass


def _load_creds() -> tuple[str, str]:
    """Resolve HackerOne API username + token from env or config file."""
    username = os.environ.get("HACKERONE_API_USERNAME")
    token = os.environ.get("HACKERONE_API_TOKEN")
    if username and token:
        return username, token
    cfg = Path("~/.config/sentinel/hackerone.env").expanduser()
    if cfg.is_file():
        env: dict[str, str] = {}
        for line in cfg.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, _, v = line.strip().partition("=")
                env[k.strip()] = v.strip()
        username = username or env.get("HACKERONE_API_USERNAME")
        token = token or env.get("HACKERONE_API_TOKEN")
    if not username or not token:
        raise HackerOneCredsError(
            "HackerOne credentials not found. Set HACKERONE_API_USERNAME + "
            "HACKERONE_API_TOKEN env vars, or write them to "
            "~/.config/sentinel/hackerone.env (key=value, one per line). "
            "Get an API token from hackerone.com → Settings → API Tokens."
        )
    return username, token


class HackerOneSource(Source):
    name = "hackerone"

    def __init__(
        self,
        max_reports: Optional[int] = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        rate_limit_rps: float = DEFAULT_RATE_LIMIT_RPS,
        only_disclosed: bool = True,
        full_bodies: bool = False,
        full_bodies_rps: float = DEFAULT_FULL_BODY_RPS,
        full_bodies_max: Optional[int] = None,
    ):
        self.max_reports = max_reports
        self.page_size = min(max(1, page_size), 100)
        self.rate_limit_rps = max(0.5, rate_limit_rps)
        self.only_disclosed = only_disclosed
        # Phase D (2026-XX-XX): opt-in second pass that fetches the full
        # `vulnerability_information` body for each disclosed report. The
        # hacktivity list endpoint omits bodies, so without this flag the
        # corpus only gets title + program + severity + CWE/CVE metadata.
        self.full_bodies = full_bodies
        self.full_bodies_rps = max(0.2, full_bodies_rps)
        # Cap to keep an opt-in run from accidentally fetching ~5,000 bodies.
        self.full_bodies_max = full_bodies_max

    # ---- fetch -----------------------------------------------------------

    def fetch(self, work_dir: Path) -> None:
        username, token = _load_creds()
        auth_header = "Basic " + base64.b64encode(
            f"{username}:{token}".encode()
        ).decode()

        out_dir = work_dir / "pages"
        out_dir.mkdir(parents=True, exist_ok=True)

        page_num = 1
        total_collected = 0
        delay = 1.0 / self.rate_limit_rps

        while True:
            # Without queryString=disclosed:true, only ~2% of returned items
            # are disclosed (full title/body present). The filter makes the
            # endpoint return ONLY publicly-disclosed reports — what we want.
            qs = (
                f"?page%5Bnumber%5D={page_num}"
                f"&page%5Bsize%5D={self.page_size}"
            )
            if self.only_disclosed:
                qs += "&queryString=disclosed%3Atrue"
            url = HACKERONE_API_BASE + qs
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": auth_header,
                    "Accept": "application/json",
                    "User-Agent": "sentinel-sec/0.2 (+https://github.com/sentinel-sec)",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read()
            except urllib.error.HTTPError as e:
                # Stop on auth errors; transient server errors -> back off once and retry.
                if e.code in (401, 403):
                    raise HackerOneCredsError(
                        f"HackerOne API returned {e.code} — check your credentials"
                    )
                if e.code in (429, 502, 503, 504):
                    log.warning("hackerone HTTP %d on page %d, backing off 30s", e.code, page_num)
                    time.sleep(30)
                    continue
                log.error("hackerone HTTP %d on page %d, stopping", e.code, page_num)
                break
            except Exception as e:
                log.error("hackerone fetch failed on page %d: %s", page_num, e)
                break

            try:
                data = json.loads(raw)
            except json.JSONDecodeError as e:
                log.error("hackerone page %d: invalid JSON: %s", page_num, e)
                break

            items = data.get("data") or []
            if not items:
                log.info("hackerone: empty page %d, stopping", page_num)
                break

            (out_dir / f"page-{page_num:05d}.json").write_bytes(raw)
            total_collected += len(items)
            log.info(
                "hackerone: page %d -> %d items (running total: %d)",
                page_num, len(items), total_collected,
            )

            if self.max_reports is not None and total_collected >= self.max_reports:
                log.info("hackerone: reached max_reports=%d, stopping", self.max_reports)
                break

            # HackerOne caps hacktivity pagination at page 99 (HTTP 400 above
            # that), and `links.next` is empty so we just count up to the
            # known limit. ~4,950 most-recent disclosed reports is the cap.
            if page_num >= HACKERONE_MAX_PAGE:
                log.info("hackerone: hit max page %d (API limit), stopping", page_num)
                break

            page_num += 1
            time.sleep(delay)

        # Phase D second pass — pull full bodies for each disclosed report
        # if the operator opted in. Cached per-id under `full-bodies/<id>.json`
        # so re-runs incur zero re-fetches for already-cached reports.
        if self.full_bodies:
            self._fetch_full_bodies(work_dir)

    def _fetch_full_bodies(self, work_dir: Path) -> None:
        """Per-report body fetch pass. Idempotent + cached on disk."""
        username, token = _load_creds()
        auth_header = "Basic " + base64.b64encode(
            f"{username}:{token}".encode()
        ).decode()

        bodies_dir = work_dir / FULL_BODIES_DIR
        bodies_dir.mkdir(parents=True, exist_ok=True)

        ids = self._collect_disclosed_ids(work_dir)
        log.info(
            "hackerone full-body pass: %d disclosed report ids queued (cap=%s)",
            len(ids), self.full_bodies_max,
        )
        delay = 1.0 / self.full_bodies_rps
        fetched = 0
        skipped = 0
        for report_id in ids:
            if self.full_bodies_max is not None and fetched >= self.full_bodies_max:
                log.info("hackerone full-body: hit cap %d, stopping", self.full_bodies_max)
                break
            cache_path = bodies_dir / f"{report_id}.json"
            if cache_path.is_file() and cache_path.stat().st_size > 0:
                skipped += 1
                continue
            url = HACKERONE_REPORT_BASE + str(report_id)
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": auth_header,
                    "Accept": "application/json",
                    "User-Agent": "sentinel-sec/0.2 (+https://github.com/sentinel-sec)",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read()
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    log.debug("hackerone full-body: report %s 404 (no longer disclosed?)", report_id)
                    # Cache an empty stub so we don't retry on every run.
                    cache_path.write_bytes(b"{}")
                    fetched += 1
                    time.sleep(delay)
                    continue
                if e.code in (429, 502, 503, 504):
                    log.warning("hackerone full-body: report %s -> HTTP %d, backoff 30s",
                                report_id, e.code)
                    time.sleep(30)
                    continue
                log.warning("hackerone full-body: report %s -> HTTP %d, skipping",
                            report_id, e.code)
                time.sleep(delay)
                continue
            except Exception as e:  # noqa: BLE001
                log.warning("hackerone full-body: report %s -> %s", report_id, e)
                time.sleep(delay)
                continue
            cache_path.write_bytes(raw)
            fetched += 1
            if fetched % 50 == 0:
                log.info("hackerone full-body: %d fetched, %d cached-skip", fetched, skipped)
            time.sleep(delay)
        log.info(
            "hackerone full-body pass complete: %d newly fetched, %d cache-skipped",
            fetched, skipped,
        )

    def _collect_disclosed_ids(self, work_dir: Path) -> list[str]:
        """Walk the cached page-*.json files and return the disclosed report ids."""
        pages_dir = work_dir / "pages"
        out: list[str] = []
        if not pages_dir.is_dir():
            return out
        for page_path in sorted(pages_dir.glob("page-*.json")):
            try:
                data = json.loads(page_path.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            for item in data.get("data") or []:
                attrs = item.get("attributes") or {}
                if self.only_disclosed and not attrs.get("disclosed", False):
                    continue
                rid = item.get("id")
                if rid:
                    out.append(str(rid))
        return out

    # ---- parse -----------------------------------------------------------

    def parse(self, work_dir: Path) -> Iterable[Document]:
        pages_dir = work_dir / "pages"
        if not pages_dir.is_dir():
            return
        bodies_dir = work_dir / FULL_BODIES_DIR
        emitted = 0
        for page_path in sorted(pages_dir.glob("page-*.json")):
            try:
                data = json.loads(page_path.read_text())
            except json.JSONDecodeError:
                continue
            for item in data.get("data") or []:
                if self.max_reports is not None and emitted >= self.max_reports:
                    return
                doc = self._item_to_doc(item, bodies_dir=bodies_dir)
                if doc is None:
                    continue
                emitted += 1
                yield doc

    def _item_to_doc(
        self, item: dict, *, bodies_dir: Optional[Path] = None,
    ) -> Optional[Document]:
        attrs = item.get("attributes") or {}
        rels = item.get("relationships") or {}

        # Skip undisclosed reports — title/body are null and offer no signal.
        if self.only_disclosed and not attrs.get("disclosed", False):
            return None

        report_id = item.get("id")
        if not report_id:
            return None
        title = attrs.get("title")
        if not title:
            # Undisclosed/anonymous activities have no title — nothing to index.
            return None
        body = attrs.get("vulnerability_information") or ""
        # NOTE: HackerOne's hacktivity list endpoint does NOT include the full
        # `vulnerability_information` body (always empty in list responses).
        # Phase D (2026-XX-XX): if the operator opted in to `full_bodies`,
        # the per-report fetch pass cached the full body at
        # `<work_dir>/full-bodies/<id>.json` — load it here so the corpus
        # gets the actual narrative. Falls through to header-only when no
        # cache file exists.
        if bodies_dir is not None and not body:
            cache_path = bodies_dir / f"{report_id}.json"
            if cache_path.is_file():
                try:
                    cached = json.loads(cache_path.read_text())
                except (json.JSONDecodeError, OSError):
                    cached = {}
                cached_attrs = ((cached.get("data") or {}).get("attributes") or {}) \
                    if isinstance(cached, dict) else {}
                body = cached_attrs.get("vulnerability_information") or body

        program_attrs = ((rels.get("program") or {}).get("data") or {}).get("attributes") or {}
        reporter_attrs = ((rels.get("reporter") or {}).get("data") or {}).get("attributes") or {}
        program_handle = program_attrs.get("handle", "")
        program_name = program_attrs.get("name") or program_handle or "?"
        reporter = reporter_attrs.get("username", "")

        severity = (attrs.get("severity_rating") or "").lower() or "info"
        cwe_obj = attrs.get("cwe") or {}
        if isinstance(cwe_obj, dict):
            cwe_id = cwe_obj.get("id")
            cwe_name = cwe_obj.get("name", "")
        else:
            cwe_id = None
            cwe_name = ""
        cve_ids = attrs.get("cve_ids") or []
        bounty = attrs.get("total_awarded_amount")
        url = attrs.get("url") or f"https://hackerone.com/reports/{report_id}"
        disclosed_at = attrs.get("disclosed_at", "")

        # Compose a markdown body that's friendly for both human reading and embedding.
        header_lines = [
            f"# {title}",
            "",
            f"**Program:** {program_name}",
            f"**Reporter:** {reporter or '?'}",
            f"**Severity:** {severity}",
        ]
        if cwe_id:
            header_lines.append(f"**CWE-{cwe_id}:** {cwe_name}")
        if cve_ids:
            header_lines.append(f"**CVEs:** {', '.join(cve_ids)}")
        if bounty:
            header_lines.append(f"**Bounty:** ${bounty}")
        if disclosed_at:
            header_lines.append(f"**Disclosed:** {disclosed_at}")
        header_lines.append(f"**URL:** {url}")
        header_lines.append("")
        header_lines.append("---")
        header_lines.append("")

        text = "\n".join(header_lines) + body

        tags = ["hackerone", "writeup", severity]
        if program_handle:
            tags.append(program_handle)
        if cwe_id:
            tags.append(f"cwe-{cwe_id}")

        metadata = {
            "hackerone_id": report_id,
            "program_handle": program_handle,
            "program_name": program_name,
            "reporter": reporter,
            "severity": severity,
            "bounty": bounty,
            "cwe_id": cwe_id,
            "cve_id": cve_ids[0] if cve_ids else None,
            "disclosed_at": disclosed_at,
        }

        return Document(
            id=Document.make_id(self.name, str(report_id)),
            text=text,
            title=title,
            source=self.name,
            url=url,
            tags=tags,
            metadata=metadata,
        )
