"""Tests for the Phase-D HackerOne full-body fetch + cache integration.

Network is mocked. We exercise:

- Per-report body fetch pass writes one cache file per disclosed id
- Cached-body pass is idempotent (re-running skips already-cached files)
- `_item_to_doc` reads from the cache when the operator opts in to full
  bodies, picking up the `vulnerability_information` field that the
  hacktivity-list endpoint omits
- `_collect_disclosed_ids` walks `pages/page-*.json` correctly
- Stub cache (404 reports) is honored — never re-fetched
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from sentinel.corpus.sources import hackerone as h1


def _write_pages(work: Path, ids: list[str], disclosed: list[bool]) -> None:
    pages = work / "pages"
    pages.mkdir(parents=True, exist_ok=True)
    items = [
        {
            "id": rid,
            "attributes": {
                "title": f"Report {rid}",
                "disclosed": disc,
                "vulnerability_information": "",
                "severity_rating": "high",
            },
            "relationships": {},
        }
        for rid, disc in zip(ids, disclosed)
    ]
    (pages / "page-00001.json").write_text(json.dumps({"data": items}))


def _stub_creds(monkeypatch):
    monkeypatch.setenv("HACKERONE_API_USERNAME", "user")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "tok")


def test_collect_disclosed_ids_filters_undisclosed(tmp_path: Path):
    _write_pages(tmp_path, ["111", "222", "333"], [True, False, True])
    src = h1.HackerOneSource(only_disclosed=True)
    ids = src._collect_disclosed_ids(tmp_path)
    assert ids == ["111", "333"]


def test_collect_disclosed_ids_includes_undisclosed_when_off(tmp_path: Path):
    _write_pages(tmp_path, ["111", "222"], [True, False])
    src = h1.HackerOneSource(only_disclosed=False)
    ids = src._collect_disclosed_ids(tmp_path)
    assert ids == ["111", "222"]


def test_full_body_fetch_caches_each_report(tmp_path: Path, monkeypatch):
    _stub_creds(monkeypatch)
    _write_pages(tmp_path, ["1001", "1002"], [True, True])

    captured_urls: list[str] = []

    class FakeResp:
        def __init__(self, payload: dict):
            self._payload = json.dumps(payload).encode()
            self._consumed = False

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return self._payload

    def fake_urlopen(req, timeout=30):
        captured_urls.append(req.full_url)
        rid = req.full_url.rsplit("/", 1)[-1]
        return FakeResp({"data": {"id": rid, "attributes": {
            "vulnerability_information": f"## Body for {rid}\nDetails…",
        }}})

    monkeypatch.setattr(h1.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(h1.time, "sleep", lambda *_a, **_k: None)

    src = h1.HackerOneSource(full_bodies=True, full_bodies_rps=10.0)
    src._fetch_full_bodies(tmp_path)

    bodies_dir = tmp_path / h1.FULL_BODIES_DIR
    assert (bodies_dir / "1001.json").is_file()
    assert (bodies_dir / "1002.json").is_file()
    assert len(captured_urls) == 2

    # Re-run — already cached, no new fetches.
    captured_urls.clear()
    src._fetch_full_bodies(tmp_path)
    assert captured_urls == []


def test_full_body_404_writes_stub_and_does_not_retry(tmp_path: Path, monkeypatch):
    _stub_creds(monkeypatch)
    _write_pages(tmp_path, ["77"], [True])

    calls: list[str] = []

    def fake_urlopen(req, timeout=30):
        calls.append(req.full_url)
        raise h1.urllib.error.HTTPError(req.full_url, 404, "not found", None, None)

    monkeypatch.setattr(h1.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(h1.time, "sleep", lambda *_a, **_k: None)

    src = h1.HackerOneSource(full_bodies=True, full_bodies_rps=10.0)
    src._fetch_full_bodies(tmp_path)

    stub = tmp_path / h1.FULL_BODIES_DIR / "77.json"
    assert stub.is_file()
    assert stub.read_bytes() == b"{}"
    assert len(calls) == 1

    src._fetch_full_bodies(tmp_path)
    # Cached stub means no re-fetch even though the body is empty.
    assert len(calls) == 1


def test_item_to_doc_reads_cached_body(tmp_path: Path):
    bodies_dir = tmp_path / h1.FULL_BODIES_DIR
    bodies_dir.mkdir()
    (bodies_dir / "555.json").write_text(json.dumps({
        "data": {"id": "555", "attributes": {
            "vulnerability_information": "## Full body markdown here\nWith details…",
        }},
    }))

    src = h1.HackerOneSource()
    item = {
        "id": "555",
        "attributes": {
            "title": "Cached body smoke",
            "disclosed": True,
            "vulnerability_information": "",
            "severity_rating": "high",
        },
        "relationships": {},
    }
    doc = src._item_to_doc(item, bodies_dir=bodies_dir)
    assert doc is not None
    assert "Full body markdown here" in doc.text


def test_item_to_doc_no_cache_dir_falls_back_to_header_only(tmp_path: Path):
    src = h1.HackerOneSource()
    item = {
        "id": "999",
        "attributes": {
            "title": "Header-only smoke",
            "disclosed": True,
            "vulnerability_information": "",
            "severity_rating": "high",
        },
        "relationships": {},
    }
    doc = src._item_to_doc(item, bodies_dir=None)
    assert doc is not None
    # Header-only — no full-body markdown should appear.
    assert "## Full body" not in doc.text


def test_full_bodies_max_caps_fetch_count(tmp_path: Path, monkeypatch):
    _stub_creds(monkeypatch)
    _write_pages(tmp_path, [str(i) for i in range(5)], [True] * 5)

    calls: list[str] = []

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'{"data": {"attributes": {"vulnerability_information": "x"}}}'

    def fake_urlopen(req, timeout=30):
        calls.append(req.full_url)
        return FakeResp()

    monkeypatch.setattr(h1.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(h1.time, "sleep", lambda *_a, **_k: None)

    src = h1.HackerOneSource(full_bodies=True, full_bodies_rps=10.0, full_bodies_max=2)
    src._fetch_full_bodies(tmp_path)

    assert len(calls) == 2
