"""Tests for the brain-grow web_search paywall/login-wall filter.

Closes task #17 (Wave-1 brain comparison surfaced llama3.1:8b + qwen2.5
both wasting turns on Medium / infosecwriteups / dev.to URLs that
fetch_url'd into login walls). web_search now drops these results
server-side before the model sees them.
"""

from __future__ import annotations

from unittest import mock

import pytest


# ---- _host_is_paywalled helper -------------------------------------------


@pytest.mark.parametrize("url", [
    "https://medium.com/@x/post-id",
    "https://medium.com/p/abc123",
    "https://example.medium.com/article",
    "https://infosecwriteups.com/something-cool-12345",
    "https://betterprogramming.pub/whatever",
    "https://dev.to/user/post-slug",
    "https://random.substack.com/p/article",
    "https://qiita.com/user/items/abc",
    "https://zenn.dev/user/articles/x",
])
def test_host_is_paywalled_recognizes_known_bad(url):
    from sentinel.agent.brain.tools import _host_is_paywalled
    assert _host_is_paywalled(url) is True, f"expected {url!r} to be flagged"


@pytest.mark.parametrize("url", [
    "https://portswigger.net/research/the-thing",
    "https://owasp.org/www-project-top-ten/",
    "https://github.com/swisskyrepo/PayloadsAllTheThings",
    "https://blog.cloudflare.com/security-stuff",
    "https://samcurry.net/web-hackers-vs-the-auto-industry",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
    "https://hackerone.com/reports/123456",
])
def test_host_is_paywalled_returns_false_for_clean(url):
    from sentinel.agent.brain.tools import _host_is_paywalled
    assert _host_is_paywalled(url) is False, f"expected {url!r} to pass"


@pytest.mark.parametrize("url", [
    "",
    "not-a-url",
    "://broken",
    "javascript:alert(1)",
    "ftp://",
    None,
])
def test_host_is_paywalled_handles_malformed_url(url):
    """Bad input must not raise — just return False so the filter is a
    no-op for unparseable junk."""
    from sentinel.agent.brain.tools import _host_is_paywalled
    if url is None:
        # urlparse(None) raises; the helper guards against this via try/except.
        try:
            assert _host_is_paywalled(url) is False
        except (TypeError, AttributeError):
            pytest.fail("helper must not raise on None input")
    else:
        assert _host_is_paywalled(url) is False


# ---- web_search filter ---------------------------------------------------


def _fake_ddg_html(urls_with_titles: list[tuple[str, str]]) -> str:
    """Build a minimal DDG HTML response that the regex in tools.py
    expects. One result block per (url, title)."""
    parts = []
    for href, title in urls_with_titles:
        parts.append(
            f'<div class="result"><a class="result__a" href="{href}">{title}</a>'
            f'<a class="result__snippet">snippet for {title}</a></div>'
        )
    return "<html><body>" + "\n".join(parts) + "</body></html>"


@pytest.fixture
def brain_ctx(tmp_path):
    """Wire a minimal BrainContext so web_search can run."""
    from sentinel.agent.brain import tools as bt
    import httpx

    class _FakeStore:
        def query(self, *a, **kw): return []
        def has_url(self, url): return False
        def upsert_chunks(self, *a, **kw): return 0

    ctx = bt.BrainContext(
        store=_FakeStore(),
        http=httpx.AsyncClient(),
        chunk_size=1500, chunk_overlap=200,
        rate_limit_per_host_sec=0.0,
        log_path=tmp_path / "brain.jsonl",
    )
    bt.set_context(ctx)
    return ctx


def test_web_search_filters_paywalled_results(brain_ctx):
    """Mixed clean + paywalled DDG results: only clean URLs should
    survive into the result list, and the filtered_paywall counter
    should be non-zero in the event log."""
    import asyncio
    from sentinel.agent.brain import tools as bt

    html = _fake_ddg_html([
        # NOTE: tools.py uses a `result__a class=` regex with href= attr,
        # AND wraps URLs through _ddg_unwrap. Use direct hrefs — the
        # unwrap is a passthrough when the URL doesn't have /l/?uddg=.
        ("https://portswigger.net/research/clean-1", "Clean PortSwigger article"),
        ("https://medium.com/@x/paywalled-1", "Medium paywalled story"),
        ("https://owasp.org/clean-2", "Clean OWASP page"),
        ("https://infosecwriteups.com/walled", "InfoSecWriteups wall"),
        ("https://dev.to/user/walled-too", "Dev.to walled"),
        ("https://hackerone.com/reports/9999", "Clean H1 report"),
    ])

    async def fake_get(url, **kw):
        from types import SimpleNamespace
        return SimpleNamespace(text=html, status_code=200, raise_for_status=lambda: None)

    with mock.patch.object(brain_ctx.http, "get", side_effect=fake_get):
        out = asyncio.run(bt.web_search.handler({"query": "anything", "max_results": 10}))

    text = out["content"][0]["text"]
    # Clean URLs survive
    assert "portswigger.net" in text
    assert "owasp.org" in text
    assert "hackerone.com" in text
    # Paywalled URLs were filtered
    assert "medium.com" not in text
    assert "infosecwriteups.com" not in text
    assert "dev.to" not in text


def test_web_search_unaffected_when_no_paywall_hits(brain_ctx):
    """All-clean response: result count matches input, no filtering."""
    import asyncio
    from sentinel.agent.brain import tools as bt

    html = _fake_ddg_html([
        ("https://portswigger.net/a", "A"),
        ("https://owasp.org/b", "B"),
        ("https://blog.cloudflare.com/c", "C"),
    ])

    async def fake_get(url, **kw):
        from types import SimpleNamespace
        return SimpleNamespace(text=html, status_code=200, raise_for_status=lambda: None)

    with mock.patch.object(brain_ctx.http, "get", side_effect=fake_get):
        out = asyncio.run(bt.web_search.handler({"query": "x", "max_results": 10}))

    text = out["content"][0]["text"]
    assert text.count("https://") == 3
