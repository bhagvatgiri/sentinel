"""Brain-Growth Agent tools.

Each tool is exposed via the @claude_agent_sdk.tool decorator and bundled
into an SDK MCP server. The Claude Agent SDK then makes them callable from
the agent loop just like any built-in tool.

Tools provided:
    web_search(query, max_results)
        DuckDuckGo HTML search — no API key required.
    fetch_url(url)
        httpx GET with sane timeouts and a Sentinel UA. Returns raw HTML.
    extract_text(url, html)
        trafilatura content extraction — strips boilerplate, returns
        readable plaintext suitable for chunking.
    check_corpus(query, top_k)
        Embed the query, search the existing corpus. Used by the agent
        to decide whether a candidate page is already covered before
        spending an embedding+upsert cycle on it.
    ingest_text(url, title, text, tags)
        Wraps the text as a Document, chunks it, embeds each chunk via
        Ollama (nomic-embed-text), upserts into Chroma. Returns a
        per-doc summary the agent can read.
    corpus_stats()
        Total chunks + per-source counts. Cheap status check.

The tools mutate one process-global `_BrainContext` (set by `loop.py`
before `query()` runs). That context owns the CorpusStore + httpx client
+ rate limits + ingestion log file handle.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, urlparse

import httpx
import trafilatura

from claude_agent_sdk import tool

from sentinel.corpus.chunker import chunk_document
from sentinel.corpus.document import Document
from sentinel.corpus.store import CorpusStore


log = logging.getLogger(__name__)


# ---- shared context -------------------------------------------------------

@dataclass
class BrainContext:
    """Process-global state the tools consume.

    Set once by `BrainAgent.run()` before invoking the SDK; the tool
    functions read from this rather than receiving it through args
    (the SDK's tool decorator only sees the LLM-supplied args dict).
    """
    store: CorpusStore
    http: httpx.AsyncClient
    chunk_size: int = 1500
    chunk_overlap: int = 200
    dedup_distance_threshold: float = 0.20  # Chroma cosine distance; lower = more similar
    # The books library has near-comprehensive coverage of every common web
    # vuln class, so a 0.20 gate against a book chunk blocks almost any new
    # web research page. Treat books as a duplicate only if the new text is
    # near-identical (< 0.10), letting alternative framings of the same topic
    # in for retrieval diversity.
    book_dedup_threshold: float = 0.10
    rate_limit_per_host_sec: float = 1.0
    fetch_timeout_sec: float = 30.0
    log_path: Optional[Path] = None
    pages_fetched: int = 0
    chunks_added: int = 0
    docs_added: int = 0
    docs_skipped_dedup: int = 0
    # Saturation detection (task #73, 2026-XX-XX). After N consecutive
    # ingest_skip_dedup events with no successful ingest in between, the
    # topic is saturated — every page the agent finds is already in the
    # corpus. Continuing burns budget for zero gain. Counter resets on
    # any successful ingest. Threshold env-overridable via
    # SENTINEL_BRAIN_SATURATION_THRESHOLD (default 5). When tripped,
    # ingest_text returns a "saturated — stop searching this topic"
    # response that the brain agent recognizes as a stop signal.
    consecutive_dedup_skips: int = 0
    saturation_threshold: int = 5
    saturation_signaled: bool = False  # latch — only emit the saturation event once
    last_fetch_at: dict = field(default_factory=dict)  # host -> timestamp
    # url -> last extract_text result. Local models truncate big text args
    # when copying between tool calls; ingest_text falls back to this when
    # the model passes a too-short text arg with a URL we have cached.
    extracted_cache: dict = field(default_factory=dict)
    fetched_html_cache: dict = field(default_factory=dict)  # url -> raw html


_ctx: Optional[BrainContext] = None


def set_context(ctx: BrainContext) -> None:
    """Called by the loop before query() runs."""
    global _ctx
    _ctx = ctx


def _require_ctx() -> BrainContext:
    if _ctx is None:
        raise RuntimeError("BrainContext not initialized — call set_context() first")
    return _ctx


def _log_event(kind: str, **fields) -> None:
    """Append a JSONL event to the ingestion log (if configured)."""
    ctx = _require_ctx()
    if ctx.log_path is None:
        return
    fields["t"] = time.time()
    fields["kind"] = kind
    try:
        with ctx.log_path.open("a") as fh:
            fh.write(json.dumps(fields, default=str) + "\n")
    except OSError:
        pass


def _ok(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


def _err(text: str) -> dict:
    return {"content": [{"type": "text", "text": f"ERROR: {text}"}], "is_error": True}


# Domains where DDG indexes content but the actual page is gated by a
# login wall, paywall, or "member-only story" prompt — fetch_url returns
# the auth page, not the article. brain-grow burns budget on these.
# Filter at the search-result layer so the model never sees them.
# (See task #17 / runs/brain-cmp-qwen-postfix2.log for the failure trace.)
_DOWNRANK_HOSTS: set[str] = {
    "medium.com",
    "infosecwriteups.com",
    "betterprogramming.pub",
    "javascript.plainenglish.io",
    "levelup.gitconnected.com",
    # dev.to lets some content through but the bulk is member-only
    "dev.to",
    # Most security-related substacks gate after intro paragraph
    "substack.com",
    # AI-generated content farms / pages that frequently 404 or paywall
    "qiita.com",
    "zenn.dev",
}


def _host_is_paywalled(url: str) -> bool:
    """True if this URL's host (or its parent domain) is in the
    paywall/login-wall list. Used by web_search to drop these entries
    before they reach the model."""
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    if host in _DOWNRANK_HOSTS:
        return True
    for bad in _DOWNRANK_HOSTS:
        if host.endswith("." + bad):
            return True
    return False


async def _per_host_rate_limit(host: str) -> None:
    """Block until enough time has passed since the last fetch to this host."""
    ctx = _require_ctx()
    now = time.monotonic()
    last = ctx.last_fetch_at.get(host, 0.0)
    delta = now - last
    if delta < ctx.rate_limit_per_host_sec:
        await asyncio.sleep(ctx.rate_limit_per_host_sec - delta)
    ctx.last_fetch_at[host] = time.monotonic()


# ---- tools ----------------------------------------------------------------

@tool(
    "web_search",
    "Search the web for security writeups, vulnerability research, and ethical-hacking knowledge. "
    "Returns a list of result URLs and titles. Uses DuckDuckGo HTML search; no API key required. "
    "Use specific queries (e.g., 'SSRF bypass Next.js image optimizer 2024') rather than broad ones.",
    {"query": str, "max_results": int},
)
async def web_search(args: dict) -> dict:
    query = (args.get("query") or "").strip()
    max_results = int(args.get("max_results") or 10)
    max_results = max(1, min(max_results, 20))
    if not query:
        return _err("query is required")

    ctx = _require_ctx()
    await _per_host_rate_limit("html.duckduckgo.com")
    url = "https://html.duckduckgo.com/html/?" + urlencode({"q": query})
    try:
        resp = await ctx.http.get(url, timeout=ctx.fetch_timeout_sec)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        _log_event("web_search_error", query=query, err=str(e))
        return _err(f"DuckDuckGo request failed: {e}")

    # DDG HTML results: anchor tag with class "result__a" inside "result" div.
    # Be lenient on whitespace/attribute order.
    pattern = re.compile(
        r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
        re.DOTALL | re.IGNORECASE,
    )
    snippet_pat = re.compile(
        r'<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>',
        re.DOTALL | re.IGNORECASE,
    )
    snippets = [_strip_tags(s) for s in snippet_pat.findall(resp.text)]
    results = []
    filtered_paywall = 0
    for i, m in enumerate(pattern.findall(resp.text)):
        if len(results) >= max_results:
            break
        href, title_html = m
        # DDG wraps URLs in /l/?uddg=<encoded>
        actual = _ddg_unwrap(href)
        # Skip known paywall/login-wall hosts — fetch_url would just get
        # the auth page back, wasting a turn + a fetch budget unit. The
        # model never sees these entries.
        if _host_is_paywalled(actual):
            filtered_paywall += 1
            continue
        title = _strip_tags(title_html).strip()
        snippet = snippets[i] if i < len(snippets) else ""
        results.append({"url": actual, "title": title, "snippet": snippet[:300]})

    _log_event("web_search", query=query, n=len(results),
               filtered_paywall=filtered_paywall)
    if not results:
        return _ok(f"No results for: {query}")
    lines = [f"Search results for: {query}"]
    for i, r in enumerate(results, 1):
        lines.append(f"\n[{i}] {r['title']}\n  URL: {r['url']}\n  {r['snippet']}")
    return _ok("\n".join(lines))


@tool(
    "fetch_url",
    "Fetch a URL and return its main content as clean readable text (HTML "
    "boilerplate stripped via trafilatura). Use after web_search to read a "
    "specific result. Honors per-host rate limiting (1 req/sec). Returns up to "
    "60KB of clean text — well under any tool-result token cap. If you genuinely "
    "need the raw HTML (rare), pass `raw=true` and the agent will return the raw "
    "body capped at 50KB.",
    {"url": str, "raw": bool},
)
async def fetch_url(args: dict) -> dict:
    url = (args.get("url") or "").strip()
    raw = bool(args.get("raw") or False)
    if not url:
        return _err("url is required")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return _err(f"only http/https URLs are allowed (got {parsed.scheme!r})")
    if not parsed.hostname:
        return _err("URL has no hostname")

    ctx = _require_ctx()
    await _per_host_rate_limit(parsed.hostname)
    try:
        resp = await ctx.http.get(url, timeout=ctx.fetch_timeout_sec, follow_redirects=True)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        _log_event("fetch_error", url=url, err=str(e))
        return _err(f"fetch failed: {e}")

    raw_body = resp.text
    ctx.pages_fetched += 1

    if raw:
        body = raw_body[:50_000]
        _log_event("fetch_ok_raw", url=url, raw_size=len(raw_body), final_url=str(resp.url))
        return _ok(
            f"Fetched {url} ({len(raw_body)} chars raw, returning first {len(body)}).\n"
            f"Final URL: {resp.url}\n"
            f"Content-Type: {resp.headers.get('content-type', '?')}\n\n"
            f"--- RAW BODY ---\n{body}"
        )

    # Default: pipe through trafilatura inline. Avoids the agent ever seeing
    # the 200KB+ HTML wrappers that hit Claude Code's tool-result token cap.
    extracted = trafilatura.extract(
        raw_body, url=url, include_links=True, include_tables=True, favor_recall=True,
    ) or ""
    extracted = extracted.strip()
    if len(extracted) < 100:
        # Trafilatura found nothing — fall back to a small slice of raw HTML
        # so the agent can at least see SOMETHING (status pages, plain text
        # responses, etc.) without hitting the token cap.
        fallback = raw_body[:8000]
        _log_event("fetch_ok_fallback", url=url, raw_size=len(raw_body),
                   final_url=str(resp.url))
        return _ok(
            f"Fetched {url} ({len(raw_body)} chars raw). trafilatura extracted "
            f"<100 chars — returning the first 8KB of raw HTML as fallback.\n"
            f"Final URL: {resp.url}\n"
            f"Content-Type: {resp.headers.get('content-type', '?')}\n\n"
            f"--- RAW (fallback) ---\n{fallback}"
        )

    text = extracted[:60_000]
    # Cache the FULL extracted text so ingest_text can fall back to it when
    # the model truncates the text it tries to copy between tool calls.
    ctx.extracted_cache[url] = extracted
    ctx.extracted_cache[str(resp.url)] = extracted
    ctx.fetched_html_cache[url] = raw_body
    ctx.fetched_html_cache[str(resp.url)] = raw_body
    _log_event("fetch_ok", url=url, raw_size=len(raw_body),
               extracted_size=len(extracted), final_url=str(resp.url))
    return _ok(
        f"Fetched {url} (raw HTML: {len(raw_body)} chars, extracted text: "
        f"{len(extracted)} chars). Returning first {len(text)} chars of clean text. "
        f"You can pass this URL directly to ingest_text without re-copying the "
        f"text — the brain caches it server-side.\n"
        f"Final URL: {resp.url}\n"
        f"Content-Type: {resp.headers.get('content-type', '?')}\n\n"
        f"--- TEXT ---\n{text}"
    )


@tool(
    "extract_text",
    "Extract the main readable text from raw HTML, stripping boilerplate (nav, ads, comments). "
    "Use this on fetch_url output before deciding whether to ingest. Returns clean plaintext.",
    {"url": str, "html": str},
)
async def extract_text(args: dict) -> dict:
    url = (args.get("url") or "").strip()
    html = args.get("html") or ""
    if not html:
        return _err("html is required")
    extracted = trafilatura.extract(
        html,
        url=url or None,
        include_links=True,
        include_tables=True,
        favor_recall=True,
    )
    if not extracted or len(extracted.strip()) < 100:
        return _err(f"trafilatura extracted <100 chars (page likely had no main content)")
    text = extracted.strip()
    # Cache so ingest_text can recover the full text if the model truncates it.
    ctx = _require_ctx()
    if url:
        ctx.extracted_cache[url] = text
    return _ok(
        f"Extracted {len(text)} chars of clean text from {url}. You can pass "
        f"this URL directly to ingest_text without re-copying the text — the "
        f"brain caches it server-side.\n\n{text[:60_000]}"
    )


@tool(
    "check_corpus",
    "Search the existing corpus for content similar to a given query or text. "
    "Use BEFORE ingesting a new page to see if it's already covered "
    "(distance < 0.20 means very similar — skip ingestion). "
    "Returns top matches with their cosine distance and source.",
    {"query": str, "top_k": int},
)
async def check_corpus(args: dict) -> dict:
    query = (args.get("query") or "").strip()
    top_k = int(args.get("top_k") or 5)
    top_k = max(1, min(top_k, 20))
    if not query:
        return _err("query is required")
    ctx = _require_ctx()
    # CorpusStore.query is sync; run in thread to avoid blocking the loop.
    results = await asyncio.to_thread(ctx.store.query, query, top_k)
    if not results:
        return _ok(f"No matches in corpus for: {query!r}")
    lines = [f"Top {len(results)} corpus matches for: {query!r}"]
    for r in results:
        lines.append(
            f"  [dist={r['distance']:.3f}] [{r['source']}] {r['title'][:80]} "
            f"({(r.get('url') or '-')[:80]})"
        )
    closest = results[0]["distance"]
    advice = (
        "ALREADY COVERED (very similar content exists)" if closest < 0.20
        else "PARTIALLY COVERED (related but distinct)" if closest < 0.40
        else "NEW TERRITORY (worth ingesting)"
    )
    lines.append(f"\nClosest match distance: {closest:.3f} — {advice}")
    return _ok("\n".join(lines))


@tool(
    "ingest_text",
    "Add a piece of clean text (from extract_text) into the corpus. "
    "Wraps it as a Document with source='brain-grow', chunks it, embeds each chunk, "
    "stores in Chroma. ALWAYS check_corpus FIRST to avoid re-ingesting known content. "
    "Returns the chunk count added.",
    {"url": str, "title": str, "text": str, "tags": str},
)
async def ingest_text(args: dict) -> dict:
    # Local Ollama models occasionally pass these as lists or non-string
    # types despite the JSON-Schema declaration. Coerce defensively.
    def _as_str(v) -> str:
        if v is None:
            return ""
        if isinstance(v, list):
            return ", ".join(str(x) for x in v)
        return str(v)

    url = _as_str(args.get("url")).strip()
    title = (_as_str(args.get("title")) or "Untitled").strip()[:200]
    text = _as_str(args.get("text")).strip()
    raw_tags = args.get("tags")

    # Local-model recovery: when the model passes a too-short `text` (it
    # truncates large strings between tool calls), fall back to the
    # extracted-text cache populated by fetch_url / extract_text. This is
    # the architectural fix for the llama3.1:8b "passes first 60 chars"
    # behavior.
    ctx_for_cache = _ctx
    if (len(text) < 1000 and url and ctx_for_cache is not None
            and url in ctx_for_cache.extracted_cache):
        cached = ctx_for_cache.extracted_cache.get(url) or ""
        if len(cached) > len(text):
            _log_event("ingest_text_cache_recovery", url=url,
                       model_text_len=len(text), cached_len=len(cached))
            text = cached

    if len(text) < 200:
        return _err(f"text too short ({len(text)} chars) — extract_text first")

    # Tags can arrive as: a real list ["a","b"], a stringified list "['a','b']",
    # or a comma-separated string "a, b".
    if isinstance(raw_tags, list):
        tags = [str(t).strip() for t in raw_tags if str(t).strip()]
    else:
        tags_str = _as_str(raw_tags).strip()
        # Try to parse a Python repr / JSON list first.
        if tags_str.startswith("[") and tags_str.endswith("]"):
            try:
                import json as _json
                parsed = _json.loads(tags_str.replace("'", '"'))
                if isinstance(parsed, list):
                    tags = [str(t).strip() for t in parsed if str(t).strip()]
                else:
                    tags = [tags_str]
            except (ValueError, TypeError):
                tags = [t.strip() for t in tags_str.strip("[]").split(",") if t.strip()]
        else:
            tags = [t.strip() for t in tags_str.split(",") if t.strip()]

    ctx = _require_ctx()

    # Dedup safety net — even if the LLM forgot to call check_corpus.
    matches = await asyncio.to_thread(ctx.store.query, text[:2000], 1)
    if matches:
        m = matches[0]
        matched_source = (m.get("source") or "").lower()
        threshold = (
            ctx.book_dedup_threshold if matched_source == "books"
            else ctx.dedup_distance_threshold
        )
        if m["distance"] < threshold:
            # URL-novelty override: if this exact URL has never been
            # ingested AND the match is from a different source (not
            # brain-grow itself), allow ingest as complementary framing.
            # This builds retrieval diversity instead of fighting the
            # seed corpus's density.
            url_is_novel = bool(url) and not await asyncio.to_thread(
                ctx.store.has_url, url
            )
            if url_is_novel and matched_source != "brain-grow":
                tags = list(tags) + ["complementary-framing"]
                _log_event("ingest_url_novelty_override", url=url,
                           distance=m["distance"], matched_source=matched_source,
                           threshold=threshold)
                # fall through to normal ingest path below
            else:
                ctx.docs_skipped_dedup += 1
                ctx.consecutive_dedup_skips += 1
                _log_event("ingest_skip_dedup", url=url, distance=m["distance"],
                           matched=m.get("url"), matched_source=matched_source,
                           threshold=threshold,
                           consecutive_skips=ctx.consecutive_dedup_skips)
                # Saturation signal — task #73. When N consecutive
                # dedup-skips fire with no successful ingest in between,
                # the topic is exhausted; every relevant page is already
                # in the corpus. Tell the agent to stop searching.
                if (ctx.consecutive_dedup_skips >= ctx.saturation_threshold
                        and not ctx.saturation_signaled):
                    ctx.saturation_signaled = True
                    _log_event("brain_topic_saturated",
                               consecutive_skips=ctx.consecutive_dedup_skips,
                               threshold=ctx.saturation_threshold,
                               docs_added_so_far=ctx.docs_added,
                               docs_skipped_so_far=ctx.docs_skipped_dedup)
                    return _ok(
                        f"TOPIC SATURATED — {ctx.consecutive_dedup_skips} consecutive "
                        f"pages all matched existing corpus content (threshold "
                        f"{ctx.saturation_threshold}). The corpus already has "
                        f"strong coverage of this topic; further searches are "
                        f"unlikely to find new material. STOP searching for this "
                        f"topic — call your final summary or move on. Stats so far: "
                        f"docs_added={ctx.docs_added}, "
                        f"docs_skipped_dedup={ctx.docs_skipped_dedup}."
                    )
                return _ok(
                    f"Skipped: very similar content already in corpus "
                    f"(distance={m['distance']:.3f}, threshold={threshold:.2f}, "
                    f"matched: {m['title'][:80]} [{matched_source}]). "
                    f"Consecutive dedup-skips: {ctx.consecutive_dedup_skips}/"
                    f"{ctx.saturation_threshold}."
                )

    doc = Document(
        id=Document.make_id("brain-grow", url or title),
        text=text,
        title=title,
        source="brain-grow",
        url=url or None,
        tags=tags,
        metadata={"ingested_by": "brain-agent"},
    )
    chunks = chunk_document(doc, ctx.chunk_size, ctx.chunk_overlap)
    if not chunks:
        return _err("chunker produced 0 chunks (text may be malformed)")
    stored = await asyncio.to_thread(ctx.store.upsert_chunks, chunks)
    ctx.docs_added += 1
    ctx.chunks_added += stored
    # Saturation reset (task #73): a successful ingest means the topic is
    # NOT saturated yet — there's still novel content. Reset the counter
    # + lift the saturation signal so the loop can continue exploring.
    ctx.consecutive_dedup_skips = 0
    ctx.saturation_signaled = False
    _log_event("ingest_ok", url=url, title=title, chunks=stored, tags=tags)
    return _ok(
        f"Ingested: {title!r}\n"
        f"  url: {url}\n"
        f"  chunks stored: {stored}\n"
        f"  tags: {tags}\n"
        f"  doc id: {doc.id}\n"
        f"Running totals: {ctx.docs_added} docs, {ctx.chunks_added} chunks added; "
        f"{ctx.docs_skipped_dedup} skipped as duplicates."
    )


@tool(
    "corpus_stats",
    "Show current corpus stats — total chunk count, breakdown by source. "
    "Useful for status checks during a long research session.",
    {},
)
async def corpus_stats(args: dict) -> dict:
    ctx = _require_ctx()
    s = await asyncio.to_thread(ctx.store.stats)
    return _ok(
        f"Corpus stats:\n"
        f"  collection: {s.get('collection')}\n"
        f"  total chunks: {s.get('chunks')}\n"
        f"  persist_dir: {s.get('persist_dir')}\n"
        f"\nThis session so far:\n"
        f"  pages fetched:    {ctx.pages_fetched}\n"
        f"  docs ingested:    {ctx.docs_added}\n"
        f"  docs deduplicated: {ctx.docs_skipped_dedup}\n"
        f"  chunks added:     {ctx.chunks_added}\n"
    )


# ---- HTML helpers ---------------------------------------------------------

_TAG_RE = re.compile(r"<[^>]+>")


def _strip_tags(html: str) -> str:
    return _TAG_RE.sub("", html or "").replace("&amp;", "&").replace(
        "&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'")


def _ddg_unwrap(href: str) -> str:
    """DDG HTML wraps real URLs as `/l/?uddg=<urlencoded>&...`. Unwrap."""
    if not href.startswith("/l/?") and not href.startswith("//duckduckgo.com/l/?"):
        return href
    from urllib.parse import parse_qs
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlparse(href)
    qs = parse_qs(parsed.query)
    return qs.get("uddg", [href])[0]


# Public list of tools for the SDK MCP server.
ALL_TOOLS = [web_search, fetch_url, extract_text, check_corpus, ingest_text, corpus_stats]
