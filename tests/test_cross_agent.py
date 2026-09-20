"""Tests for cross-agent collaboration: BrainQueue + request_brain_research +
auto-brain keyword extraction.

Mocks the BrainAgent so we don't fire real LLM/network during tests.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.agent.brain_queue import BrainQueue
from sentinel.agent.pentest import auto_brain, tools as p_tools
from sentinel.core.scope import AuditLog, Scope


def _make_scope_yaml(tmp: Path) -> Path:
    p = tmp / "scope.yaml"
    p.write_text(
        "client: testco\nengagement_id: 2026-test\n"
        "authorized_by: t@example.com\n"
        "valid_from: 2026-01-01\nvalid_until: 2099-12-31\n"
        "targets:\n  domains: ['example.com']\n"
        "rate_limits:\n  requests_per_second: 30\n"
    )
    return p


# ---- BrainQueue ----------------------------------------------------------

def test_brain_queue_dedup_within_session():
    """Re-enqueueing the same topic in one session is a no-op."""
    q = BrainQueue(corpus_dir="/tmp/fake-corpus", max_topics=10)
    s1 = q.enqueue("SSRF Next.js", requested_by="auth-vuln")
    s2 = q.enqueue("ssrf next.js", requested_by="ssrf-vuln")  # different case → same topic
    assert "enqueued" in s1
    assert "skipped" in s2 and "already" in s2
    assert q.stats.enqueued == 1
    assert q.stats.skipped_dup == 1


def test_brain_queue_max_topics_cap():
    q = BrainQueue(corpus_dir="/tmp/fake", max_topics=2)
    # Use realistic topic strings that pass the low-signal filter (Phase
    # 96 added the filter to reject vague pre-warm sniffs).
    realistic_topics = [
        f"OAuth2 redirect_uri bypass technique number {i}"
        for i in range(5)
    ]
    for t in realistic_topics:
        q.enqueue(t, requested_by="test")
    assert q.stats.enqueued == 2


def test_brain_queue_normalize():
    assert BrainQueue._normalize("  SSRF  Next.js   ") == "ssrf next.js"
    assert BrainQueue._normalize("") == ""


def test_brain_queue_ignores_empty_topic():
    q = BrainQueue(corpus_dir="/tmp/fake", max_topics=5)
    out = q.enqueue("", requested_by="test")
    assert "ignored" in out
    assert q.stats.enqueued == 0


# Note: end-to-end "worker drains topics" coverage lives in integration smoke,
# not unit tests — it requires a real asyncio loop + BrainAgent mock and adds
# a pytest-asyncio dependency that isn't worth it for one test.


# ---- request_brain_research tool ----------------------------------------

def _invoke(decorated, args):
    return asyncio.run(decorated.handler(args))


@pytest.fixture
def ctx_with_queue(tmp_path):
    """PentestContext with a real BrainQueue plugged in (worker NOT started)."""
    scope_path = _make_scope_yaml(tmp_path)
    scope = Scope.load(str(scope_path))
    audit = AuditLog(tmp_path / ".audit.jsonl")
    workspace = tmp_path / "ws"
    workspace.mkdir()
    queue = BrainQueue(corpus_dir=str(tmp_path / "fake-corpus"), max_topics=5)
    c = p_tools.PentestContext(
        scope=scope, audit=audit, workspace_dir=workspace, http=None,
        rate_limit_per_host_sec=0.0, brain_queue=queue,
    )
    p_tools.set_context(c)
    return c, queue


@pytest.fixture
def ctx_no_queue(tmp_path):
    scope_path = _make_scope_yaml(tmp_path)
    scope = Scope.load(str(scope_path))
    audit = AuditLog(tmp_path / ".audit.jsonl")
    workspace = tmp_path / "ws"
    workspace.mkdir()
    c = p_tools.PentestContext(
        scope=scope, audit=audit, workspace_dir=workspace, http=None,
        rate_limit_per_host_sec=0.0, brain_queue=None,
    )
    p_tools.set_context(c)
    return c


def test_request_brain_research_enqueues(ctx_with_queue):
    ctx, queue = ctx_with_queue
    out = _invoke(p_tools.request_brain_research, {
        "topic": "SSRF bypass in Next.js image optimizer",
        "justification": "Recon found Vercel/Next.js — want bypass precedent",
    })
    assert out.get("is_error") is not True
    assert "enqueued" in out["content"][0]["text"]
    assert queue.stats.enqueued == 1
    # Audit log entry written.
    raw = ctx.audit.path.read_text()
    assert "request_brain_research" in raw
    assert "SSRF bypass" in raw


def test_request_brain_research_dedup(ctx_with_queue):
    ctx, queue = ctx_with_queue
    _invoke(p_tools.request_brain_research, {"topic": "GraphQL JWT bypass", "justification": ""})
    out = _invoke(p_tools.request_brain_research, {"topic": "graphql jwt bypass", "justification": ""})
    text = out["content"][0]["text"]
    assert "skipped" in text
    assert queue.stats.enqueued == 1
    assert queue.stats.skipped_dup == 1


def test_request_brain_research_without_queue_fails_gracefully(ctx_no_queue):
    out = _invoke(p_tools.request_brain_research, {"topic": "anything", "justification": ""})
    assert out["is_error"] is True
    assert "brain queue not enabled" in out["content"][0]["text"]


def test_request_brain_research_requires_topic(ctx_with_queue):
    out = _invoke(p_tools.request_brain_research, {"topic": "  ", "justification": ""})
    assert out["is_error"] is True


# ---- auto_brain keyword extraction --------------------------------------

def test_extract_picks_up_tech_stack():
    text = "The target is a Next.js app deployed on Vercel."
    topics = auto_brain.extract_research_topics(text)
    assert any("Next.js" in t for t in topics)
    assert any("Vercel" in t for t in topics)


def test_extract_picks_up_cve():
    text = "The advisory is CVE-2024-12345 affecting Spring Boot 2.x."
    topics = auto_brain.extract_research_topics(text)
    assert any("CVE-2024-12345" in t for t in topics)


def test_extract_picks_up_cwe():
    text = "This is a textbook CWE-918 SSRF case."
    topics = auto_brain.extract_research_topics(text)
    # Both CWE and "SSRF" hit — should produce at least one of each.
    assert any("CWE-918" in t for t in topics) or any("SSRF" in t for t in topics)


def test_extract_picks_up_vuln_keywords():
    text = "Initial recon identified XXE and SSTI candidates."
    topics = auto_brain.extract_research_topics(text)
    assert any("XXE" in t for t in topics) or any("SSTI" in t for t in topics)


def test_extract_caps_at_max_per_result():
    # Many overlapping signals — must still cap at MAX_TOPICS_PER_RESULT.
    text = (
        "Next.js Vercel WordPress Django Rails Spring Boot Kubernetes Redis "
        "MongoDB CVE-2024-1 CVE-2024-2 CVE-2024-3 SSRF XSS XXE"
    )
    topics = auto_brain.extract_research_topics(text)
    assert len(topics) <= auto_brain.MAX_TOPICS_PER_RESULT


def test_extract_excludes_already_seen():
    text = "Hosting on Vercel with Next.js"
    topics = auto_brain.extract_research_topics(
        text, exclude={"next.js attack surface and cves"},
    )
    # Vercel still in, Next.js excluded.
    assert any("Vercel" in t for t in topics)
    assert not any(t.lower() == "next.js attack surface and cves" for t in topics)


def test_extract_empty_text_returns_empty():
    assert auto_brain.extract_research_topics("") == []
    assert auto_brain.extract_research_topics(None) == []
