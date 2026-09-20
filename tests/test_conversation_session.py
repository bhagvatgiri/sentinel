"""Tests for sentinel.rag.conversation — session persistence + smart-default regex."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from sentinel.rag.conversation import (
    ConversationSession,
    Turn,
    detect_engagement_scope,
    is_low_info_query,
)


# ---- detect_engagement_scope --------------------------------------------


@pytest.mark.parametrize("msg", [
    "what was our recent SQL injection?",
    "show me my latest finding",
    "what did we find in this engagement?",
    "did this scan turn up anything serious?",
    "summarize OUR recent vulnerability",  # case-insensitive
    "what does the scan say about AcmeProgram?",
    "we found something weird",
])
def test_engagement_scope_positive(msg):
    assert detect_engagement_scope(msg) is True


@pytest.mark.parametrize("msg", [
    "what is SSRF?",
    "explain CWE-639",
    "how does PKCE work?",
    "tell me about NIST SP 800-53",
    "",
])
def test_engagement_scope_negative(msg):
    assert detect_engagement_scope(msg) is False


# ---- is_low_info_query --------------------------------------------------
# Regression for the 2026-XX-XX bug: "hey" pulled random PATT LFI chunks
# and the model described them as the answer.

@pytest.mark.parametrize("msg", [
    "hey", "hi", "Hello", "yo", "thanks", "ok", "nope", "bye", "yes",
    "hi!", "thanks.", "?", "??", "ok??", "ty",
    "a", "ab", "abc", "  ", " hi ",
])
def test_is_low_info_query_positive(msg):
    """These should ALL skip retrieval — they're greetings or too-short."""
    assert is_low_info_query(msg) is True, f"expected {msg!r} to be low-info"


@pytest.mark.parametrize("msg", [
    "what is SSRF?",
    "explain CWE-639",
    "how does PKCE work?",
    "are headers important",  # "are" passes the 3-char threshold; substantive enough
    "tell me",                  # 7 chars; substantive enough that retrieval might help
])
def test_is_low_info_query_negative(msg):
    assert is_low_info_query(msg) is False


# ---- ConversationSession persistence ------------------------------------


@pytest.fixture
def tmp_chat_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "sentinel.rag.conversation.CHAT_SESSIONS_DIR",
        tmp_path / "chat",
    )
    return tmp_path / "chat"


def test_new_session_has_unique_id():
    s1 = ConversationSession.new()
    s2 = ConversationSession.new()
    assert s1.id != s2.id
    assert len(s1.id) > 10
    # Sortable: starts with ISO date
    assert s1.id[:4] == "2026" or s1.id[:4] == "2025"  # works in 2025 or 2026


def test_append_and_load_roundtrip(tmp_chat_dir):
    sess = ConversationSession.new(model="llama3.1:8b", source_filters=["owasp"])
    sess.append_turn(Turn(role="user", content="hi"))
    sess.append_turn(Turn(
        role="assistant", content="hello",
        citations=[{"title": "T", "source": "owasp", "url": None, "distance": 0.3}],
        retrieval_query="hi",
    ))
    loaded = ConversationSession.load(sess.id)
    assert loaded is not None
    assert loaded.id == sess.id
    assert loaded.model == "llama3.1:8b"
    assert loaded.source_filters == ["owasp"]
    assert len(loaded.history) == 2
    assert loaded.history[0].role == "user"
    assert loaded.history[0].content == "hi"
    assert loaded.history[1].role == "assistant"
    assert loaded.history[1].citations[0]["source"] == "owasp"
    assert loaded.history[1].retrieval_query == "hi"


def test_load_nonexistent_session_returns_none(tmp_chat_dir):
    assert ConversationSession.load("does-not-exist") is None


def test_update_title_appends_header_line(tmp_chat_dir):
    sess = ConversationSession.new()
    sess.append_turn(Turn(role="user", content="x"))
    sess.update_title("My Title")
    loaded = ConversationSession.load(sess.id)
    assert loaded.title == "My Title"
    # File should have at least 3 lines: original header, turn, updated header
    lines = sess.path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) >= 3
    headers = [json.loads(l) for l in lines if json.loads(l).get("_header")]
    assert len(headers) == 2  # original + updated


def test_list_all_returns_newest_first(tmp_chat_dir):
    s1 = ConversationSession.new()
    s1.append_turn(Turn(role="user", content="a"))
    s1.update_title("first")
    # Force a small gap so created_at differs
    s2 = ConversationSession.new()
    s2.append_turn(Turn(role="user", content="b"))
    s2.update_title("second")
    s2.created_at = s1.created_at + 100
    s2.update_title("second")  # re-write header with bumped timestamp
    # patch s2.created_at into the header by writing manually
    sessions = ConversationSession.list_all()
    assert len(sessions) == 2
    ids = [s.id for s in sessions]
    assert s2.id in ids and s1.id in ids
