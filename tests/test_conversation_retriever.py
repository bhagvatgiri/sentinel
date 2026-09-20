"""Tests for sentinel.rag.conversation_retriever — query construction across turns."""

from __future__ import annotations

from unittest.mock import MagicMock

from sentinel.rag.conversation import ConversationSession, Turn
from sentinel.rag.conversation_retriever import ConversationRetriever


def _new_session_with_turns(turns: list[Turn]) -> ConversationSession:
    s = ConversationSession.new()
    s.history = list(turns)
    return s


def test_build_query_uses_only_user_turns():
    """Assistant content must NEVER end up in the retrieval query."""
    s = _new_session_with_turns([
        Turn(role="user", content="what is SSRF?"),
        Turn(role="assistant", content="SSRF is server-side request forgery — DON'T USE THIS TEXT"),
        Turn(role="user", content="any famous CVEs?"),
        Turn(role="assistant", content="There's CVE-2021-44228 etc. — DON'T USE THIS EITHER"),
    ])
    cr = ConversationRetriever(MagicMock())
    query = cr.build_query(s, "what about for log4j specifically?")
    # Last 2 prior user turns + current message — 3 lines total
    assert "what is SSRF?" in query
    assert "any famous CVEs?" in query
    assert "what about for log4j specifically?" in query
    # Assistant content MUST be excluded
    assert "DON'T USE THIS" not in query


def test_build_query_caps_at_two_prior_user_turns():
    """A long history should only contribute the most recent 2 user turns."""
    s = _new_session_with_turns([
        Turn(role="user", content="oldest user turn"),
        Turn(role="assistant", content="reply 1"),
        Turn(role="user", content="middle user turn"),
        Turn(role="assistant", content="reply 2"),
        Turn(role="user", content="newest prior user turn"),
        Turn(role="assistant", content="reply 3"),
    ])
    cr = ConversationRetriever(MagicMock())
    query = cr.build_query(s, "current message")
    assert "oldest user turn" not in query
    assert "middle user turn" in query
    assert "newest prior user turn" in query
    assert "current message" in query


def test_build_query_truncates_long_components():
    """Each component capped at 400 chars to avoid diluting the embedding."""
    long_msg = "x" * 1000
    s = _new_session_with_turns([Turn(role="user", content=long_msg)])
    cr = ConversationRetriever(MagicMock())
    query = cr.build_query(s, "current")
    # Each "x" segment should be capped at 400
    assert query.count("x") == 400


def test_retrieve_for_turn_uses_session_filter_when_no_override():
    """When session has source_filters set, they should drive retrieval."""
    s = _new_session_with_turns([])
    s.source_filters = ["owasp", "mitre-cwe"]
    inner = MagicMock()
    inner.retrieve.return_value = []
    cr = ConversationRetriever(inner)
    cr.retrieve_for_turn(s, "what is SSRF?")
    args, kwargs = inner.retrieve.call_args
    assert kwargs["source_filter"] == ["owasp", "mitre-cwe"]


def test_retrieve_for_turn_override_beats_session_filter():
    """An explicit source_filter overrides the session's pinned filters."""
    s = _new_session_with_turns([])
    s.source_filters = ["owasp"]
    inner = MagicMock()
    inner.retrieve.return_value = []
    cr = ConversationRetriever(inner)
    cr.retrieve_for_turn(s, "what is SSRF in 2024?", source_filter=["past-engagements"])
    args, kwargs = inner.retrieve.call_args
    assert kwargs["source_filter"] == ["past-engagements"]


# ---- garbage-retrieval guards (2026-XX-XX regression) -----------------


from sentinel.rag.retriever import RetrievedChunk


def _chunk(distance: float, text: str = "x") -> RetrievedChunk:
    return RetrievedChunk(text=text, title="t", source="owasp", url=None, distance=distance)


def test_low_info_query_skips_retrieval_entirely():
    """The 'hey' case: low-info query → no retriever call, chunks=[]."""
    s = _new_session_with_turns([])
    inner = MagicMock()
    cr = ConversationRetriever(inner)
    query_used, chunks = cr.retrieve_for_turn(s, "hey")
    assert chunks == []
    inner.retrieve.assert_not_called()


def test_distance_threshold_drops_unrelated_chunks_when_no_filter():
    """For substantive queries with no pinned filter, distance > 0.5 chunks
    get filtered. This protects against random matches when the corpus
    has no actually-relevant content."""
    s = _new_session_with_turns([])
    inner = MagicMock()
    inner.retrieve.return_value = [
        _chunk(0.2, "highly related"),
        _chunk(0.45, "still related"),
        _chunk(0.6, "noise 1"),
        _chunk(0.9, "noise 2"),
    ]
    cr = ConversationRetriever(inner)
    _, chunks = cr.retrieve_for_turn(s, "what is SSRF specifically?")
    assert len(chunks) == 2
    assert all(c.distance <= 0.5 for c in chunks)


def test_distance_threshold_NOT_applied_when_user_pinned_filter():
    """If the user explicitly pinned a source, respect their choice — even
    if the embedding match is weak. They asked for this scope."""
    s = _new_session_with_turns([])
    s.source_filters = ["past-engagements"]
    inner = MagicMock()
    inner.retrieve.return_value = [
        _chunk(0.7, "weak match"),
        _chunk(0.8, "weaker match"),
    ]
    cr = ConversationRetriever(inner)
    _, chunks = cr.retrieve_for_turn(s, "what was the recent finding?")
    # Should NOT filter — user pinned the source, give them what's there
    assert len(chunks) == 2


def test_distance_threshold_NOT_applied_when_explicit_override():
    """Same logic for an explicit per-turn override."""
    s = _new_session_with_turns([])
    inner = MagicMock()
    inner.retrieve.return_value = [_chunk(0.9, "weak")]
    cr = ConversationRetriever(inner)
    _, chunks = cr.retrieve_for_turn(s, "explain something", source_filter=["nvd"])
    assert len(chunks) == 1
