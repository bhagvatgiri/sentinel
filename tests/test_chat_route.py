"""Smoke tests for sentinel.web.routes.chat — endpoints respond with the right
shape. Heavy I/O (Chroma, Ollama) is mocked.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from sentinel.rag.conversation import ConversationSession, Turn
from sentinel.web.app import create_app


@pytest.fixture
def chat_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "sentinel.rag.conversation.CHAT_SESSIONS_DIR",
        tmp_path / "chat",
    )
    return tmp_path / "chat"


@pytest.fixture
def client(chat_dir):
    return TestClient(create_app())


def _stub_resolver():
    return [{"name": "owasp", "count": 100}, {"name": "hackerone", "count": 4950}], 320000


def test_chat_index_renders(client):
    with patch("sentinel.web.routes.chat._resolve_chip_set", return_value=_stub_resolver()):
        r = client.get("/chat")
    assert r.status_code == 200
    assert "Chat with the brain" in r.text
    # Chip set rendered from the introspection result
    assert "hackerone" in r.text
    assert "4,950" in r.text  # the dynamic count


def test_chat_new_creates_session_and_redirects(client, chat_dir):
    with patch("sentinel.web.routes.chat._resolve_chip_set", return_value=_stub_resolver()):
        r = client.post("/chat/new", data={"model": "llama3.1:8b"}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/chat/")
    sid = r.headers["location"].split("/")[-1]
    assert ConversationSession.load(sid) is not None


def test_chat_show_404s_on_unknown_session(client):
    with patch("sentinel.web.routes.chat._resolve_chip_set", return_value=_stub_resolver()):
        r = client.get("/chat/does-not-exist")
    assert r.status_code == 400  # _form_error returns 400
    assert "Session not found" in r.text


def test_chat_show_renders_existing_session_with_turns(client, chat_dir):
    """Regression for the chat_thread `session` vs `active_session` template
    variable bug surfaced 2026-XX-XX: GET /chat/<sid> with an existing
    session must render the conversation. Original Phase A tests only
    covered POST /message which passes `session` directly to the
    component; chat_show passes `active_session` and was missing a
    {% with session=active_session %} alias."""
    sess = ConversationSession.new()
    sess.append_turn(Turn(role="user", content="prior question"))
    sess.append_turn(Turn(role="assistant", content="prior answer"))
    with patch("sentinel.web.routes.chat._resolve_chip_set", return_value=_stub_resolver()):
        r = client.get(f"/chat/{sess.id}")
    assert r.status_code == 200, f"chat_show 500'd: {r.text[:300]}"
    assert "prior question" in r.text
    assert "prior answer" in r.text


def test_chat_message_appends_turns_and_renders(client, chat_dir):
    # Pre-create a session
    sess = ConversationSession.new()
    sess.append_turn(Turn(role="user", content="hi there"))  # creates the file

    fake_chunks = []  # empty retrieval still works

    with patch("sentinel.web.routes.chat._resolve_chip_set", return_value=_stub_resolver()), \
         patch("sentinel.web.routes.chat.OllamaEmbedder") as MockEmb, \
         patch("sentinel.web.routes.chat.CorpusStore") as MockStore, \
         patch("sentinel.web.routes.chat.OllamaClient") as MockOllama:
        MockEmb.return_value = MagicMock()
        MockStore.return_value = MagicMock()
        retriever_mock = MagicMock()
        retriever_mock.retrieve.return_value = fake_chunks
        with patch("sentinel.web.routes.chat.Retriever", return_value=retriever_mock):
            instance = MockOllama.return_value
            instance.generate.return_value = "Hello back!"
            r = client.post(
                f"/chat/{sess.id}/message",
                data={"message": "what is SSRF?", "top_k": 5},
            )

    assert r.status_code == 200
    assert "Hello back!" in r.text
    # Reload — should now have user(hi there) + user(what is SSRF?) + assistant(Hello back!)
    loaded = ConversationSession.load(sess.id)
    assert loaded is not None
    contents = [t.content for t in loaded.history]
    assert "hi there" in contents
    assert "what is SSRF?" in contents
    assert "Hello back!" in contents


def test_chat_message_auto_engagement_filter_banner(client, chat_dir):
    """When the user types an engagement-scoped phrase, the response surfaces
    the auto-filter banner."""
    # Use the actual new-session route so the file is persisted with the header.
    with patch("sentinel.web.routes.chat._resolve_chip_set", return_value=_stub_resolver()):
        new = client.post("/chat/new", data={"model": "llama3.1:8b"}, follow_redirects=False)
    assert new.status_code == 303
    sid = new.headers["location"].split("/")[-1]

    with patch("sentinel.web.routes.chat._resolve_chip_set", return_value=_stub_resolver()), \
         patch("sentinel.web.routes.chat.OllamaEmbedder"), \
         patch("sentinel.web.routes.chat.CorpusStore"), \
         patch("sentinel.web.routes.chat.OllamaClient") as MockOllama:
        retriever_mock = MagicMock()
        retriever_mock.retrieve.return_value = []
        with patch("sentinel.web.routes.chat.Retriever", return_value=retriever_mock):
            MockOllama.return_value.generate.return_value = "ok"
            r = client.post(
                f"/chat/{sid}/message",
                data={"message": "what was our recent SQL injection finding?", "top_k": 5},
            )

    assert r.status_code == 200
    assert "Detected engagement-scoped phrasing" in r.text


def test_chat_message_empty_returns_error(client, chat_dir):
    sess = ConversationSession.new()
    sess.append_turn(Turn(role="user", content="x"))
    r = client.post(f"/chat/{sess.id}/message", data={"message": "   "})
    assert r.status_code == 400
    assert "empty" in r.text.lower()
