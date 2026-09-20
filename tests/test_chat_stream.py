"""Tests for Phase A.1 — SSE streaming on /chat (Task #68)."""

from __future__ import annotations

import io
import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from sentinel.llm.ollama_client import OllamaClient
from sentinel.rag.conversation import ConversationSession, Turn
from sentinel.web.app import create_app


# ---- OllamaClient.generate_stream ------------------------------------------


def _fake_ollama_stream_lines(chunks: list[str]) -> bytes:
    """Build a fake /api/generate stream response: one JSON object per line,
    last one with done=true."""
    parts = []
    for i, c in enumerate(chunks):
        parts.append(json.dumps({"response": c, "done": i == len(chunks) - 1}).encode())
    return b"\n".join(parts) + b"\n"


def test_generate_stream_yields_chunks_until_done():
    client = OllamaClient(host="http://stub:11434", model="test")
    fake = io.BytesIO(_fake_ollama_stream_lines(["Hello", " ", "world"]))
    fake.__enter__ = lambda self: self
    fake.__exit__ = lambda self, *a: False
    with patch("urllib.request.urlopen", return_value=fake):
        out = list(client.generate_stream("hi"))
    assert out == ["Hello", " ", "world"]


def test_generate_stream_ignores_malformed_json_lines():
    client = OllamaClient(host="http://stub:11434", model="test")
    raw = b'{"response":"valid","done":false}\n<<garbage>>\n{"response":"end","done":true}\n'
    fake = io.BytesIO(raw)
    fake.__enter__ = lambda self: self
    fake.__exit__ = lambda self, *a: False
    with patch("urllib.request.urlopen", return_value=fake):
        out = list(client.generate_stream("hi"))
    assert out == ["valid", "end"]


def test_generate_stream_returns_empty_on_transport_error():
    import urllib.error
    client = OllamaClient(host="http://stub:11434", model="test")
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("nope")):
        out = list(client.generate_stream("hi"))
    assert out == []


# ---- POST /chat/<sid>/stream -----------------------------------------------


@pytest.fixture
def chat_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("sentinel.rag.conversation.CHAT_SESSIONS_DIR", tmp_path / "chat")
    return tmp_path / "chat"


@pytest.fixture
def client(chat_dir):
    return TestClient(create_app())


def _stub_chip_set():
    return [{"name": "owasp", "count": 100}], 100_000


def _make_session() -> ConversationSession:
    sess = ConversationSession.new()
    sess.append_turn(Turn(role="user", content="prior question"))  # creates the file
    return sess


def test_stream_endpoint_returns_event_stream(client, chat_dir):
    sess = _make_session()
    with patch("sentinel.web.routes.chat._resolve_chip_set", return_value=_stub_chip_set()), \
         patch("sentinel.web.routes.chat.OllamaEmbedder"), \
         patch("sentinel.web.routes.chat.CorpusStore"), \
         patch("sentinel.web.routes.chat.OllamaClient") as MockOllama:
        retriever_mock = MagicMock()
        retriever_mock.retrieve.return_value = []
        with patch("sentinel.web.routes.chat.Retriever", return_value=retriever_mock):
            instance = MockOllama.return_value
            instance.generate_stream.return_value = iter(["Hello", " world"])
            r = client.post(f"/chat/{sess.id}/stream", data={"message": "hi", "top_k": 5})
    assert r.status_code == 200
    assert "text/event-stream" in r.headers.get("content-type", "")
    body = r.text
    assert "event: token" in body
    assert "data: Hello" in body
    assert "event: done" in body
    assert f"/chat/{sess.id}/refresh" in body  # done payload points at refresh URL


def test_stream_persists_user_turn_immediately_then_assistant(client, chat_dir):
    """Even if the stream ends, both turns must end up in the JSONL."""
    sess = _make_session()
    with patch("sentinel.web.routes.chat._resolve_chip_set", return_value=_stub_chip_set()), \
         patch("sentinel.web.routes.chat.OllamaEmbedder"), \
         patch("sentinel.web.routes.chat.CorpusStore"), \
         patch("sentinel.web.routes.chat.OllamaClient") as MockOllama:
        retriever_mock = MagicMock()
        retriever_mock.retrieve.return_value = []
        with patch("sentinel.web.routes.chat.Retriever", return_value=retriever_mock):
            MockOllama.return_value.generate_stream.return_value = iter(["one", "two"])
            client.post(f"/chat/{sess.id}/stream", data={"message": "what is X?"})
    loaded = ConversationSession.load(sess.id)
    contents = [t.content for t in loaded.history]
    assert "what is X?" in contents
    assert "onetwo" in contents


def test_stream_persists_partial_when_generation_raises(client, chat_dir):
    """If generate_stream blows up mid-yield, the partial assistant text
    must still land in the session JSONL."""
    sess = _make_session()

    def boom():
        yield "first chunk "
        yield "second chunk "
        raise RuntimeError("model died")

    with patch("sentinel.web.routes.chat._resolve_chip_set", return_value=_stub_chip_set()), \
         patch("sentinel.web.routes.chat.OllamaEmbedder"), \
         patch("sentinel.web.routes.chat.CorpusStore"), \
         patch("sentinel.web.routes.chat.OllamaClient") as MockOllama:
        retriever_mock = MagicMock()
        retriever_mock.retrieve.return_value = []
        with patch("sentinel.web.routes.chat.Retriever", return_value=retriever_mock):
            MockOllama.return_value.generate_stream.return_value = boom()
            r = client.post(f"/chat/{sess.id}/stream", data={"message": "go"})
    assert r.status_code == 200
    assert "event: error" in r.text
    loaded = ConversationSession.load(sess.id)
    last = loaded.history[-1]
    assert last.role == "assistant"
    assert "first chunk" in last.content
    assert "second chunk" in last.content


def test_stream_endpoint_404s_unknown_session(client, chat_dir):
    r = client.post("/chat/does-not-exist/stream", data={"message": "x"})
    assert r.status_code == 400
    assert "Session not found" in r.text


def test_stream_endpoint_rejects_empty_message(client, chat_dir):
    sess = _make_session()
    r = client.post(f"/chat/{sess.id}/stream", data={"message": "  "})
    assert r.status_code == 400


# ---- GET /chat/<sid>/refresh ------------------------------------------------


def test_refresh_renders_chat_thread_for_known_session(client, chat_dir):
    sess = _make_session()
    sess.append_turn(Turn(role="assistant", content="hello back"))
    with patch("sentinel.web.routes.chat._resolve_chip_set", return_value=_stub_chip_set()):
        r = client.get(f"/chat/{sess.id}/refresh")
    assert r.status_code == 200
    assert "prior question" in r.text
    assert "hello back" in r.text


def test_refresh_404s_unknown_session(client, chat_dir):
    r = client.get("/chat/does-not-exist/refresh")
    assert r.status_code == 400
