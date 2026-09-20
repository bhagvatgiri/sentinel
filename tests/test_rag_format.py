"""Tests for retriever helpers — deterministic, no Chroma/Ollama needed."""

from sentinel.rag.retriever import RetrievedChunk, format_context


def test_format_context_empty():
    assert format_context([]) == ""


def test_format_context_numbers_and_cites():
    chunks = [
        RetrievedChunk(text="content one", title="Doc A", source="owasp", url="https://a", distance=0.1),
        RetrievedChunk(text="content two", title="Doc B", source="mitre-cwe", url=None, distance=0.2),
    ]
    out = format_context(chunks)
    assert "<context>" in out and "</context>" in out
    assert "[1] owasp: Doc A <https://a>" in out
    assert "[2] mitre-cwe: Doc B" in out
    assert "content one" in out
    assert "content two" in out
