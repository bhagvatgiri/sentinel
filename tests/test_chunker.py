"""Tests for the chunker — deterministic, no external deps."""

from sentinel.corpus.chunker import chunk_document
from sentinel.corpus.document import Document


def _doc(text: str, source: str = "test") -> Document:
    return Document(
        id=Document.make_id(source, text[:40]),
        text=text,
        title="t",
        source=source,
    )


def test_short_document_one_chunk():
    chunks = chunk_document(_doc("short text"), chunk_size=200, chunk_overlap=20)
    assert len(chunks) == 1
    assert chunks[0].text == "short text"
    assert chunks[0].chunk_index == 0
    assert chunks[0].id.endswith("#chunk-0")


def test_chunk_ids_unique_and_indexed():
    long_text = "para A. " * 100 + "\n\n" + "para B. " * 100
    chunks = chunk_document(_doc(long_text), chunk_size=300, chunk_overlap=50)
    ids = [c.id for c in chunks]
    indices = [c.chunk_index for c in chunks]
    assert len(set(ids)) == len(ids)  # unique
    assert indices == list(range(len(chunks)))


def test_chunk_size_respected_within_tolerance():
    text = "x" * 5000
    chunks = chunk_document(_doc(text), chunk_size=500, chunk_overlap=50)
    # With overlap, chunks may exceed chunk_size by up to overlap chars; allow margin.
    for c in chunks:
        assert len(c.text) <= 500 + 60


def test_overlap_creates_continuity():
    text = "A" * 400 + "B" * 400 + "C" * 400
    chunks = chunk_document(_doc(text), chunk_size=400, chunk_overlap=50)
    assert len(chunks) >= 2
    # Subsequent chunks should start with characters that appeared at the end
    # of the previous chunk (overlap window).
    prev_tail = chunks[0].text[-50:]
    assert chunks[1].text.startswith(prev_tail) or prev_tail in chunks[1].text[:60]


def test_empty_text_no_chunks():
    assert chunk_document(_doc(""), 100, 10) == []
    assert chunk_document(_doc("   \n  \n"), 100, 10) == []


def test_metadata_propagated_to_chunks():
    d = Document(
        id="test:abc",
        text="long " * 200,
        title="My Title",
        source="src",
        url="https://example.com",
        tags=["x", "y"],
        metadata={"k": "v"},
    )
    chunks = chunk_document(d, chunk_size=200, chunk_overlap=20)
    assert all(c.title == "My Title" for c in chunks)
    assert all(c.source == "src" for c in chunks)
    assert all(c.url == "https://example.com" for c in chunks)
    assert all(c.metadata["k"] == "v" for c in chunks)
    assert all(c.metadata["tags"] == ["x", "y"] for c in chunks)
