"""Corpus pipeline — ingest cybersecurity reference material into a local
vector store and (optionally) into the Obsidian vault.

Architecture:

    Source  ->  Document  ->  Chunker  ->  Embedder  ->  Chroma store
                              |
                              +->  Obsidian writer

A `Source` yields `Document` objects (raw text + metadata). The pipeline
chunks them, embeds via Ollama, persists to Chroma, and writes a markdown
note per document into the user's vault.
"""

from sentinel.corpus.document import Document  # noqa: F401
