"""score_novelty primitive (Plan 05-03, NOVEL-04 partial).

The per-finding novelty score the Plan 05-04 RunReport escalation gate consumes:

  score = 1.0 - clip(max_cosine_similarity, 0.0, 1.0)

  0.0 = finding's embedding matches a corpus chunk exactly
  1.0 = finding's embedding has no neighbor (orthogonal / anti-parallel / empty index)

The scorer is pure-Python with TWO defensive fallback paths:

  1. Embedder unreachable (Ollama down): embed_one returns None -> we return 0.0.
     CONSERVATIVE-FAIL: without an embedding we have no novelty signal, so
     downstream escalation does NOT fire. Better to under-escalate than crash
     the pipeline. The scorer logs the fall-through at WARNING; Plan 05-04's
     pipeline wiring records it to the engagement audit log as a normal event.

  2. Empty index (operator never ran `novelty refresh-index`): return 1.0
     (vacuously novel). Plan 05-04's gate has its own empty-index short-circuit
     so this is informational; the float is still in-range and won't trip the
     Finding.novelty_score [0.0, 1.0] invariant.

The OllamaEmbedder is lazily constructed on first call (the kwarg=None default
is the standard injection seam — Plan 05-04's pipeline.py always passes a real
embedder; tests inject MagicMock).
"""

from __future__ import annotations

import logging
from typing import Optional

import numpy as np

from sentinel.agent.novelty.corpus_index import CorpusIndex
from sentinel.core.findings import Finding
from sentinel.corpus.embedder import OllamaEmbedder


log = logging.getLogger(__name__)


def score_novelty(
    finding: Finding,
    index: CorpusIndex,
    embedder: Optional[OllamaEmbedder] = None,
) -> float:
    """Per-finding novelty score against a pre-built CorpusIndex.

    Args:
        finding: Source finding. Query text is built from
            `finding.title + " " + (finding.description or "")`.
        index: A CorpusIndex (Plan 05-02). May be empty (size == 0) — that
            short-circuits to 1.0 (vacuously novel).
        embedder: Optional OllamaEmbedder. If None, a default one is constructed
            lazily (host=localhost:11434, model=nomic-embed-text). Tests inject
            a MagicMock with `.embed_one.return_value = [...]`.

    Returns:
        float in [0.0, 1.0]:
          * 0.0 — exact corpus match OR embedder unreachable (CONSERVATIVE-FAIL)
          * 1.0 — orthogonal/anti-parallel to every corpus row, OR empty index
          * else — `1.0 - max_cosine_similarity` clamped to [0.0, 1.0]
    """
    # Step 1 — build the query text. Per Plan 05-03 <interfaces>:
    #   title + " " + description.
    # The (or "") guards against legacy Findings deserialized with description=None
    # (shouldn't happen — the dataclass requires it — but be defensive).
    query_text = f"{finding.title} {finding.description or ''}".strip()

    # Step 2 — embed via the supplied (or lazily-constructed) embedder.
    embed_client = embedder if embedder is not None else OllamaEmbedder()
    vector = embed_client.embed_one(query_text)

    # Step 3 — CONSERVATIVE-FAIL on embedder failure. Returning 0.0 means the
    # downstream Plan 05-04 escalation gate (novelty_score >= threshold) does
    # NOT fire — preferable to crashing or to escalating on no signal.
    if vector is None:
        log.warning(
            "score_novelty: embedder returned None for finding %r — "
            "returning 0.0 (conservative; no escalation)",
            finding.title,
        )
        return 0.0

    # Step 4 — empty index => vacuously novel. Plan 05-04's pipeline guard will
    # short-circuit escalation when the index is empty, so this value is
    # informational only.
    if index.size == 0:
        return 1.0

    # Step 5 — cosine-similarity nearest-neighbor. CorpusIndex.nearest returns
    # NearestMatch entries ordered by ascending cosine_distance; we take the
    # closest (top_k=1).
    query_vec = np.asarray(vector, dtype=np.float32)
    matches = index.nearest(query_vec, top_k=1)
    if not matches:
        # Zero-norm query (Plan 05-02 T-05-02-05 contract) — surfaces as "no
        # match"; novelty is undefined for a zero vector, so fall back to the
        # conservative 0.0 (same rationale as embedder failure).
        log.warning(
            "score_novelty: CorpusIndex.nearest returned [] for finding %r "
            "(likely zero-norm query) — returning 0.0 (conservative)",
            finding.title,
        )
        return 0.0

    nearest = matches[0]
    # cosine_distance is in [0.0, 2.0]; similarity = 1 - distance is in [-1.0, 1.0].
    # We clamp similarity to [0.0, 1.0] so anti-parallel vectors (similarity = -1)
    # don't drive novelty above 1.0 (the Finding.novelty_score [0.0, 1.0] invariant
    # would reject the resulting Finding mutation in Plan 05-04).
    similarity = 1.0 - float(nearest.cosine_distance)
    clamped_similarity = max(0.0, min(1.0, similarity))
    return float(1.0 - clamped_similarity)
