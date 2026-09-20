"""Phase 5 novelty subsystem (Plans 05-02 / 05-03 / 05-04 / 05-05).

This package owns the pre-embedded corpus+NVD vector index that backs the
NoveltyScorer in Plan 05-03. It deliberately lives next to (but separate from)
the broader `sentinel.corpus` package because:

  * `sentinel.corpus` owns the on-disk Chroma store and the ingestion pipeline
    (OWASP / MITRE / NVD / writeups / books) — that store stays the source of
    truth for RAG retrieval (ask + chat + brain-grow).
  * `sentinel.agent.novelty` owns the FLAT numpy.float32 (N, D) array sidecar
    derived from the Chroma store. The flat-array shape lets the scorer
    compute `vectors @ query` per finding in microseconds; going through
    Chroma per finding would add a network hop to the embedder + Python
    pagination overhead per call.

Public exports — populated incrementally across Phase 5 plans:

  Plan 05-02 (this plan)
    - CorpusIndex         : the flat-array vector store (persist/load/nearest)
    - IndexEntry          : per-row metadata aligned to a vector row
    - NearestMatch        : (cosine_distance, entry) result tuple
    - NvdLoader           : NVD-specific entry extractor (--since-year filter)
    - refresh_index       : the CLI entry point that builds + persists the index

  Plan 05-03 (APPENDS below)
    - NoveltyScorer       : per-finding scorer that wraps a CorpusIndex.load()

  Plan 05-04 (APPENDS below)
    - NoveltyThreshold    : scope.yaml-configurable escalation threshold helper

APPEND-only contract: every Phase 5 plan adds new exports below the existing
ones; no plan reorders, renames, or deletes prior exports.
"""

from sentinel.agent.novelty.corpus_index import (
    CorpusIndex,
    IndexEntry,
    NearestMatch,
)
from sentinel.agent.novelty.nvd_loader import NvdLoader
from sentinel.agent.novelty.refresh import refresh_index

# Plan 05-03 — APPEND-only below Plan 05-02's exports.
from sentinel.agent.novelty.scorer import score_novelty
from sentinel.agent.novelty.escalation_prompt import (
    EXPLOIT_CHAIN_SCHEMA,
    ExploitChain,
    parse_exploit_chain,
    render_escalation_prompt,
    validate_exploit_chain,
)

# Plan 05-04 — APPEND-only below Plan 05-03's exports.
from sentinel.agent.novelty.novel_finding_evidence import NovelFindingEvidence
from sentinel.agent.novelty.pipeline_gate import (
    EscalationDecision,
    GateResult,
    evaluate_novelty_gate,
)

__all__ = [
    # Plan 05-02
    "CorpusIndex",
    "IndexEntry",
    "NearestMatch",
    "NvdLoader",
    "refresh_index",
    # Plan 05-03
    "score_novelty",
    "render_escalation_prompt",
    "parse_exploit_chain",
    "validate_exploit_chain",
    "ExploitChain",
    "EXPLOIT_CHAIN_SCHEMA",
    # Plan 05-04
    "NovelFindingEvidence",
    "evaluate_novelty_gate",
    "EscalationDecision",
    "GateResult",
]
