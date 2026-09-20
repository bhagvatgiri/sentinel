"""CorpusIndex — flat-numpy vector store + metadata sidecar (Plan 05-02, NOVEL-02).

The novelty scorer in Plan 05-03 needs:
  * Single-call load (no Chroma client warm-up per pipeline run)
  * Per-finding nearest() that vectorizes against the entire corpus in one
    numpy dot-product (microseconds, not milliseconds)
  * Stable on-disk shape that survives `~/sentinel-corpus/` getting copied
    between machines or backed up

Persistence layout — under <corpus_dir>/novelty-index/:

    vectors.npy        # numpy.float32 array, shape (N, D); D=768 for nomic-embed-text
    metadata.jsonl     # one JSON object per line, ordered to align with vectors row index

Row N in vectors.npy describes IndexEntry N in metadata.jsonl. CorpusIndex.load()
validates that the two files have matching row counts — a truncated or hand-edited
vectors.npy will raise ValueError loudly (T-05-02-01 mitigation).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np


@dataclass
class IndexEntry:
    """Per-row metadata aligned to a single vector row in CorpusIndex.vectors.

    The fields here are what Plan 05-03's NoveltyScorer needs to render a
    "nearest corpus chunk" explanation to the operator AND what Plan 05-05's
    dashboard needs to surface the citation.

    text_preview is the first 240 chars of the chunk text (per <interfaces> in
    the plan) — enough to render a UI card, small enough to keep metadata.jsonl
    under a few MB for the ~14k-chunk seed corpus.
    """

    chunk_id: str
    source: str
    title: str
    text_preview: str
    url: Optional[str] = None
    cve_id: Optional[str] = None


@dataclass
class NearestMatch:
    """Single nearest-neighbor result from CorpusIndex.nearest().

    cosine_distance is in [0.0, 2.0]; closer to 0.0 = more similar. Plan 05-03
    inverts this to a [0, 1] novelty score: high distance = high novelty.
    """

    cosine_distance: float
    entry: IndexEntry


@dataclass
class CorpusIndex:
    """Flat-numpy vector index + per-row metadata.

    vectors  : numpy.float32 array shape (N, D). D = 768 for nomic-embed-text.
    entries  : list[IndexEntry] of length N, aligned to vectors row index.

    Construction is cheap (no validation cost beyond what numpy does); persist()
    serializes to two sidecar files; load() reconstitutes from those files and
    validates row alignment.
    """

    vectors: np.ndarray
    entries: list[IndexEntry] = field(default_factory=list)

    @property
    def size(self) -> int:
        """Number of vector rows / entries (always equal by construction)."""
        return int(self.vectors.shape[0])

    @property
    def dim(self) -> int:
        """Embedding dimensionality (typically 768 for nomic-embed-text)."""
        if self.vectors.ndim < 2:
            return 0
        return int(self.vectors.shape[1])

    def persist(self, dir_path: Path | str) -> None:
        """Write vectors.npy + metadata.jsonl under dir_path. Creates dir if needed.

        Idempotent: re-persisting the same CorpusIndex overwrites both files.
        Per Plan 05-02 T-05-02-04, no --force flag — the operator's intent is
        always "refresh", so overwrite is the correct default.
        """
        dir_path = Path(dir_path).expanduser()
        dir_path.mkdir(parents=True, exist_ok=True)

        # vectors.npy — numpy native format, fast mmap on reload
        np.save(dir_path / "vectors.npy", self.vectors.astype(np.float32, copy=False))

        # metadata.jsonl — one JSON object per line, aligned to vectors row index
        meta_path = dir_path / "metadata.jsonl"
        with meta_path.open("w", encoding="utf-8") as fh:
            for entry in self.entries:
                fh.write(json.dumps(asdict(entry), ensure_ascii=False))
                fh.write("\n")

    @classmethod
    def load(cls, dir_path: Path | str) -> "CorpusIndex":
        """Reload a CorpusIndex from a directory previously written by persist().

        Validates row alignment between vectors.npy and metadata.jsonl. A
        mismatch raises ValueError (T-05-02-01 mitigation: truncated or
        hand-edited sidecars fail loudly rather than silently misaligning).
        """
        dir_path = Path(dir_path).expanduser()
        vectors_path = dir_path / "vectors.npy"
        meta_path = dir_path / "metadata.jsonl"
        if not vectors_path.exists():
            raise FileNotFoundError(f"missing vectors.npy under {dir_path}")
        if not meta_path.exists():
            raise FileNotFoundError(f"missing metadata.jsonl under {dir_path}")

        vectors = np.load(vectors_path)
        # Ensure float32 — load() may bring back the dtype we wrote, but be
        # defensive in case future code paths drop in arrays of other dtypes.
        if vectors.dtype != np.float32:
            vectors = vectors.astype(np.float32, copy=False)

        entries: list[IndexEntry] = []
        with meta_path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                obj = json.loads(raw)
                entries.append(
                    IndexEntry(
                        chunk_id=obj.get("chunk_id", ""),
                        source=obj.get("source", ""),
                        title=obj.get("title", ""),
                        text_preview=obj.get("text_preview", ""),
                        url=obj.get("url"),
                        cve_id=obj.get("cve_id"),
                    )
                )

        if vectors.shape[0] != len(entries):
            raise ValueError(
                "CorpusIndex.load: row alignment mismatch — "
                f"vectors.npy has {vectors.shape[0]} rows but metadata.jsonl "
                f"has {len(entries)} lines (T-05-02-01 mitigation)."
            )

        return cls(vectors=vectors, entries=entries)

    def nearest(
        self, query: np.ndarray, top_k: int = 1
    ) -> list[NearestMatch]:
        """Return the top_k entries with lowest cosine distance to query.

        Vectorized: computes `vectors @ query` in a single numpy op, divides
        by per-row norms + query norm, sorts ascending, slices top_k.

        Edge cases (T-05-02-05):
          * Empty index -> []
          * Zero-norm query -> [] (cosine is undefined; surface as "no match"
            rather than ZeroDivisionError)
        """
        if self.size == 0:
            return []

        query_arr = np.asarray(query, dtype=np.float32).ravel()
        query_norm = float(np.linalg.norm(query_arr))
        if query_norm <= 0.0:
            return []

        # Per-row norms; protect against zero-norm corpus rows by clamping
        # the divisor (a zero-norm row will yield cosine=0 / clamped denom -> 0,
        # producing cosine_distance=1.0 for that row — non-fatal).
        row_norms = np.linalg.norm(self.vectors, axis=1)
        row_norms_safe = np.where(row_norms > 0.0, row_norms, 1.0)

        dot = self.vectors @ query_arr
        cosines = dot / (row_norms_safe * query_norm)
        # If a row was zero-norm we forced the divisor to 1.0; the dot product
        # is also 0 in that case so cosines stays 0 there — distance becomes
        # 1.0, which is the correct "orthogonal / unrelated" answer.

        distances = 1.0 - cosines

        # argsort ascending; slice top_k; map back to entries.
        k = min(top_k, self.size)
        order = np.argsort(distances, kind="stable")[:k]
        out: list[NearestMatch] = []
        for i in order:
            out.append(
                NearestMatch(
                    cosine_distance=float(distances[i]),
                    entry=self.entries[int(i)],
                )
            )
        return out


def _cosine_distance(a: np.ndarray, b: np.ndarray) -> float:
    """Standalone cosine distance helper.

    Used by Plan 05-03's NoveltyScorer when it needs to compute the distance
    between two known vectors outside of the index-wide nearest() path. The
    1e-12 floor protects against ZeroDivisionError on degenerate inputs.
    """
    denom = float(np.linalg.norm(a) * np.linalg.norm(b)) or 1e-12
    return float(1.0 - float(np.dot(a, b)) / denom)
