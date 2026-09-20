"""NvdLoader — NVD-specific entry extractor for the novelty index (Plan 05-02, NOVEL-03).

Walks chunks pulled out of the Chroma corpus, filters by `source == "nvd"` +
`--since-year YYYY`, parses the `CVE-YYYY-NNNNN` id from chunk metadata, and
yields (vector, IndexEntry) tuples ready to assemble into a CorpusIndex.

NvdLoader treats malformed cve_id values as benign data quality issues and
silently skips them (T-05-02-05 mitigation — a poisoned metadata.cve_id field
cannot crash the refresh loop). Operators see the dropped-count reflected in
refresh_index's stats output but no audit-log flood.
"""

from __future__ import annotations

import re
from typing import Iterable, Iterator, Tuple

import numpy as np

from sentinel.agent.novelty.corpus_index import IndexEntry


# CVE id shape: CVE-<year 4-digit>-<sequence 4+ digits>
# Strict on the year (required for since_year filtering); permissive on the
# sequence portion (CVE IDs can be 4+ digits and may include letters in some
# experimental schemes — we accept any non-whitespace tail).
_CVE_ID_RE = re.compile(r"^CVE-(\d{4})-\S+$")

_PREVIEW_LEN = 240


class NvdLoader:
    """NVD chunk -> IndexEntry adapter with --since-year filter.

    Usage:
        loader = NvdLoader(since_year=2022)
        for vector, entry in loader.iter_entries(chunks_iter):
            ...   # assemble into CorpusIndex

    chunks_iter yields (chunk_id, vector, metadata, document) tuples — the
    same shape produced by refresh.py's `_iter_chroma_chunks` helper. NvdLoader
    does NOT itself talk to Chroma; it is a pure transformation stage that the
    refresh pipeline composes on top of the Chroma reader.
    """

    def __init__(self, since_year: int = 2020) -> None:
        self.since_year = int(since_year)

    def iter_entries(
        self,
        chunks: Iterable[Tuple[str, list[float] | np.ndarray, dict, str]],
    ) -> Iterator[Tuple[np.ndarray, IndexEntry]]:
        """Yield (vector, IndexEntry) pairs for in-window NVD chunks only."""
        for chunk_id, vector, metadata, document in chunks:
            cve_id = (metadata or {}).get("cve_id")
            if not cve_id or not isinstance(cve_id, str):
                # Test 5: missing cve_id -> silent skip
                continue

            match = _CVE_ID_RE.match(cve_id.strip())
            if not match:
                # Test 6: malformed cve_id -> silent skip
                continue

            try:
                year = int(match.group(1))
            except ValueError:
                # Defensive — the regex already constrained group(1) to 4 digits,
                # but be safe against future regex relaxations.
                continue
            if year < self.since_year:
                # Test 2: since_year filter
                continue

            text = document or ""
            preview = text[:_PREVIEW_LEN]

            # Normalize vector to numpy.float32 array (callers may pass either
            # list[float] from Chroma or np.ndarray from a pre-built fixture).
            vec_array = np.asarray(vector, dtype=np.float32).ravel()

            entry = IndexEntry(
                chunk_id=str(chunk_id),
                source="nvd",
                title=metadata.get("title", "") or cve_id,
                text_preview=preview,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                cve_id=cve_id,
            )
            yield vec_array, entry
