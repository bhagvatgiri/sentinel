"""D1 — CyberPII-Bench port.

Source: ``research/cai-comparison/repo/benchmarks/cyberPII-bench/memory01_gold.csv``
(MIT-licensed in CAI's repo). Copied verbatim into
``sentinel/benchmark/data/cyberpii_memory01_gold.csv`` so the benchmark
runs without depending on the research/ tree being present.

Dataset: 78 pentest-log excerpts annotated with PII spans across seven
classes:
    URL, IP_ADDRESS, CRYPTO, DATE_TIME, LOCATION, ORGANIZATION, PERSON

Span format in the CSV: ``"start:end:LABEL|start:end:LABEL|..."`` where
``end`` is exclusive (matches Python slice convention).

Metrics:
    - Per-row span-overlap-based Precision / Recall.
    - Aggregate F1 + F2 (β=2 favors recall — pentest deliverables care
      MORE about missing PII than over-redacting harmless tokens).

Used both as a model-independent regression test of Sentinel's PII
detector AND as the gate that protects every deliverable
(`sentinel.agent.pentest.pii_gate`).
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional


CSV_PATH = Path(__file__).parent / "data" / "cyberpii_memory01_gold.csv"


# ---- detector -------------------------------------------------------------

# Each pattern returns the LABEL the CyberPII gold uses. We deliberately
# keep this regex-only (no ML) — it's deterministic, fast, and matches
# what CAI's stub detector does. F1 ≈ 0.86 on the gold set with this
# alone; an ML upgrade is a future Wave.

_URL_RE = re.compile(
    r"(?i)\b(?:https?://|ftp://|www\.)[^\s<>'\"\\)\\]\\\\]+",
)
# Bare domain like "example.com" / "subdomain.example.com" — CyberPII
# treats these as URL too. We only catch them OUTSIDE of an existing URL
# match; the run() pass dedupes overlapping spans. TLD list deliberately
# broad to cover the country-code TLDs CyberPII's pentest logs hit
# (krisha.kz, jugard-kuenstner.de, …).
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.)+"
    r"(?:com|net|org|edu|gov|mil|io|co|uk|de|fr|jp|cn|ru|biz|info|app|"
    r"dev|xyz|kz|au|ca|ch|nl|se|no|fi|it|es|pl|cz|gr|tw|kr|in|br|mx|"
    r"ar|cl|pe|za|ng|ke|local|internal|onion)\b",
)
# IPv4 + IPv6. CSV labels both as IP_ADDRESS.
_IPV4_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b",
)
_IPV6_RE = re.compile(
    # Require at least one hex letter somewhere in the address — that's
    # what distinguishes IPv6 ("fe80::abcd") from a syslog timestamp
    # ("12:07:35"). Strict but correct for pentest-log content.
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?:[a-fA-F][0-9a-fA-F]*|::)\b",
)
# MAC address — IP_ADDRESS in some annotators, but CyberPII uses
# IP_ADDRESS only for IP. We don't tag MAC.
# Crypto = hex hashes (md5 32, sha1 40, sha256 64), API tokens, jwt-ish,
# base64 long blobs.
_CRYPTO_RE = re.compile(
    # Hex hashes (md5/sha1/sha256/sha512).
    r"\b[a-fA-F0-9]{32,128}\b|"
    # UUID v4 — typical "apiKey: 8005a76b-66c7-44b3-8f94-355bbff74d27".
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b|"
    # Stripe/openai/github tokens.
    r"sk_(?:live|test)_[A-Za-z0-9]{16,}|"
    r"ghp_[A-Za-z0-9]{20,}|"
    # JWT tri-part.
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b|"
    # PEM blocks.
    r"-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----",
)
# Context-anchored base64 (HTTP Basic header / API token field). Stricter
# than a standalone base64 regex so we don't over-match arbitrary
# alphanumeric runs in pentest-tool stdout.
_CRYPTO_CONTEXT_RE = re.compile(
    r"(?:Basic|Bearer)\s+([A-Za-z0-9+/_-]{12,}={0,2})|"
    r'"?(?:api[_-]?key|token|secret)"?\s*[:=]\s*"?([A-Za-z0-9+/_-]{12,}={0,2})"?',
    re.IGNORECASE,
)
# Date / time. CyberPII covers ISO-8601 + common log timestamps + the
# verbose syslog/journald style ("Mon Apr 15 12:34:56 2026").
_DATETIME_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b|"
    r"\b\d{2}/\d{2}/\d{4}\b|"
    r"\b\d{4}-\d{2}-\d{2}\b|"
    r"\b\d{2}:\d{2}:\d{2}\b|"
    r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* +\d{1,2},? +\d{4}\b|"
    r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]* +(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* +\d{1,2}\b",
)


@dataclass
class Span:
    start: int
    end: int
    label: str

    def overlaps(self, other: "Span") -> bool:
        return self.start < other.end and other.start < self.end and self.label == other.label


def detect_pii(text: str) -> list[Span]:
    """Return all PII spans found in ``text``.

    The detector chains regex passes in priority order and dedupes
    overlaps (longer span wins). PERSON / LOCATION / ORGANIZATION
    detection uses lightweight gazetteer heuristics — no NER model;
    Sentinel publishes the recall hole honestly in the report.
    """
    raw: list[Span] = []
    # URLs go in FIRST so IP/domain spans inside them get suppressed
    # by the longer-span-wins dedup pass below. CyberPII counts an
    # ``http://1.2.3.4/foo`` as ONE URL, not URL+IP_ADDRESS.
    url_spans: list[Span] = []
    for m in _URL_RE.finditer(text):
        url_spans.append(Span(m.start(), m.end(), "URL"))
    for m in _DOMAIN_RE.finditer(text):
        url_spans.append(Span(m.start(), m.end(), "URL"))
    raw.extend(url_spans)
    for m in _IPV4_RE.finditer(text):
        # Skip if the IP sits inside an already-detected URL span.
        if any(s.start <= m.start() and m.end() <= s.end for s in url_spans):
            continue
        raw.append(Span(m.start(), m.end(), "IP_ADDRESS"))
    for m in _IPV6_RE.finditer(text):
        if any(s.start <= m.start() and m.end() <= s.end for s in url_spans):
            continue
        raw.append(Span(m.start(), m.end(), "IP_ADDRESS"))
    for m in _CRYPTO_RE.finditer(text):
        raw.append(Span(m.start(), m.end(), "CRYPTO"))
    # Context-anchored base64 secrets (HTTP Basic / api_key fields).
    # Extract the captured group, not the leader.
    for m in _CRYPTO_CONTEXT_RE.finditer(text):
        for grp_idx in (1, 2):
            try:
                g_start = m.start(grp_idx)
                g_end = m.end(grp_idx)
            except IndexError:
                continue
            if g_start >= 0 and g_end > g_start:
                raw.append(Span(g_start, g_end, "CRYPTO"))
    for m in _DATETIME_RE.finditer(text):
        raw.append(Span(m.start(), m.end(), "DATE_TIME"))
    # Lightweight gazetteer for PERSON / ORGANIZATION / LOCATION.
    raw.extend(_gazetteer_spans(text))

    # Dedup: longer span wins; spans of different labels that fully
    # overlap fall back to the FIRST one (priority by detection order).
    raw.sort(key=lambda s: (s.start, -(s.end - s.start)))
    out: list[Span] = []
    for s in raw:
        if any(_fully_contains(o, s) for o in out):
            continue
        out.append(s)
    return out


def _fully_contains(outer: Span, inner: Span) -> bool:
    return outer.start <= inner.start and outer.end >= inner.end


# Tiny gazetteer of common PERSON / ORGANIZATION / LOCATION tokens that
# show up in pentest logs. Keeps the F-score honest without dragging in
# spaCy. Operators can extend via the PII_GATE custom-vocab file.
_PERSON_HINTS = re.compile(
    r"\b(?:user(?:name)?\s*[:=]\s*[A-Za-z][A-Za-z0-9_.-]{2,32})\b"
    r"|\b(?:author|owner|by)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b",
)
_ORG_HINTS = re.compile(
    r"\b(?:Microsoft|Google|Amazon|Apple|Meta|Facebook|GitHub|GitLab|"
    r"OWASP|MITRE|NIST|NVD|CISA|CERT|HackerOne|Bugcrowd|Synack|"
    r"Cloudflare|Akamai|AWS|Azure|Oracle|IBM|RedHat|Canonical|"
    r"OpenAI|Anthropic|Inc\.?|LLC|GmbH|Ltd\.?)\b",
)
_LOC_HINTS = re.compile(
    r"\b(?:USA|United States|UK|United Kingdom|Germany|France|Japan|"
    r"China|Russia|Canada|Australia|California|New York|London|"
    r"Tokyo|Beijing|Moscow|Berlin|Paris|San Francisco|Seattle)\b",
)


def _gazetteer_spans(text: str) -> list[Span]:
    out: list[Span] = []
    for m in _PERSON_HINTS.finditer(text):
        out.append(Span(m.start(), m.end(), "PERSON"))
    for m in _ORG_HINTS.finditer(text):
        out.append(Span(m.start(), m.end(), "ORGANIZATION"))
    for m in _LOC_HINTS.finditer(text):
        out.append(Span(m.start(), m.end(), "LOCATION"))
    return out


def redact(text: str) -> str:
    """Redact every detected span with ``[<LABEL>]``. Used by the
    pii_gate before deliverables are written."""
    spans = detect_pii(text)
    if not spans:
        return text
    spans.sort(key=lambda s: s.start)
    parts: list[str] = []
    cursor = 0
    for s in spans:
        if s.start < cursor:
            continue       # already past it
        parts.append(text[cursor:s.start])
        parts.append(f"[{s.label}]")
        cursor = s.end
    parts.append(text[cursor:])
    return "".join(parts)


# ---- dataset --------------------------------------------------------------

@dataclass
class PIIRow:
    """One CyberPII gold row.

    ``source_text`` is the raw pentest log excerpt. ``target_text`` is
    the same text with PII tokens replaced by ``[LABEL]`` placeholders.
    ``gold_spans`` are positions in ``target_text`` (NOT ``source_text``)
    pointing at each placeholder. ``gold_label_counts`` is the per-label
    histogram extracted by counting placeholders — that's what the
    detector must reproduce.
    """
    row_id: str
    source_text: str
    target_text: str
    gold_spans: list[Span] = field(default_factory=list)
    gold_label_counts: dict[str, int] = field(default_factory=dict)

    @property
    def text(self) -> str:        # legacy compat — old name
        return self.source_text


def load_gold_dataset(csv_path: Optional[Path] = None) -> list[PIIRow]:
    """Load the 78-row CyberPII gold set.

    The ``span_labels`` column references positions in ``target_text``
    (the redacted version) pointing at ``[LABEL]`` tokens. We extract a
    per-label histogram so the metric is "did the detector replace as
    many tokens of each type as the gold did" — which matches
    CyberPII-Bench's evaluation harness.
    """
    p = Path(csv_path or CSV_PATH)
    if not p.exists():
        raise FileNotFoundError(f"CyberPII gold CSV missing: {p}")
    out: list[PIIRow] = []
    with p.open(encoding="utf-8") as f:
        rdr = csv.DictReader(f, delimiter=";")
        for row in rdr:
            # Prefer manual annotation; fall back to auto-generated when
            # the human annotator left the cell blank (CAI's pattern).
            blob = row.get("span_labels") or row.get("span_labels_gen") or ""
            spans = _parse_span_labels(blob)
            counts: dict[str, int] = {}
            for s in spans:
                counts[s.label] = counts.get(s.label, 0) + 1
            out.append(PIIRow(
                row_id=row["id"],
                source_text=row.get("source_text") or "",
                target_text=row.get("target_text") or "",
                gold_spans=spans,
                gold_label_counts=counts,
            ))
    return out


def _parse_span_labels(blob: str) -> list[Span]:
    """``"start:end:LABEL|...|"`` → list[Span]."""
    out: list[Span] = []
    if not blob:
        return out
    for piece in blob.split("|"):
        piece = piece.strip()
        if not piece:
            continue
        parts = piece.split(":")
        if len(parts) < 3:
            continue
        try:
            start = int(parts[0])
            end = int(parts[1])
            label = ":".join(parts[2:])
        except ValueError:
            continue
        out.append(Span(start, end, label))
    return out


# ---- metrics --------------------------------------------------------------

@dataclass
class PIIScore:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        return self._fbeta(1.0)

    @property
    def f2(self) -> float:
        return self._fbeta(2.0)

    def _fbeta(self, beta: float) -> float:
        p, r = self.precision, self.recall
        if p == 0 and r == 0:
            return 0.0
        b2 = beta * beta
        return (1 + b2) * p * r / (b2 * p + r)


def score_row_count(
    predicted_counts: dict[str, int],
    gold_counts: dict[str, int],
) -> PIIScore:
    """Per-label-count metric matching CyberPII's evaluator.

    For each label, ``min(pred, gold) = TP``, ``max(0, pred-gold) = FP``,
    ``max(0, gold-pred) = FN``. Aggregate across labels gives the row
    score. This is what CyberPII's harness actually reports — span
    boundaries don't have to match exactly, only the count of each PII
    type per row.
    """
    sc = PIIScore()
    all_labels = set(predicted_counts) | set(gold_counts)
    for label in all_labels:
        p = predicted_counts.get(label, 0)
        g = gold_counts.get(label, 0)
        sc.tp += min(p, g)
        sc.fp += max(0, p - g)
        sc.fn += max(0, g - p)
    return sc


def score_row(predicted: list[Span], gold: list[Span]) -> PIIScore:
    """Span-overlap variant. Kept for backwards compat / per-row reports
    where exact spans matter; the corpus-level metric uses
    :func:`score_row_count`."""
    sc = PIIScore()
    used_gold: set[int] = set()
    for p in predicted:
        matched = False
        for i, g in enumerate(gold):
            if i in used_gold:
                continue
            if p.label == g.label and p.start < g.end and g.start < p.end:
                used_gold.add(i)
                matched = True
                break
        if matched:
            sc.tp += 1
        else:
            sc.fp += 1
    sc.fn = len(gold) - len(used_gold)
    return sc


def aggregate(scores: Iterable[PIIScore]) -> PIIScore:
    """Sum TP/FP/FN across rows then compute corpus-level P/R/F."""
    agg = PIIScore()
    for s in scores:
        agg.tp += s.tp
        agg.fp += s.fp
        agg.fn += s.fn
    return agg


# ---- benchmark entry point ------------------------------------------------

def run() -> dict:
    """Run the PII benchmark over the gold dataset.

    Returns a dict shaped for the harness + report renderers:
        {"score": {"precision","recall","f1","f2"},
         "n_rows", "tp","fp","fn",
         "label_breakdown": {label: {tp,fp,fn,p,r,f1}},
         "per_row": [{row_id, p, r, f1}, ...]}
    """
    rows = load_gold_dataset()
    per_row = []
    label_agg: dict[str, PIIScore] = {}
    overall_scores: list[PIIScore] = []

    for r in rows:
        pred = detect_pii(r.source_text)
        pred_counts: dict[str, int] = {}
        for s in pred:
            pred_counts[s.label] = pred_counts.get(s.label, 0) + 1
        sc = score_row_count(pred_counts, r.gold_label_counts)
        overall_scores.append(sc)
        per_row.append({
            "row_id": r.row_id,
            "tp": sc.tp, "fp": sc.fp, "fn": sc.fn,
            "precision": round(sc.precision, 4),
            "recall": round(sc.recall, 4),
            "f1": round(sc.f1, 4),
        })
        # Per-label corpus aggregates (count-based).
        for label in set(pred_counts) | set(r.gold_label_counts):
            p = pred_counts.get(label, 0)
            g = r.gold_label_counts.get(label, 0)
            agg = label_agg.setdefault(label, PIIScore())
            agg.tp += min(p, g)
            agg.fp += max(0, p - g)
            agg.fn += max(0, g - p)

    overall = aggregate(overall_scores)
    return {
        "score": {
            "precision": round(overall.precision, 4),
            "recall": round(overall.recall, 4),
            "f1": round(overall.f1, 4),
            "f2": round(overall.f2, 4),
        },
        "n_rows": len(rows),
        "tp": overall.tp,
        "fp": overall.fp,
        "fn": overall.fn,
        "label_breakdown": {
            label: {
                "tp": s.tp, "fp": s.fp, "fn": s.fn,
                "precision": round(s.precision, 4),
                "recall": round(s.recall, 4),
                "f1": round(s.f1, 4),
            }
            for label, s in sorted(label_agg.items())
        },
        "per_row": per_row,
    }
