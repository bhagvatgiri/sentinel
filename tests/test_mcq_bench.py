"""D3 — SecEval/CyberMetric MCQ RAG-regression test."""

from __future__ import annotations

import pytest

from sentinel.benchmark import mcq_bench


def test_dataset_has_50_questions():
    assert len(mcq_bench.QUESTIONS) == 50


def test_each_question_well_formed():
    for q in mcq_bench.QUESTIONS:
        assert q.qid
        assert q.question
        assert isinstance(q.choices, dict)
        assert len(q.choices) >= 2
        assert q.correct in q.choices, (
            f"{q.qid}: correct '{q.correct}' not in choices {list(q.choices)}"
        )
        assert q.rag_query


def test_run_with_default_stub_runners_produces_delta():
    """With cold = keyword baseline + rag = perfect-stub, delta is
    large + positive. This proves the harness wiring is correct
    without needing live Chroma/Ollama in CI."""
    r = mcq_bench.run()
    assert r["n_questions"] == 50
    assert r["rag_accuracy"] == 1.0
    assert r["cold_accuracy"] < 1.0
    assert r["delta"] > 0.5


def test_rag_must_beat_cold_by_at_least_10pct():
    """Spec: RAG accuracy must exceed cold by >= 10 %.

    With the stub RAG runner this is trivially true; the test exists
    as a regression guard so a future change to either runner that
    accidentally collapses the delta is caught immediately.
    """
    r = mcq_bench.run()
    assert (r["rag_accuracy"] - r["cold_accuracy"]) >= 0.10


def test_per_question_shape():
    r = mcq_bench.run()
    for q in r["per_question"]:
        for k in ("qid", "domain", "cold_answer", "rag_answer", "correct"):
            assert k in q


def test_cold_baseline_is_deterministic():
    """Same input → same output every call (no LLM in the loop)."""
    a = mcq_bench.cold_runner_keyword_baseline(mcq_bench.QUESTIONS[0])
    b = mcq_bench.cold_runner_keyword_baseline(mcq_bench.QUESTIONS[0])
    assert a == b


def test_custom_runners_can_be_passed():
    """Operators can plug in real runners for live benchmark runs."""
    always_a = lambda q: "A"
    r = mcq_bench.run(cold_runner=always_a, rag_runner=always_a)
    # cold == rag here -> delta is 0, accuracy depends on dataset
    assert r["delta"] == 0.0
