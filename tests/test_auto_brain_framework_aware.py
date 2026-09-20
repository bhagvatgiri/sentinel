"""Tests for the framework-aware auto_brain extension (Phase D).

When `framework_aware=True` (the default), each tech-stack pattern hit
emits both the generic attack-surface topic and a paired HackerOne
disclosed-reports query. This gives the brain agent a direct lane into
the H1 corpus for the specific framework — particularly powerful when
combined with `sentinel ingest --source hackerone --hackerone-full-bodies`.
"""

from __future__ import annotations

from sentinel.agent.pentest import auto_brain


def test_framework_aware_pairs_h1_query():
    topics = auto_brain.extract_research_topics(
        "Server: Vercel\nNext.js running\n", framework_aware=True
    )
    # Up to 3 topics total; expect both a Next.js attack-surface topic
    # and a paired Next.js HackerOne query.
    joined = " | ".join(topics)
    assert "Next.js" in joined
    assert "HackerOne disclosed reports" in joined
    assert "Next.js" in [t for t in topics if "HackerOne" in t][0]


def test_framework_aware_off_yields_only_generic():
    topics = auto_brain.extract_research_topics(
        "Server: Vercel\nNext.js running\n", framework_aware=False
    )
    # No paired H1 query.
    for t in topics:
        assert "HackerOne disclosed reports" not in t


def test_paired_topic_uses_correct_framework_name():
    """The H1 paired query must name the framework, not just say 'tech stack'."""
    topics = auto_brain.extract_research_topics(
        "POST /graphql request observed", framework_aware=True
    )
    h1 = [t for t in topics if "HackerOne disclosed reports" in t]
    assert len(h1) == 1
    assert "GraphQL" in h1[0]


def test_topic_cap_still_enforced():
    text = (
        "We see Next.js, Vercel, Express, GraphQL, Cloudflare Workers, "
        "WordPress, Spring Boot, Jenkins on this target."
    )
    topics = auto_brain.extract_research_topics(text, framework_aware=True)
    assert len(topics) <= auto_brain.MAX_TOPICS_PER_RESULT


def test_excluded_topics_still_skipped():
    text = "Next.js detected"
    topics = auto_brain.extract_research_topics(
        text,
        framework_aware=True,
        exclude={"next.js attack surface and cves"},
    )
    # Generic Next.js topic excluded; the paired H1 query should still land.
    has_h1 = any("HackerOne disclosed reports" in t for t in topics)
    assert has_h1


def test_no_framework_match_yields_empty():
    topics = auto_brain.extract_research_topics(
        "Some unremarkable text with no tech signals.",
        framework_aware=True,
    )
    assert topics == []
