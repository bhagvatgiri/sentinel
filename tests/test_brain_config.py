"""BrainConfig backend default + CLI override — Phase 102/103."""

from __future__ import annotations

from sentinel.agent.brain.loop import BrainConfig


def test_default_backend_is_ollama():
    cfg = BrainConfig(topic="x", corpus_dir="/tmp/x")
    assert cfg.backend == "ollama"
    assert cfg.ollama_brain_model == "llama3.1:8b"
    assert cfg.ollama_max_turns == 30


def test_can_override_to_claude():
    cfg = BrainConfig(topic="x", corpus_dir="/tmp/x", backend="claude")
    assert cfg.backend == "claude"


def test_can_override_ollama_model():
    cfg = BrainConfig(topic="x", corpus_dir="/tmp/x",
                      ollama_brain_model="mistral-nemo:12b")
    assert cfg.ollama_brain_model == "mistral-nemo:12b"


def test_cli_brain_grow_default_backend_is_ollama():
    """Confirm the CLI argparser keeps the default."""
    from sentinel.cli import _build_parser
    p = _build_parser()
    args = p.parse_args(["brain-grow", "--topic", "x", "--corpus-dir", "/tmp/x"])
    assert args.brain_backend == "ollama"
    assert args.ollama_brain_model == "llama3.1:8b"


def test_cli_brain_backend_override():
    from sentinel.cli import _build_parser
    p = _build_parser()
    args = p.parse_args([
        "brain-grow", "--topic", "x", "--corpus-dir", "/tmp/x",
        "--brain-backend", "claude",
    ])
    assert args.brain_backend == "claude"


def test_brain_queue_defaults_to_ollama_backend():
    from sentinel.agent.brain_queue import BrainQueue
    q = BrainQueue(corpus_dir="/tmp/x")
    assert q.backend == "ollama"
    assert q.ollama_brain_model == "llama3.1:8b"


def test_ollama_system_prompt_is_imperative():
    """Local models stop after planning if the prompt asks them to plan.
    The Ollama prompt must be tool-call-first."""
    from sentinel.agent.brain.prompt import OLLAMA_SYSTEM_PROMPT, SYSTEM_PROMPT
    assert OLLAMA_SYSTEM_PROMPT != SYSTEM_PROMPT
    p = OLLAMA_SYSTEM_PROMPT.lower()
    # Anti-narration + imperative signals.
    assert "do not chat" in p or "do not plan" in p
    assert "call web_search" in p or "call a tool" in p
    # Must NOT ask for a plan first.
    assert "begin by planning" not in p


def test_ollama_system_prompt_renders_with_required_placeholders():
    from sentinel.agent.brain.prompt import OLLAMA_SYSTEM_PROMPT
    rendered = OLLAMA_SYSTEM_PROMPT.format(
        topic="GraphQL introspection production CVE 2024",
        depth=2,
        max_pages=5,
    )
    assert "GraphQL introspection" in rendered
    # max_pages should appear in the rendered prompt as a stop condition.
    assert "5" in rendered
