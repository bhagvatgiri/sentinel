"""Tests for select_ollama_prompt — closes Task #61.

The runtime selects between OLLAMA_SYSTEM_PROMPT (default) and
OLLAMA_SYSTEM_PROMPT_MISTRAL (the tighter variant for mistral-nemo)
based on the configured brain model.
"""

from __future__ import annotations

import pytest

from sentinel.agent.brain.prompt import (
    OLLAMA_SYSTEM_PROMPT,
    OLLAMA_SYSTEM_PROMPT_MISTRAL,
    select_ollama_prompt,
)


@pytest.mark.parametrize("model", [
    "mistral-nemo:12b",
    "mistral-nemo:latest",
    "MISTRAL-NEMO:12b",        # case insensitive
    "mistral:nemo",            # alt namespacing
])
def test_mistral_models_get_mistral_prompt(model):
    p = select_ollama_prompt(model)
    assert p is OLLAMA_SYSTEM_PROMPT_MISTRAL
    # The imperative variant explicitly forbids narration markers
    assert "NEVER narrate" in p
    assert "→ NEXT ACTION" in p


@pytest.mark.parametrize("model", [
    "llama3.1:8b",     # the actual brain-grow default
    "llama3.2:3b",
    "qwen2.5-coder:7b",
    "deepseek-r1:8b",
    "gemma2:9b",
    "",                # empty string falls through to default
])
def test_non_mistral_models_get_default_prompt(model):
    p = select_ollama_prompt(model)
    assert p is OLLAMA_SYSTEM_PROMPT
    # Default prompt has its own structure
    assert "automated research bot" in p
    # Default prompt does NOT have the "→ NEXT ACTION" cue (mistral-only)
    assert "→ NEXT ACTION" not in p


def test_mistral_prompt_can_format_with_topic_kwargs():
    """The variant must accept the same {topic}/{depth}/{max_pages} placeholders
    so loop.py can call .format() the same way for either variant."""
    rendered = OLLAMA_SYSTEM_PROMPT_MISTRAL.format(
        topic="SSRF bypass techniques",
        depth=2,
        max_pages=10,
    )
    assert "SSRF bypass techniques" in rendered
    assert "10" in rendered  # max_pages substituted somewhere
