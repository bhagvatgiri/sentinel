"""Schema converter for the Ollama brain loop — Phase 100/101.

Verifies that every brain @tool's metadata round-trips into a valid
OpenAI-style function definition Ollama's /api/chat will accept.
"""

from __future__ import annotations

from sentinel.agent.brain import tools as brain_tools
from sentinel.agent.brain.ollama_loop import (
    _PYTYPE_TO_JSON, _tool_to_json_schema, build_tools_payload,
)


def test_pytype_map_covers_brain_tool_types():
    """Every type used by a brain tool's input_schema must map to JSON-Schema."""
    used: set[type] = set()
    for t in brain_tools.ALL_TOOLS:
        for ty in (t.input_schema or {}).values():
            used.add(ty)
    missing = used - set(_PYTYPE_TO_JSON.keys())
    assert not missing, f"unmapped Python types: {missing}"


def test_single_tool_round_trip():
    schema = _tool_to_json_schema(brain_tools.web_search)
    assert schema["type"] == "function"
    fn = schema["function"]
    assert fn["name"] == "web_search"
    assert "DuckDuckGo" in fn["description"]
    assert fn["parameters"]["type"] == "object"
    assert "query" in fn["parameters"]["properties"]
    assert fn["parameters"]["properties"]["query"]["type"] == "string"
    assert fn["parameters"]["properties"]["max_results"]["type"] == "integer"
    assert "query" in fn["parameters"]["required"]
    assert "max_results" in fn["parameters"]["required"]


def test_build_payload_returns_one_per_tool():
    payload = build_tools_payload(brain_tools.ALL_TOOLS)
    assert len(payload) == len(brain_tools.ALL_TOOLS)
    names = [p["function"]["name"] for p in payload]
    expected = {t.name for t in brain_tools.ALL_TOOLS}
    assert set(names) == expected


def test_every_tool_has_description():
    for p in build_tools_payload(brain_tools.ALL_TOOLS):
        desc = p["function"]["description"]
        assert desc and len(desc) > 20, (
            f"tool {p['function']['name']} has too-short description"
        )


def test_payload_serializes_as_json():
    """Ollama wants JSON. Make sure our payload survives a round trip."""
    import json
    payload = build_tools_payload(brain_tools.ALL_TOOLS)
    s = json.dumps(payload)
    parsed = json.loads(s)
    assert parsed == payload


# ---- inline-tool-call fallback parser ------------------------------------


def test_inline_parser_recognizes_name_arguments_shape():
    """qwen2.5-coder:7b emits {"name": "search", "arguments": {...}} in content."""
    from sentinel.agent.brain.ollama_loop import _parse_inline_tool_call
    out = _parse_inline_tool_call(
        '{"name": "web_search", "arguments": {"query": "x", "max_results": 3}}',
        {"web_search", "fetch_url"},
    )
    assert out is not None
    assert out[0]["function"]["name"] == "web_search"
    assert out[0]["function"]["arguments"] == {"query": "x", "max_results": 3}


def test_inline_parser_recognizes_tool_args_shape():
    from sentinel.agent.brain.ollama_loop import _parse_inline_tool_call
    out = _parse_inline_tool_call(
        '{"tool": "fetch_url", "args": {"url": "https://x"}}',
        {"web_search", "fetch_url"},
    )
    assert out is not None
    assert out[0]["function"]["name"] == "fetch_url"


def test_inline_parser_strips_markdown_fences():
    from sentinel.agent.brain.ollama_loop import _parse_inline_tool_call
    out = _parse_inline_tool_call(
        '```json\n{"name": "web_search", "arguments": {"query": "x"}}\n```',
        {"web_search"},
    )
    assert out is not None


def test_inline_parser_rejects_unknown_tool():
    from sentinel.agent.brain.ollama_loop import _parse_inline_tool_call
    out = _parse_inline_tool_call(
        '{"name": "made_up_tool", "arguments": {}}',
        {"web_search"},
    )
    assert out is None


def test_inline_parser_returns_none_for_plain_text():
    from sentinel.agent.brain.ollama_loop import _parse_inline_tool_call
    assert _parse_inline_tool_call("Hello, just chatting.", {"web_search"}) is None


def test_inline_parser_strips_tool_response_wrapper():
    """qwen2.5-coder:7b sometimes wraps its inline JSON in
    <tool_response>...</tool_response> tags (mimicking training data)."""
    from sentinel.agent.brain.ollama_loop import _parse_inline_tool_call
    out = _parse_inline_tool_call(
        '<tool_response>\n{"name": "web_search", "arguments": {"query": "x"}}\n</tool_response>',
        {"web_search"},
    )
    assert out is not None
    assert out[0]["function"]["name"] == "web_search"


def test_inline_parser_recognizes_parameters_synonym():
    """Some llama3.1:8b runs emit {"name": "ingest_text", "parameters": {...}}
    instead of "arguments" (seen at turn 12 of the postfix Web Cache Deception
    run, runs/brain-grow-20260505-143127.jsonl)."""
    from sentinel.agent.brain.ollama_loop import _parse_inline_tool_call
    out = _parse_inline_tool_call(
        '{"name": "ingest_text", "parameters": {"url": "https://x", "title": "T", "tags": ["a"]}}',
        {"ingest_text"},
    )
    assert out is not None
    assert out[0]["function"]["name"] == "ingest_text"
    assert out[0]["function"]["arguments"]["url"] == "https://x"


def test_inline_parser_synthesizes_fetch_url_from_narration():
    """qwen2.5-coder:7b's actual Run B failure mode: narrates the URL
    selection in prose instead of calling fetch_url. Synthesize a
    fetch_url call from the first URL it named so the loop continues."""
    from sentinel.agent.brain.ollama_loop import _parse_inline_tool_call
    out = _parse_inline_tool_call(
        "<tool_response>\nSelected URL for fetching: https://dev.to/foo/bar\n</tool_response>",
        {"web_search", "fetch_url"},
    )
    assert out is not None
    assert out[0]["function"]["name"] == "fetch_url"
    assert out[0]["function"]["arguments"]["url"] == "https://dev.to/foo/bar"


def test_inline_parser_synthesis_skipped_if_fetch_url_not_allowed():
    """If fetch_url isn't in the allowed tool set, don't synthesize."""
    from sentinel.agent.brain.ollama_loop import _parse_inline_tool_call
    out = _parse_inline_tool_call(
        "Selected URL: https://example.com/x",
        {"web_search"},
    )
    assert out is None


def test_inline_parser_strips_qwen_im_start_chat_template():
    """qwen2.5-coder:7b leaks its assistant-turn chat template token
    (<|im_start|>) ahead of valid JSON in the content field. The parser
    must strip it so the JSON tool call is recognized.

    Reproduces runs/brain-cmp-qwen-postfix.log:turn 4."""
    from sentinel.agent.brain.ollama_loop import _parse_inline_tool_call
    out = _parse_inline_tool_call(
        '<|im_start|>\n{"name": "fetch_url", "arguments": {"url": "https://medium.com/@x/y"}}',
        {"web_search", "fetch_url"},
    )
    assert out is not None
    assert out[0]["function"]["name"] == "fetch_url"
    assert out[0]["function"]["arguments"]["url"] == "https://medium.com/@x/y"


def test_inline_parser_strips_chat_template_then_unwraps_tool_response():
    """Layered case: <|im_start|> + <tool_response> wrapper + JSON.
    Locks in the strip-then-unwrap order — chat-template tokens must
    come off first or the wrapper regex won't match."""
    from sentinel.agent.brain.ollama_loop import _parse_inline_tool_call
    out = _parse_inline_tool_call(
        '<|im_start|>\n<tool_response>\n{"name": "web_search", "arguments": {"query": "x"}}\n</tool_response>',
        {"web_search"},
    )
    assert out is not None
    assert out[0]["function"]["name"] == "web_search"
    assert _parse_inline_tool_call("", {"web_search"}) is None
    assert _parse_inline_tool_call("not json {malformed", {"web_search"}) is None
