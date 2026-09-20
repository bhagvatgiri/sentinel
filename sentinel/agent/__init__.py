"""Sentinel autonomous agents (Brain-Growth, Pentest, etc.).

Built on `claude-agent-sdk` — the same SDK family that powers Claude Code
itself. Each sub-package defines its own tool registry and prompt; the
`claude-agent-sdk` provides the core loop (LLM → tool call → tool result →
LLM → ...).
"""
