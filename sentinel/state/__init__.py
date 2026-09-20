"""Session-continuity helpers — `CURRENT_STATE.md` snapshot synthesis."""

from sentinel.state.current_state import (
    build_snapshot,
    render_markdown,
    update_current_state,
    update_current_state_safe,
    update_current_state_with_status,
)

__all__ = [
    "build_snapshot",
    "render_markdown",
    "update_current_state",
    "update_current_state_safe",
    "update_current_state_with_status",
]
