"""FastAPI dependency providers — config, etc."""

from __future__ import annotations

from sentinel.ui.state import UIConfig


def get_config() -> UIConfig:
    """Reload from ~/.sentinel/ui-config.json on every request.

    Cheap (small JSON) and avoids stale config when the user edits the file
    in another tab / via the Tools page.
    """
    return UIConfig.load()
