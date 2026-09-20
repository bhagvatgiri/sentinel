"""Sentinel reporting surface — renderers + PoC-step plumbing.

Phase 4 (Manual PoC Reproduction in Reports) populates this package's
public re-exports. Plans 04-02 (markdown), 04-03 (PDF), 04-04 (Obsidian),
and 04-05 (dashboard route) all import the Phase 4 contract via:

    from sentinel.reporting import PocStep, generate_poc_steps

Plan 04-01 establishes the first two re-exports below. Subsequent plans
APPEND additional re-exports (render_poc_section, etc.) — they do not
modify these.

Plan 04-02 appends `render_poc_section` (H1-narrative Markdown renderer)
below the 04-01 imports. Plans 04-03 (PDF), 04-04 (Obsidian), and 04-05
(dashboard route) will append further symbols in the same APPEND-only
pattern.
"""

from sentinel.reporting.poc_steps import PocStep, generate_poc_steps
from sentinel.reporting.poc_markdown import render_poc_section

__all__ = [
    "PocStep",
    "generate_poc_steps",
    "render_poc_section",
]
