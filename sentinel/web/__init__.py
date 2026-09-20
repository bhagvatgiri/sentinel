"""Sentinel web UI — FastAPI + Jinja2 + HTMX + Tailwind.

Replaces the Streamlit UI (sentinel/ui/) with a real server-rendered web
app. Backend modules under sentinel/core, sentinel/scanners, sentinel/llm,
etc. are imported as-is — no rewrite.

Launch via the CLI:
    sentinel web   # http://localhost:8080
"""
