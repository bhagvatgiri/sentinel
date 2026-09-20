"""Shared UI config + data loaders (formerly the Streamlit package).

The Streamlit dashboard was removed 2026-XX-XX in favor of the FastAPI/HTMX
dashboard under sentinel/web/. What survives here is `state.py` — the
`UIConfig` dataclass and the data-loader helpers that BOTH the CLI and the
web routes import. There is no longer a `sentinel ui` subcommand or any
streamlit dependency.
"""
