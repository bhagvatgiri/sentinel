"""Shared state + data loaders for the Streamlit app.

We persist user-chosen paths in ~/.sentinel/ui-config.json so they don't get
re-typed every session. Everything else is read fresh from disk on each
render — there's no app-side database.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


CONFIG_PATH = Path.home() / ".sentinel" / "ui-config.json"


@dataclass
class UIConfig:
    vault_path: str = str(Path.home() / "Obsidian" / "security-vault")
    corpus_dir: str = str(Path.home() / "sentinel-corpus")
    scopes_dir: str = "./engagements"
    runs_dir: str = "./runs"
    # Phase 03 / Plan 03-06 — base dir for per-finding evidence bundles
    # written by sentinel/agent/poc/sandbox.py during the verify-phase-03
    # pipeline phase. The /findings/<run>/<fp> dashboard route resolves
    # `workspaces_dir / <engagement_id> / verification / <fingerprint>/`
    # off this field. Legacy ~/.sentinel/ui-config.json files that pre-date
    # this field continue loading via UIConfig.load's __dataclass_fields__
    # filter (missing key -> default).
    workspaces_dir: str = "workspaces"
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    embed_model: str = "nomic-embed-text"
    project_dir: str = str(Path.cwd())  # for invoking the sentinel CLI

    @classmethod
    def load(cls) -> "UIConfig":
        if CONFIG_PATH.exists():
            try:
                data = json.loads(CONFIG_PATH.read_text())
                # Filter unknown keys so old configs don't break.
                fields = {f for f in cls.__dataclass_fields__}
                return cls(**{k: v for k, v in data.items() if k in fields})
            except (json.JSONDecodeError, TypeError):
                pass
        return cls()

    def save(self) -> None:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(asdict(self), indent=2))


# ---- data loaders ---------------------------------------------------------


def list_runs(runs_dir: str | Path) -> list[dict]:
    """Each run JSON in `runs_dir`. Returns sorted by mtime desc."""
    p = Path(runs_dir).expanduser()
    if not p.is_dir():
        return []
    out = []
    for jf in p.glob("*.json"):
        try:
            data = json.loads(jf.read_text())
            out.append(
                {
                    "path": str(jf),
                    "filename": jf.name,
                    "client": (data.get("scope") or {}).get("client", "?"),
                    "engagement": (data.get("scope") or {}).get("engagement_id", "?"),
                    "scanners": data.get("scanners_run", []),
                    "findings_count": len(data.get("findings", [])),
                    "errors_count": len(data.get("errors", [])),
                    "mtime": datetime.fromtimestamp(jf.stat().st_mtime).isoformat(timespec="seconds"),
                }
            )
        except (json.JSONDecodeError, OSError):
            continue
    return sorted(out, key=lambda r: r["mtime"], reverse=True)


def list_workspaces(workspaces_root: str | Path) -> list[dict]:
    """Every pentest-pipeline workspace under `workspaces_root`.

    Returns one dict per workspace, sorted by mtime desc:
        {name, path, mtime, n_deliverables, completed_phases, last_phase,
         has_event_log, job_id, has_resume_state}

    Used by:
      - `sentinel workspaces` CLI subcommand (terse table)
      - FastAPI `/workspaces` route (cards)
      - Streamlit `9_Workspaces.py` page (cards + actions)
    """
    root = Path(workspaces_root).expanduser()
    if not root.is_dir():
        return []
    out: list[dict] = []
    for ws in sorted(root.iterdir()):
        if not ws.is_dir():
            continue
        completed: list[str] = []
        last_phase = ""
        completed_path = ws / ".completed_phases.json"
        if completed_path.is_file():
            try:
                meta = json.loads(completed_path.read_text())
                completed = list(meta.get("completed", []) or meta.get("phases", []))
                last_phase = meta.get("last_phase") or (completed[-1] if completed else "")
            except (json.JSONDecodeError, OSError):
                completed = []
        deliv = ws / "deliverables"
        n_deliv = len(list(deliv.glob("*.md"))) if deliv.is_dir() else 0
        # Locate matching event log (runs/events-<job_id>.jsonl with workspace name in head).
        job_id = ""
        has_log = False
        runs_dir = root.parent / "runs"
        if runs_dir.is_dir():
            for log_path in runs_dir.glob("events-*.jsonl"):
                try:
                    head = log_path.read_text(errors="replace")[:4096]
                except OSError:
                    continue
                if ws.name in head or ws.name in log_path.name:
                    has_log = True
                    job_id = log_path.stem.replace("events-", "")
                    break
        out.append({
            "name": ws.name,
            "path": str(ws),
            "mtime": datetime.fromtimestamp(ws.stat().st_mtime).isoformat(timespec="seconds"),
            "n_deliverables": n_deliv,
            "completed_phases": completed,
            "last_phase": last_phase,
            "has_event_log": has_log,
            "job_id": job_id,
            "has_resume_state": completed_path.is_file(),
        })
    return sorted(out, key=lambda w: w["mtime"], reverse=True)


def list_engagements(scopes_dir: str | Path) -> list[dict]:
    """List scope YAMLs in `scopes_dir`."""
    p = Path(scopes_dir).expanduser()
    if not p.is_dir():
        return []
    out = []
    for sf in list(p.glob("*.yaml")) + list(p.glob("*.yml")):
        try:
            import yaml
            data = yaml.safe_load(sf.read_text()) or {}
            out.append(
                {
                    "path": str(sf),
                    "filename": sf.name,
                    "client": data.get("client", "?"),
                    "engagement_id": data.get("engagement_id", "?"),
                    "valid_from": str(data.get("valid_from", "?")),
                    "valid_until": str(data.get("valid_until", "?")),
                    "authorized_by": data.get("authorized_by", "?"),
                }
            )
        except Exception:
            continue
    return sorted(out, key=lambda e: e["filename"])


def list_audit_logs(scopes_dir: str | Path) -> list[dict]:
    """Find .audit-*.jsonl files near the scope files (default location)."""
    p = Path(scopes_dir).expanduser()
    if not p.is_dir():
        return []
    out = []
    for jf in list(p.glob(".audit-*.jsonl")) + list(p.parent.glob(".audit-*.jsonl")):
        try:
            from sentinel.core.scope import AuditLog
            ok, err = AuditLog.verify(jf)
            line_count = sum(1 for _ in jf.open() if _.strip())
            out.append({"path": str(jf), "filename": jf.name, "ok": ok, "error": err, "entries": line_count})
        except Exception as e:
            out.append({"path": str(jf), "filename": jf.name, "ok": False, "error": str(e), "entries": 0})
    return out


def vault_knowledge_stats(vault_path: str | Path) -> dict:
    """Per-source counts inside vault/Knowledge/."""
    base = Path(vault_path).expanduser() / "Knowledge"
    if not base.is_dir():
        return {}
    stats = {}
    for sub in sorted(p for p in base.iterdir() if p.is_dir()):
        files = [f for f in sub.glob("*.md") if f.name != "_INDEX.md"]
        if not files:
            continue
        total_size = sum(f.stat().st_size for f in files)
        latest = max((f.stat().st_mtime for f in files), default=0)
        stats[sub.name] = {
            "docs": len(files),
            "size_kb": round(total_size / 1024, 1),
            "last_modified": datetime.fromtimestamp(latest).isoformat(timespec="seconds") if latest else "—",
        }
    return stats


def corpus_chroma_stats(
    corpus_dir: str | Path, ollama_host: str, embed_model: str,
    *, extra_sources: list[str] | tuple[str, ...] = (),
) -> dict:
    """Open the Chroma DB read-only and return per-source chunk counts.

    `extra_sources` lets callers request counts for additional source
    labels the function doesn't know about by default (e.g. dashboard
    asking for the per-engagement `past-engagement-<client>-<id>`
    labels). Each value is queried via `where={"source": label}` and
    included in `per_source` only if at least one chunk matches.
    """
    p = Path(corpus_dir).expanduser()
    if not p.is_dir():
        return {"available": False, "reason": "corpus dir does not exist"}
    try:
        from sentinel.corpus.embedder import OllamaEmbedder
        from sentinel.corpus.store import CorpusStore
    except RuntimeError as e:
        return {"available": False, "reason": str(e)}
    try:
        embedder = OllamaEmbedder(host=ollama_host, model=embed_model)
        store = CorpusStore(p, embedder)
        total = store._collection.count()
        # Per-source counts via metadata: query with where filters. The
        # always-known sources are the seed-corpus ingesters in
        # sentinel/corpus/sources/. extra_sources are caller-supplied —
        # typically past-engagement-* labels derived from the engagements
        # list, since those vary per install.
        per_source = {}
        known = ("owasp", "mitre-cwe", "mitre-attack", "nist", "nvd", "writeups",
                 "hackerone", "books", "payloads-all-the-things")
        for src in known:
            try:
                ids = store._collection.get(where={"source": src}, include=[])
                per_source[src] = len(ids.get("ids") or [])
            except Exception:
                per_source[src] = 0
        for src in extra_sources:
            if src in per_source:
                continue  # don't shadow the known list
            try:
                ids = store._collection.get(where={"source": src}, include=[])
                n = len(ids.get("ids") or [])
                if n > 0:
                    per_source[src] = n
            except Exception:
                pass
        return {
            "available": True,
            "total_chunks": total,
            "per_source": per_source,
            "persist_dir": str(p),
        }
    except Exception as e:
        return {"available": False, "reason": str(e)}


def ollama_status(host: str, model: str) -> dict:
    """Check if Ollama and the chat model are reachable."""
    from sentinel.llm.ollama_client import OllamaClient
    c = OllamaClient(host=host, model=model)
    return {"available": c.is_available(), "host": host, "model": model}


def embedder_status(host: str, embed_model: str) -> dict:
    from sentinel.corpus.embedder import OllamaEmbedder
    e = OllamaEmbedder(host=host, model=embed_model)
    return {"available": e.is_available(), "host": host, "model": embed_model}
