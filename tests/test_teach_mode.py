"""Tests for teach-mode (2026-XX-XX).

The contract that matters for your-CEH-rebuilding-skills use case:
- A brief is ALWAYS written, even when Ollama is down or no corpus exists
  (operator can come back later — never lose a finding to infra hiccup).
- When RAG works, the corpus snippets DO get injected into the prompt.
- The output markdown follows the 5-section structure expected by readers.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sentinel.agent import teach_mode as tm
from sentinel.core.findings import Finding, Severity


def _f(scanner="vuln:idor", title="IDOR on /api/users/{id}",
       desc="numeric id with no per-user check", cwe="CWE-639") -> Finding:
    return Finding(title=title, description=desc, severity=Severity.HIGH,
                   scanner=scanner, target="http://target.example",
                   location="/api/users/1", cwe=cwe)


def test_brief_always_written_even_when_ollama_down(tmp_path, monkeypatch):
    """Ollama unreachable → fallback brief with metadata is still written."""
    monkeypatch.setattr(tm, "_ollama_complete",
                        lambda *a, **kw: ("", "ollama unreachable"))
    b = tm.generate_teach_brief(_f())
    assert b.error and "ollama" in b.error.lower()
    assert b.title.startswith("IDOR")
    assert "Teach-mode generation failed" in b.markdown
    assert "Retry" in b.markdown  # operator hint


def test_brief_with_ollama_includes_prompt_sections(tmp_path, monkeypatch):
    """When Ollama responds, the wrapper markdown carries the title +
    flags whether RAG was used."""
    monkeypatch.setattr(tm, "_ollama_complete",
                        lambda *a, **kw: ("## 1. What this is\n…", None))
    b = tm.generate_teach_brief(_f())
    assert b.error is None
    assert b.markdown.startswith("# Teach-mode — IDOR on /api/users/{id}")
    assert "no RAG context" in b.markdown
    assert "## 1. What this is" in b.markdown


def test_brief_with_rag_marks_rag_grounded(tmp_path, monkeypatch):
    """When a retriever returns chunks, the brief flags RAG-grounded AND the
    chunks make it into the model prompt."""
    fake_chunks = [
        SimpleNamespace(text="OWASP BOLA cheatsheet: enforce ownership ...",
                        source="owasp/BOLA.md"),
        SimpleNamespace(text="CWE-639: Authorization Bypass through ...",
                        source="mitre-cwe/CWE-639.md"),
    ]
    fake_retriever = SimpleNamespace(retrieve=lambda q, top_k: fake_chunks)
    captured_prompt = {}
    def fake_complete(prompt, *, host, model, timeout=120.0):
        captured_prompt["p"] = prompt
        return "## 1. What this is\nBOLA explanation", None
    monkeypatch.setattr(tm, "_ollama_complete", fake_complete)
    b = tm.generate_teach_brief(_f(), retriever=fake_retriever)
    assert b.used_rag is True
    assert "RAG-grounded" in b.markdown
    assert "BOLA cheatsheet" in captured_prompt["p"]
    assert "CWE-639" in captured_prompt["p"]


def test_retriever_error_degrades_to_no_rag(monkeypatch):
    """A broken retriever shouldn't crash the brief — falls back to no-RAG."""
    bad = SimpleNamespace(retrieve=lambda q, top_k: (_ for _ in ()).throw(
        RuntimeError("chroma down")))
    monkeypatch.setattr(tm, "_ollama_complete",
                        lambda *a, **kw: ("## 1. ok", None))
    b = tm.generate_teach_brief(_f(), retriever=bad)
    assert b.used_rag is False
    assert b.error is None
    assert "no RAG context" in b.markdown


def test_write_teach_briefs_creates_per_finding_files_and_index(tmp_path, monkeypatch):
    """write_teach_briefs writes <fingerprint>.md per finding + an index."""
    monkeypatch.setattr(tm, "_ollama_complete",
                        lambda *a, **kw: ("## 1. ok\n## 2. ok\n## 3. ok", None))
    findings = [_f(), _f(scanner="vuln:ssrf", title="SSRF in /redirect",
                          desc="follows arbitrary URL", cwe="CWE-918")]
    summary = tm.write_teach_briefs(findings, tmp_path)
    assert summary["count"] == 2
    teach_dir = tmp_path / "deliverables" / "teach"
    md_files = sorted(teach_dir.glob("*.md"))
    # one per-finding + the index
    assert len(md_files) == 3
    idx = teach_dir / "teach_index.md"
    assert idx.exists()
    idx_text = idx.read_text()
    assert "Teach-mode Index" in idx_text
    assert "IDOR" in idx_text and "SSRF" in idx_text


def test_write_teach_briefs_continues_after_per_finding_failure(tmp_path, monkeypatch):
    """If Ollama fails on one finding, the others still ship."""
    calls = {"n": 0}
    def flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return "", "ollama down"   # first finding fails
        return "## 1. ok", None        # second succeeds
    monkeypatch.setattr(tm, "_ollama_complete", flaky)
    summary = tm.write_teach_briefs([_f(), _f(title="other", desc="d2")], tmp_path)
    assert summary["count"] == 2  # both written (one is the fallback)
    assert any("ollama" in e for e in summary["errors"])
