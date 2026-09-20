"""Teach-mode — turn every finding into a learning brief grounded in the corpus.

Built for the "CEH but rusty after 5 years" operator: every Sentinel finding
gets a plain-English explanation, the relevant OWASP CheatSheet + CWE entry
from the local RAG corpus, step-by-step manual reproduction, and a
"what-a-fix-looks-like" snippet. Runs on local Ollama (free), opt-in via
``sentinel teach-findings`` (standalone) or wired into the scan-autonomous
pipeline behind ``--teach-mode``.

Inputs: a list of ``Finding`` objects (any source — a run.json, the
agent's findings, an old engagement). Outputs: one markdown file per finding
under ``deliverables/teach/<fingerprint>.md`` + a combined ``teach_index.md``.

Design choices:
- LOCAL by default — Ollama + ``mistral-nemo:12b`` for the narrative (the
  model the project uses for narrative writing per CLAUDE.md). Free, no
  Anthropic spend. Operator can swap via ``--ollama-model``.
- RAG-grounded — pulls top corpus chunks per finding's vuln class so the
  brief cites real OWASP/CWE/writeup material, not the model's
  hallucinations. Falls back to a corpus-less brief if no corpus_dir.
- Resilient — never raises; on Ollama-down / corpus-missing it writes a
  short note so the operator knows what failed.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from sentinel.core.findings import Finding

log = logging.getLogger(__name__)


_TEACH_PROMPT = """You are explaining a security finding to a Certified Ethical \
Hacker who has been away from hands-on work for ~5 years. They are technical \
and remember the concepts, but the muscle memory is rusty. Be precise, \
specific, and concrete. Avoid generic prose.

# Finding to explain
- Title:        {title}
- Vuln class:   {vuln_class}
- CWE:          {cwe}
- Severity:     {severity}
- Target:       {target}
- Location:     {location}
- Description (from scanner / agent):
{description}

# Reference material from the Sentinel corpus (OWASP CheatSheets, MITRE CWE, \
bug-bounty writeups)
{rag_snippets}

# Produce a markdown brief with EXACTLY these five sections, in order
## 1. What this is, in one paragraph
Plain English. No marketing. Tell them what the bug actually is.

## 2. Why it's exploitable here
Tie back to the SPECIFIC finding above (the target, the endpoint, the \
description). Not generic theory — explain what's wrong with THIS endpoint.

## 3. Manual reproduction — 3-5 numbered steps
Concrete shell/curl/browser steps the operator can run by hand to re-prove \
the bug. Include the exact request to send.

## 4. What a fix looks like
One code snippet OR config change that would close it. Be specific to the \
class (e.g. for IDOR show the ownership check; for SSRF show URL allowlisting).

## 5. References
Bullet list of links: relevant OWASP CheatSheet URL, the CWE entry URL, and \
1-2 canonical writeups if you saw any in the reference material above.
"""


@dataclass
class TeachBrief:
    finding_fingerprint: str
    title: str
    markdown: str           # the rendered brief
    used_rag: bool          # whether RAG context was actually included
    error: Optional[str] = None


def _retrieve_for_finding(finding: Finding, retriever) -> tuple[str, bool]:
    """Pull top RAG chunks for this finding's class. Returns (snippets_str,
    used_rag). Returns ("", False) if no retriever / retrieval fails."""
    if retriever is None:
        return "", False
    try:
        # Build a focused query: vuln class + CWE + first line of description.
        slug = (finding.scanner or "").split(":", 1)[-1] if ":" in (finding.scanner or "") else ""
        desc_head = (finding.description or "").split("\n", 1)[0][:200]
        q = f"{slug} {finding.cwe or ''} {finding.title}: {desc_head}".strip()
        chunks = retriever.retrieve(q, top_k=4)
    except Exception as e:  # noqa: BLE001
        log.info("teach_mode: retrieval failed: %s", e)
        return "", False
    if not chunks:
        return "", False
    parts: list[str] = []
    for c in chunks:
        # Each chunk: c.text and c.source (depends on Retriever API; both are
        # accessed defensively in case the field name changes).
        text = (getattr(c, "text", None) or getattr(c, "content", None) or "")[:600]
        source = (getattr(c, "source", None) or getattr(c, "uri", None) or "corpus")
        parts.append(f"---\n*Source: `{source}`*\n{text}")
    return "\n\n".join(parts), True


def _ollama_complete(prompt: str, *, host: str, model: str,
                     timeout: float = 120.0) -> tuple[str, Optional[str]]:
    """Single-shot Ollama completion. Returns (text, error). Best-effort —
    never raises; on Ollama-down returns ("", error message)."""
    try:
        import httpx
        with httpx.Client(timeout=timeout) as c:
            r = c.post(f"{host.rstrip('/')}/api/generate",
                       json={"model": model, "prompt": prompt, "stream": False,
                             "options": {"temperature": 0.3}})
            if r.status_code != 200:
                return "", f"ollama {r.status_code}: {r.text[:200]}"
            return ((r.json() or {}).get("response") or "").strip(), None
    except Exception as e:  # noqa: BLE001
        return "", f"ollama call failed: {type(e).__name__}: {e}"


def generate_teach_brief(finding: Finding, *,
                          retriever=None,
                          ollama_host: str = "http://localhost:11434",
                          ollama_model: str = "mistral-nemo:12b",
                          ) -> TeachBrief:
    """Build a teach-mode brief for one finding. Best-effort: degrades
    cleanly when RAG / Ollama are unavailable so a partial result still ships."""
    fp = finding.fingerprint()
    rag, used = _retrieve_for_finding(finding, retriever)
    rag_block = rag if rag else ("*(no corpus snippets retrieved — Sentinel's "
                                  "RAG store may be unconfigured or empty. The "
                                  "brief below is from the model alone.)*")
    vuln_class = (finding.scanner or "").split(":", 1)[-1] if ":" in (finding.scanner or "") else (finding.scanner or "")
    prompt = _TEACH_PROMPT.format(
        title=finding.title,
        vuln_class=vuln_class or "(unknown)",
        cwe=finding.cwe or "(unknown)",
        severity=(finding.severity.value if hasattr(finding.severity, "value")
                  else finding.severity),
        target=finding.target,
        location=finding.location or "(unspecified)",
        description=(finding.description or "(none)")[:800],
        rag_snippets=rag_block,
    )
    text, err = _ollama_complete(prompt, host=ollama_host, model=ollama_model)
    if err:
        # Build a minimal fallback brief from the metadata so we ALWAYS write
        # something — the operator can come back when Ollama is up.
        text = (f"# {finding.title}\n\n"
                f"*Teach-mode generation failed: {err}*\n\n"
                f"- Class: {vuln_class}\n- CWE: {finding.cwe or '?'}\n"
                f"- Target: {finding.target}\n- Location: {finding.location or '?'}\n\n"
                f"## Description\n{finding.description or '(none)'}\n\n"
                f"## Retry\nStart Ollama and re-run: "
                f"`sentinel teach-findings <findings.json>`")
        return TeachBrief(fp, finding.title, text, used_rag=used, error=err)
    md = (f"# Teach-mode — {finding.title}\n\n"
          f"*Auto-generated by Sentinel teach-mode.* "
          f"({'RAG-grounded' if used else 'no RAG context'})\n\n"
          f"{text}")
    return TeachBrief(fp, finding.title, md, used_rag=used, error=None)


def write_teach_briefs(findings: Iterable[Finding], workspace: Path, *,
                        retriever=None, ollama_host: str = "http://localhost:11434",
                        ollama_model: str = "mistral-nemo:12b",
                        ) -> dict[str, Any]:
    """Generate + write teach briefs for every finding. Returns a summary dict
    with counts + per-finding paths + any errors."""
    teach_dir = workspace / "deliverables" / "teach"
    teach_dir.mkdir(parents=True, exist_ok=True)
    briefs: list[TeachBrief] = []
    paths: list[str] = []
    errors: list[str] = []
    for f in findings:
        b = generate_teach_brief(f, retriever=retriever,
                                  ollama_host=ollama_host,
                                  ollama_model=ollama_model)
        out = teach_dir / f"{b.finding_fingerprint}.md"
        try:
            out.write_text(b.markdown)
            paths.append(str(out))
        except Exception as e:  # noqa: BLE001
            errors.append(f"{b.finding_fingerprint}: write failed: {e}")
            continue
        if b.error:
            errors.append(f"{b.finding_fingerprint}: {b.error}")
        briefs.append(b)

    # Combined index.
    idx = teach_dir / "teach_index.md"
    idx_lines = ["# Teach-mode Index\n",
                 f"*{len(briefs)} findings explained "
                 f"({sum(1 for b in briefs if b.used_rag)} with RAG-grounded "
                 f"context).*\n",
                 "| Fingerprint | Title | RAG | Brief |",
                 "|---|---|---|---|"]
    for b in briefs:
        idx_lines.append(f"| `{b.finding_fingerprint}` | {b.title} | "
                          f"{'' if b.used_rag else '–'} | "
                          f"[`teach/{b.finding_fingerprint}.md`]"
                          f"(./teach/{b.finding_fingerprint}.md) |")
    try:
        idx.write_text("\n".join(idx_lines))
    except Exception as e:  # noqa: BLE001
        errors.append(f"index write failed: {e}")
    return {
        "count": len(briefs),
        "with_rag": sum(1 for b in briefs if b.used_rag),
        "errors": errors,
        "index": str(idx),
        "paths": paths,
    }
