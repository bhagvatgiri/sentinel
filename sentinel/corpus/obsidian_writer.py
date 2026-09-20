"""Write ingested docs into the user's Obsidian vault as markdown notes.

Layout inside the vault:

    Knowledge/
        owasp/
        mitre-cwe/
        mitre-attack/
        nist/
        nvd/
        writeups/
        books/

Each note has YAML frontmatter so Obsidian's Dataview / tag searches work.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from sentinel.corpus.document import Document


_SLUG_RE = re.compile(r"[^a-z0-9]+")
_FORBIDDEN_FS = re.compile(r"[<>:\"/\\|?*\x00-\x1f]")

# Identifier patterns for cross-reference wikilinks. Matches in body text are
# rewritten to [[target_stem|CWE-79]] form when the lookup has the target.
_CWE_RE = re.compile(r"\bCWE[\s-]?(\d{1,5})\b", re.IGNORECASE)
_CVE_RE = re.compile(r"\bCVE[\s-](\d{4})[\s-](\d{4,8})\b", re.IGNORECASE)
_ATTACK_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
# group(1) = document number (e.g. 53), group(2) = optional revision number (e.g. 5 in "r5")
_NIST_SP_RE = re.compile(r"\bSP[\s-]?800[\s-]?(\d{1,3})(?:[\s-]?r(\d+))?\b", re.IGNORECASE)
# TODO: tighten to A\d{2} when 2017-era OWASP corpus (single-digit codes like A1–A10) is known
# not to be ingested. Today only zero-padded 2021-era codes land in the lookup, so single-digit
# regex matches like "A1" silently miss the lookup; if 2017 corpus is later added, this would
# produce false-positive links on incidental text like "Figure A1" / "Appendix A2".
# group(1) = the bare code "A01"; the optional ":YYYY" suffix is stripped at link-display time
_OWASP_TOP10_RE = re.compile(r"\b(A\d{1,2})(?::\d{4})?\b")
# Protect regions where we must NOT inject wikilinks.
_CODEBLOCK_RE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
_WIKILINK_RE = re.compile(r"\[\[[^\]]+\]\]")
_MD_LINK_RE = re.compile(r"\[[^\]]+\]\([^\)]+\)")
_AUTOLINK_RE = re.compile(r"<https?://[^>]+>")

# Curated vulnerability-class synonyms mapped to CWE IDs.
# These phrases appear constantly in CVE bodies but rarely as the parenthetical
# alias in CWE titles. Linking them to the authoritative CWE note creates
# high-density edges in the knowledge graph.
#
# Curated empirically from NVD body-text scans. Each entry is a phrase (lowercase,
# normalized) → the CWE ID it should resolve to. The lookup builder converts each
# entry to a name_lookup[phrase] = cwe_stem mapping at runtime.
VULN_CLASS_SYNONYMS: dict[str, int] = {
    # Memory safety (high-frequency CVE descriptions)
    "buffer overflow": 120,
    "stack-based buffer overflow": 121,
    "heap-based buffer overflow": 122,
    "heap buffer overflow": 122,
    "stack buffer overflow": 121,
    "use after free": 416,
    "use-after-free": 416,
    "double free": 415,
    "null pointer dereference": 476,
    "null-pointer dereference": 476,
    "out-of-bounds read": 125,
    "out of bounds read": 125,
    "out-of-bounds write": 787,
    "out of bounds write": 787,
    "integer overflow": 190,
    "integer underflow": 191,
    "type confusion": 843,
    "uninitialized memory": 908,
    "memory corruption": 119,

    # Injection / parsing
    "command injection": 78,
    "os command injection": 78,
    "ldap injection": 90,
    "xpath injection": 643,
    "xml external entity": 611,
    "xml external entities": 611,
    "expression language injection": 917,
    "server-side template injection": 1336,
    "template injection": 1336,
    "deserialization of untrusted data": 502,
    "insecure deserialization": 502,
    "format string vulnerability": 134,
    "format string": 134,
    "code injection": 94,
    "remote code execution": 94,
    "arbitrary code execution": 94,
    "header injection": 93,
    "log injection": 117,

    # Web-app classes
    "directory traversal": 22,
    "path traversal": 22,
    "open redirect": 601,
    "url redirection": 601,
    "prototype pollution": 1321,
    "clickjacking": 1021,
    "session fixation": 384,

    # Crypto / auth / authz
    "weak cryptography": 327,
    "weak hashing": 328,
    "hardcoded credentials": 798,
    "hardcoded password": 259,
    "improper certificate validation": 295,
    "missing authentication": 306,
    "broken authentication": 287,
    "broken access control": 284,
    "privilege escalation": 269,
    "missing authorization": 862,

    # Race / concurrency
    "race condition": 362,
    "toctou": 367,
    "time-of-check to time-of-use": 367,

    # DoS / resource
    "denial of service": 400,
    "uncontrolled resource consumption": 400,
    "infinite loop": 835,
    "stack exhaustion": 674,

    # Info disclosure
    "information disclosure": 200,
    "sensitive data exposure": 200,
    "information exposure": 200,
}


def _slug(s: str, max_len: int = 80) -> str:
    s = _SLUG_RE.sub("-", s.lower()).strip("-")
    return s[:max_len] or "untitled"


def _safe_filename(s: str, max_len: int = 120) -> str:
    s = _FORBIDDEN_FS.sub("-", s).strip()
    return (s[:max_len] or "untitled") + ".md"


class ObsidianCorpusWriter:
    def __init__(self, vault_path: str | Path):
        self.vault_path = Path(vault_path).expanduser().resolve()

    def write_documents(self, source: str, docs: Iterable[Document]) -> int:
        base = self.vault_path / "Knowledge" / _slug(source)
        base.mkdir(parents=True, exist_ok=True)
        # Materialize once: we need to know the filename of every doc in this
        # batch BEFORE rendering so cross-refs within the batch resolve.
        docs = list(docs)
        # Build identifier -> filename_stem lookup spanning everything already
        # written to the vault PLUS the docs we're about to write. This makes
        # cross-source links work (e.g. an NVD note can [[link]] to a CWE note
        # written in a previous ingest).
        new_stems: dict[str, str] = {}
        for d in docs:
            stem = _safe_filename(f"{_slug(d.title, 60)}-{d.id.split(':')[-1][:8]}")[:-3]
            for key in _identifiers_for_doc(d):
                new_stems.setdefault(key, stem)
        lookup = _scan_existing_lookup(self.vault_path / "Knowledge")
        for k, v in new_stems.items():
            lookup.setdefault(k, v)
        count = 0
        for d in docs:
            stem = _safe_filename(f"{_slug(d.title, 60)}-{d.id.split(':')[-1][:8]}")[:-3]
            (base / f"{stem}.md").write_text(self._render(d, lookup, stem))
            count += 1
        # Index file (overwritten each run for this source).
        (base / "_INDEX.md").write_text(self._render_index(source, base))
        return count

    def _render(self, d: Document, lookup: dict[str, str] | None = None, self_stem: str = "") -> str:
        tags = " ".join(f"#{_slug(t)}" for t in d.tags) if d.tags else ""
        meta_lines = []
        for k, v in d.metadata.items():
            if isinstance(v, (list, tuple)):
                meta_lines.append(f"{k}: [{', '.join(str(x) for x in v)}]")
            elif v is None:
                continue
            else:
                meta_lines.append(f"{k}: {_yaml_escape(v)}")
        meta_block = "\n".join(meta_lines)

        fm = (
            "---\n"
            f"title: {_yaml_escape(d.title)}\n"
            f"source: {d.source}\n"
            f"id: {d.id}\n"
            f"url: {_yaml_escape(d.url or '')}\n"
            f"tags: [knowledge, source/{_slug(d.source)}{', ' + ', '.join(_slug(t) for t in d.tags) if d.tags else ''}]\n"
            f"{meta_block}\n"
            "---\n\n"
        )
        body = f"# {d.title}\n\n"
        if d.url:
            body += f"Source: <{d.url}>\n\n"
        if tags:
            body += tags + "\n\n"
        body += d.text
        if lookup:
            body = _inject_wikilinks(body, lookup, self_stem)
        return fm + body

    def _render_index(self, source: str, base: Path) -> str:
        files = sorted(p.name for p in base.glob("*.md") if p.name != "_INDEX.md")
        lines = [f"# {source} — index", "", f"{len(files)} documents.", ""]
        for fname in files:
            lines.append(f"- [[{fname[:-3]}]]")
        return "\n".join(lines) + "\n"


def _yaml_escape(v) -> str:
    s = str(v).replace("\n", " ").replace('"', "'")
    if any(c in s for c in [":", "#", "[", "]", "{", "}", "&", "*", ">", "|"]) or s.startswith(("- ", "? ")):
        return f'"{s}"'
    return s


# ---- wikilink cross-reference helpers ---------------------------------------


def _identifiers_for_doc(d: "Document") -> list[str]:
    """Canonical identifiers for a doc, used as lookup keys."""
    out = []
    md = d.metadata or {}
    if md.get("cwe_id"):
        try:
            out.append(f"CWE-{int(md['cwe_id'])}")
        except (TypeError, ValueError):
            pass
    if md.get("cve_id"):
        cve = str(md["cve_id"]).strip().upper()
        m = re.match(r"CVE[-\s](\d{4})[-\s](\d+)", cve)
        if m:
            out.append(f"CVE-{m.group(1)}-{int(m.group(2)):04d}")
    if md.get("attack_id"):
        t = str(md["attack_id"]).strip().upper()
        if re.match(r"T\d{4}(\.\d{3})?$", t):
            out.append(t)
    return out


def _scan_existing_lookup(knowledge_dir: Path) -> dict[str, str]:
    """Build identifier -> filename_stem from existing notes already in vault.

    Only reads frontmatter (cheap). Skips _INDEX.md files. Tolerates missing dirs.
    """
    lookup: dict[str, str] = {}
    if not knowledge_dir.is_dir():
        return lookup
    for p in knowledge_dir.rglob("*.md"):
        if p.name == "_INDEX.md":
            continue
        try:
            with p.open("r", encoding="utf-8", errors="ignore") as fh:
                head = fh.read(2048)  # frontmatter is always near the top
        except Exception:
            continue
        if not head.startswith("---"):
            continue
        end = head.find("\n---\n", 4)
        if end < 0:
            continue
        fm_text = head[4:end]
        cwe = _grep_yaml_field(fm_text, "cwe_id")
        if cwe:
            try:
                lookup.setdefault(f"CWE-{int(cwe)}", p.stem)
            except ValueError:
                pass
        cve = _grep_yaml_field(fm_text, "cve_id")
        if cve:
            m = re.match(r"CVE[-\s](\d{4})[-\s](\d+)", cve.upper())
            if m:
                lookup.setdefault(f"CVE-{m.group(1)}-{int(m.group(2)):04d}", p.stem)
        att = _grep_yaml_field(fm_text, "attack_id")
        if att and re.match(r"T\d{4}(\.\d{3})?$", att.upper()):
            lookup.setdefault(att.upper(), p.stem)

        # NIST: parse "identifier: SP-800-53r5" from frontmatter, or fall back to filename
        nist_id = _grep_yaml_field(fm_text, "identifier")
        if nist_id and re.match(r"SP-?800-?\d+(r\d+)?$", nist_id, re.IGNORECASE):
            m2 = re.match(r"SP-?800-?(\d+)(?:r(\d+))?$", nist_id, re.IGNORECASE)
            if m2:
                canonical = f"SP-800-{int(m2.group(1))}" + (f"r{m2.group(2)}" if m2.group(2) else "")
                lookup.setdefault(canonical, p.stem)
        elif p.parent.name == "nist":
            m = re.match(r"sp-800-(\d+)(?:-rev-(\d+))?", p.stem.lower())
            if m:
                canonical = f"SP-800-{int(m.group(1))}" + (f"r{m.group(2)}" if m.group(2) else "")
                lookup.setdefault(canonical, p.stem)

        # OWASP Top-10: parse from filename for owasp notes
        if p.parent.name == "owasp":
            m = re.search(r"top10-\d{4}-(a\d{1,2})-", p.stem.lower())
            if m:
                lookup.setdefault(m.group(1).upper(), p.stem)

    return lookup


def _grep_yaml_field(fm_text: str, key: str) -> str:
    for line in fm_text.split("\n"):
        if line.startswith(key + ":"):
            return line[len(key) + 1:].strip().strip('"').strip("'")
    return ""


def _scan_name_lookup(knowledge_dir: Path) -> dict[str, str]:
    """Build lowercase-phrase -> filename_stem from parenthetical aliases in CWE titles,
    multi-word technique names from ATT&CK notes, and concept-hub titles from concepts/.

    Sources:
    - ``mitre-cwe/*.md`` — parenthetical aliases like ``('SQL Injection')`` or ``("XSS")``
    - ``mitre-attack/*.md`` — multi-word technique names extracted from titles (e.g. "OS Credential Dumping")
    - ``concepts/*.md`` — vendor/product concept-hub titles (e.g. "WordPress", "Fortinet FortiOS")

    Filters (CWE + ATT&CK):
    - phrase must be ≥ 2 words OR an all-uppercase acronym of ≥ 3 chars (e.g. XSS, SSRF)
    - phrase must not contain ``\\n [ ] { } |`` (defensive against malformed titles)

    ATT&CK additional filters:
    - skip notes with ``matrix: mobile-attack`` or ``matrix: ics-attack``
    - skip bare single-word generic tactic/technique names (blocklist, case-insensitive)

    Concept-hub special case:
    - also allows single capitalized words ≥ 4 chars matching ``[A-Z][a-zA-Z0-9]+``
      (vendor/product proper nouns like "WordPress", "Fortinet", "Microsoft")

    Returns ``{lowercase_phrase: stem}`` dict.
    """
    _PAREN_RE = re.compile(r"\(['\"]([^'\"\)]+)['\"]\)")
    _BAD_CHARS = re.compile(r"[\n\[\]{}|]")
    # ATT&CK technique titles include T-code prefix: "T1003 OS Credential Dumping"
    # Strip the leading T-code (TNNNN or TNNNN.NNN) to get the technique name.
    _TCODE_PREFIX_RE = re.compile(r"^T\d{4}(?:\.\d{3})?\s+")
    # Generic single-word blocklist for ATT&CK (case-insensitive).
    _ATTACK_BLOCKLIST = {
        "discovery", "execution", "persistence", "evasion", "collection",
        "exfiltration", "command", "control", "impact", "reconnaissance",
        "phishing", "scanning",
    }

    lookup: dict[str, str] = {}

    # ---- 1. CWE parenthetical aliases ----------------------------------------
    cwe_dir = knowledge_dir / "mitre-cwe"
    if cwe_dir.is_dir():
        for p in cwe_dir.glob("*.md"):
            if p.name == "_INDEX.md":
                continue
            try:
                with p.open("r", encoding="utf-8", errors="ignore") as fh:
                    head = fh.read(2048)
            except Exception:
                continue
            title_line = ""
            for line in head.splitlines():
                if line.startswith("title:"):
                    title_line = line
                    break
            if not title_line:
                continue
            for m in _PAREN_RE.finditer(title_line):
                phrase = m.group(1).strip()
                if _BAD_CHARS.search(phrase):
                    continue
                words = phrase.split()
                is_multiword = len(words) >= 2
                is_acronym = len(words) == 1 and phrase.isupper() and len(phrase) >= 3
                if not (is_multiword or is_acronym):
                    continue
                lookup.setdefault(phrase.lower(), p.stem)

    # ---- 2. ATT&CK technique-name aliases ------------------------------------
    attack_dir = knowledge_dir / "mitre-attack"
    if attack_dir.is_dir():
        for p in attack_dir.glob("*.md"):
            if p.name == "_INDEX.md":
                continue
            try:
                with p.open("r", encoding="utf-8", errors="ignore") as fh:
                    head = fh.read(2048)
            except Exception:
                continue
            # Parse frontmatter fields we care about
            title_val = ""
            matrix_val = ""
            in_fm = False
            for line in head.splitlines():
                if line == "---":
                    if not in_fm:
                        in_fm = True
                        continue
                    else:
                        break  # end of frontmatter
                if not in_fm:
                    continue
                if line.startswith("title:"):
                    title_val = line[6:].strip().strip('"').strip("'")
                elif line.startswith("matrix:"):
                    matrix_val = line[7:].strip().strip('"').strip("'")

            if not title_val:
                continue
            # Skip mobile/ICS matrices — only enterprise or unset
            if matrix_val in ("mobile-attack", "ics-attack"):
                continue
            # Strip leading T-code prefix (e.g. "T1003 " or "T1566.001 ") to get technique name
            technique_name = _TCODE_PREFIX_RE.sub("", title_val).strip()
            if not technique_name:
                continue
            # Apply same bad-chars filter
            if _BAD_CHARS.search(technique_name):
                continue
            words = technique_name.split()
            is_multiword = len(words) >= 2
            is_acronym = len(words) == 1 and technique_name.isupper() and len(technique_name) >= 3
            if not (is_multiword or is_acronym):
                continue
            # Apply ATT&CK-specific blocklist (case-insensitive single-word check)
            if len(words) == 1 and technique_name.lower() in _ATTACK_BLOCKLIST:
                continue
            # Multi-word: also block if the whole phrase (lowercased) is in blocklist
            if technique_name.lower() in _ATTACK_BLOCKLIST:
                continue
            lookup.setdefault(technique_name.lower(), p.stem)

    # ---- 3. Concept-hub titles (vendor/product proper nouns) -----------------
    concepts_dir = knowledge_dir / "concepts"
    if concepts_dir.is_dir():
        for p in concepts_dir.glob("*.md"):
            if p.name == "_INDEX.md":
                continue
            try:
                with p.open("r", encoding="utf-8", errors="ignore") as fh:
                    head = fh.read(2048)
            except Exception:
                continue
            title_val = ""
            for line in head.splitlines():
                if line.startswith("title:"):
                    title_val = line[6:].strip().strip('"').strip("'")
                    break
            if not title_val:
                continue
            if _BAD_CHARS.search(title_val):
                continue
            words = title_val.split()
            is_multiword = len(words) >= 2
            is_acronym = len(words) == 1 and title_val.isupper() and len(title_val) >= 3
            # Concept-hub special case: allow single capitalized proper nouns ≥ 4 chars
            is_proper_noun = (
                len(words) == 1
                and len(title_val) >= 4
                and bool(re.match(r"[A-Z][a-zA-Z0-9]+$", title_val))
            )
            if not (is_multiword or is_acronym or is_proper_noun):
                continue
            lookup.setdefault(title_val.lower(), p.stem)

    # ---- 4. Curated VULN_CLASS_SYNONYMS (phrase → CWE ID → stem) -------------
    # Synonyms are curated so they bypass the ≥2-word filter; add them unconditionally.
    # Build cwe_id -> stem map for synonym resolution by re-walking mitre-cwe/.
    cwe_id_to_stem: dict[int, str] = {}
    cwe_dir2 = knowledge_dir / "mitre-cwe"
    if cwe_dir2.is_dir():
        for p in cwe_dir2.rglob("*.md"):
            if p.name == "_INDEX.md":
                continue
            try:
                with p.open("r", encoding="utf-8", errors="ignore") as fh:
                    head = fh.read(2048)
            except OSError:
                continue
            if not head.startswith("---"):
                continue
            end = head.find("\n---\n", 4)
            if end < 0:
                continue
            fm_text = head[4:end]
            cwe = _grep_yaml_field(fm_text, "cwe_id")
            if cwe:
                try:
                    cwe_id_to_stem.setdefault(int(cwe), p.stem)
                except ValueError:
                    pass

    # Resolve the curated synonyms; setdefault so existing parenthetical aliases win
    for phrase, cwe_id in VULN_CLASS_SYNONYMS.items():
        stem = cwe_id_to_stem.get(cwe_id)
        if stem:
            lookup.setdefault(phrase.lower(), stem)

    return lookup


def _inject_wikilinks(
    body: str,
    lookup: dict[str, str],
    self_stem: str,
    name_lookup: dict[str, str] | None = None,
) -> str:
    """Replace identifier mentions in body with [[stem|identifier]] wikilinks.

    Skips code blocks, inline code, existing wikilinks, markdown links, and
    autolinks (URLs in <...>). Idempotent: re-processing doesn't double-wrap.

    If ``name_lookup`` is provided, also substitutes well-known CWE parenthetical
    aliases (e.g. "SQL injection", "XSS") with their corresponding wikilinks.
    Longer phrases take priority over shorter overlapping ones.
    """
    placeholders: list[str] = []

    def stash(m):
        placeholders.append(m.group(0))
        return f"\x00PH{len(placeholders)-1}\x00"

    body = _CODEBLOCK_RE.sub(stash, body)
    body = _INLINE_CODE_RE.sub(stash, body)
    body = _WIKILINK_RE.sub(stash, body)
    body = _MD_LINK_RE.sub(stash, body)
    body = _AUTOLINK_RE.sub(stash, body)

    def link(key: str, original: str) -> str:
        target = lookup.get(key)
        if target and target != self_stem:
            return f"[[{target}|{key}]]"
        return original

    body = _CWE_RE.sub(lambda m: link(f"CWE-{int(m.group(1))}", m.group(0)), body)
    body = _CVE_RE.sub(
        lambda m: link(f"CVE-{m.group(1)}-{int(m.group(2)):04d}", m.group(0)), body
    )
    body = _ATTACK_RE.sub(lambda m: link(m.group(1).upper(), m.group(0)), body)

    # Display label preserves original spacing (e.g. "SP 800-53r5" or "SP-800-53"); key is canonical lowercase-r form.
    def _nist_sub(m: re.Match) -> str:
        num = int(m.group(1))
        rev = m.group(2)
        key = f"SP-800-{num}" + (f"r{rev}" if rev else "")
        stem = lookup.get(key)
        if not stem or stem == self_stem:
            return m.group(0)
        return f"[[{stem}|{m.group(0)}]]"

    # Display label is the normalized bare code "A01" — drops any ":YYYY" year suffix that may appear in source text. Asymmetric with _nist_sub by design (year is noise for the link label).
    def _owasp_sub(m: re.Match) -> str:
        code = m.group(1).upper()
        stem = lookup.get(code)
        if not stem or stem == self_stem:
            return m.group(0)
        return f"[[{stem}|{code}]]"

    body = _NIST_SP_RE.sub(_nist_sub, body)
    body = _OWASP_TOP10_RE.sub(_owasp_sub, body)

    # Name-based phrase substitution — must run BEFORE placeholder restoration.
    if name_lookup:
        # Sort longest first so "OS command injection" wins over "injection"
        sorted_keys = sorted(name_lookup.keys(), key=len, reverse=True)
        name_re = re.compile(
            r"\b(?:" + "|".join(re.escape(k) for k in sorted_keys) + r")\b",
            re.IGNORECASE,
        )

        def _name_sub(m: re.Match) -> str:
            stem = name_lookup.get(m.group(0).lower())
            if not stem or stem == self_stem:
                return m.group(0)
            return f"[[{stem}|{m.group(0)}]]"

        body = name_re.sub(_name_sub, body)

    for i, ph in enumerate(placeholders):
        body = body.replace(f"\x00PH{i}\x00", ph)
    return body
