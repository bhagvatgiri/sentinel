from pathlib import Path

from sentinel.corpus.obsidian_writer import _inject_wikilinks, _scan_existing_lookup


def test_inject_wikilink_for_nist_sp_800():
    body = "Follow SP 800-53 controls for access management."
    lookup = {"SP-800-53": "sp-800-53-rev-5-security-controls-abc123"}
    result = _inject_wikilinks(body, lookup, self_stem="other-note")
    assert "[[sp-800-53-rev-5-security-controls-abc123|SP 800-53]]" in result


def test_inject_wikilink_for_owasp_top10_code():
    body = "This is an A01:2021 broken access control finding."
    lookup = {"A01": "owasp-top10-2021-a01-broken-access-control-def456"}
    result = _inject_wikilinks(body, lookup, self_stem="other-note")
    assert "[[owasp-top10-2021-a01-broken-access-control-def456|A01]]" in result


def test_inject_is_idempotent():
    body = "See SP 800-53 controls."
    lookup = {"SP-800-53": "sp-800-53-stem"}
    once = _inject_wikilinks(body, lookup, self_stem="other")
    twice = _inject_wikilinks(once, lookup, self_stem="other")
    assert once == twice


def test_inject_skips_code_blocks():
    body = "Outside CWE-79 reference.\n```\nInside CWE-89 should NOT link.\n```\n"
    lookup = {"CWE-79": "cwe-79-stem", "CWE-89": "cwe-89-stem"}
    result = _inject_wikilinks(body, lookup, self_stem="other")
    assert "[[cwe-79-stem|CWE-79]]" in result
    assert "[[cwe-89-stem|CWE-89]]" not in result


def test_inject_skips_existing_wikilinks():
    body = "Already linked: [[existing-stem|CWE-79]] should not double-wrap."
    lookup = {"CWE-79": "cwe-79-stem"}
    result = _inject_wikilinks(body, lookup, self_stem="other")
    assert result.count("[[") == 1


def test_scan_lookup_indexes_nist_from_filename(tmp_path):
    nist_dir = tmp_path / "nist"
    nist_dir.mkdir()
    note = nist_dir / "sp-800-53-rev-5-security-controls-abc12345.md"
    note.write_text(
        "---\ntitle: NIST SP 800-53 Rev 5\nsource: nist\nidentifier: SP-800-53r5\n---\nBody.\n"
    )
    lookup = _scan_existing_lookup(tmp_path)
    assert "SP-800-53r5" in lookup
    assert lookup["SP-800-53r5"] == "sp-800-53-rev-5-security-controls-abc12345"


def test_scan_lookup_indexes_nist_from_frontmatter(tmp_path):
    """Note lives outside nist/ — only the frontmatter `identifier` field can produce the key."""
    other_dir = tmp_path / "books"  # NOT "nist" — forces if-branch only
    other_dir.mkdir()
    note = other_dir / "some-nist-paper-xyz98765.md"
    note.write_text(
        "---\ntitle: NIST SP 800-53 Rev 5\nsource: nist\nidentifier: SP-800-53r5\n---\nBody.\n"
    )
    lookup = _scan_existing_lookup(tmp_path)
    assert "SP-800-53r5" in lookup
    assert lookup["SP-800-53r5"] == "some-nist-paper-xyz98765"


def test_scan_lookup_indexes_nist_from_frontmatter_versionless(tmp_path):
    """Versionless identifier like 'SP-800-53' should canonicalize without r-suffix."""
    other_dir = tmp_path / "books"
    other_dir.mkdir()
    note = other_dir / "some-nist-paper-aaa00000.md"
    note.write_text(
        "---\ntitle: NIST SP 800-53\nsource: nist\nidentifier: SP-800-53\n---\nBody.\n"
    )
    lookup = _scan_existing_lookup(tmp_path)
    assert "SP-800-53" in lookup


def test_scan_lookup_indexes_owasp_top10_from_filename(tmp_path):
    owasp_dir = tmp_path / "owasp"
    owasp_dir.mkdir()
    note = owasp_dir / "owasp-top10-2021-a01-broken-access-control-def45678.md"
    note.write_text(
        "---\ntitle: A01:2021 Broken Access Control\nsource: owasp\n"
        "tags: [knowledge, source/owasp, owasp, top10]\n---\nBody.\n"
    )
    lookup = _scan_existing_lookup(tmp_path)
    assert "A01" in lookup
    assert lookup["A01"] == "owasp-top10-2021-a01-broken-access-control-def45678"


def test_scan_name_lookup_extracts_parenthetical_alias(tmp_path):
    """CWE titles with 'short name' parentheticals are indexed."""
    from sentinel.corpus.obsidian_writer import _scan_name_lookup
    cwe_dir = tmp_path / "mitre-cwe"
    cwe_dir.mkdir()
    (cwe_dir / "cwe-79-xss-aaaaaaaa.md").write_text(
        "---\ntitle: \"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')\"\nsource: mitre-cwe\ncwe_id: 79\n---\nBody.\n"
    )
    (cwe_dir / "cwe-89-sql-bbbbbbbb.md").write_text(
        "---\ntitle: \"CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')\"\nsource: mitre-cwe\ncwe_id: 89\n---\n"
    )
    names = _scan_name_lookup(tmp_path)
    assert names.get("cross-site scripting") == "cwe-79-xss-aaaaaaaa"
    assert names.get("sql injection") == "cwe-89-sql-bbbbbbbb"


def test_scan_name_lookup_skips_single_common_words(tmp_path):
    """Bare 'Authentication' (1 word, not acronym) must NOT be indexed."""
    from sentinel.corpus.obsidian_writer import _scan_name_lookup
    cwe_dir = tmp_path / "mitre-cwe"
    cwe_dir.mkdir()
    (cwe_dir / "cwe-287-auth-cccccccc.md").write_text(
        "---\ntitle: \"CWE-287: Improper Authentication ('Authentication')\"\nsource: mitre-cwe\ncwe_id: 287\n---\n"
    )
    names = _scan_name_lookup(tmp_path)
    assert "authentication" not in names  # 1-word non-acronym, filtered


def test_scan_name_lookup_keeps_acronyms(tmp_path):
    """All-caps ≥3-char acronyms ARE indexed."""
    from sentinel.corpus.obsidian_writer import _scan_name_lookup
    cwe_dir = tmp_path / "mitre-cwe"
    cwe_dir.mkdir()
    (cwe_dir / "cwe-918-ssrf-dddddddd.md").write_text(
        "---\ntitle: \"CWE-918: Server-Side Request Forgery ('SSRF')\"\nsource: mitre-cwe\ncwe_id: 918\n---\n"
    )
    names = _scan_name_lookup(tmp_path)
    assert names.get("ssrf") == "cwe-918-ssrf-dddddddd"


def test_inject_wikilinks_links_phrase_matches():
    """A CVE description mentioning 'SQL injection' gets linked when name_lookup is provided."""
    from sentinel.corpus.obsidian_writer import _inject_wikilinks
    body = "Buffer overflow allows SQL injection via the search parameter."
    lookup = {}
    name_lookup = {"sql injection": "cwe-89-sql-stem"}
    result = _inject_wikilinks(body, lookup, self_stem="other-note", name_lookup=name_lookup)
    assert "[[cwe-89-sql-stem|SQL injection]]" in result


def test_inject_wikilinks_prefers_longer_phrase_on_overlap():
    """When 'OS command injection' and 'injection' both match, the longer phrase wins."""
    from sentinel.corpus.obsidian_writer import _inject_wikilinks
    body = "The endpoint is vulnerable to OS command injection in the filename arg."
    lookup = {}
    name_lookup = {
        "injection": "cwe-74-stem",
        "os command injection": "cwe-78-stem",
    }
    result = _inject_wikilinks(body, lookup, self_stem="other", name_lookup=name_lookup)
    assert "[[cwe-78-stem|OS command injection]]" in result
    # The shorter "injection" inside "OS command injection" should NOT also be linked
    assert result.count("[[") == 1


def test_inject_wikilinks_skips_phrase_inside_code_block():
    """Phrase matching respects the existing protected-region scheme."""
    from sentinel.corpus.obsidian_writer import _inject_wikilinks
    body = "Outside SQL injection should link.\n```\nInside SQL injection should NOT link.\n```\n"
    lookup = {}
    name_lookup = {"sql injection": "cwe-89-stem"}
    result = _inject_wikilinks(body, lookup, self_stem="other", name_lookup=name_lookup)
    # Exactly one link (the outside one); the inside-codeblock one preserved literally
    assert result.count("[[cwe-89-stem|SQL injection]]") == 1


def test_inject_wikilinks_case_insensitive_preserves_display():
    """Match 'sql injection' lowercase but render display text with the matched casing."""
    from sentinel.corpus.obsidian_writer import _inject_wikilinks
    body_lower = "a typical sql injection vector"
    body_mixed = "A typical SQL Injection vector"
    lookup = {}
    name_lookup = {"sql injection": "cwe-89-stem"}
    r1 = _inject_wikilinks(body_lower, lookup, self_stem="other", name_lookup=name_lookup)
    r2 = _inject_wikilinks(body_mixed, lookup, self_stem="other", name_lookup=name_lookup)
    assert "[[cwe-89-stem|sql injection]]" in r1
    assert "[[cwe-89-stem|SQL Injection]]" in r2


def test_inject_wikilinks_skips_self_link_by_name():
    """A note's own title-derived name shouldn't be wikilinked back to itself."""
    from sentinel.corpus.obsidian_writer import _inject_wikilinks
    body = "This CWE describes Cross-site Scripting attacks in detail."
    name_lookup = {"cross-site scripting": "cwe-79-stem"}
    result = _inject_wikilinks(body, {}, self_stem="cwe-79-stem", name_lookup=name_lookup)
    assert "[[" not in result  # self-link prevented


# ---------------------------------------------------------------------------
# Part 1 — ATT&CK technique-name aliases
# ---------------------------------------------------------------------------

def test_scan_name_lookup_extracts_attack_technique_titles(tmp_path):
    from sentinel.corpus.obsidian_writer import _scan_name_lookup
    att_dir = tmp_path / "mitre-attack"
    att_dir.mkdir()
    (att_dir / "os-credential-dumping-abc12345.md").write_text(
        "---\ntitle: T1003 OS Credential Dumping\nsource: mitre-attack\nmatrix: enterprise-attack\nstix_type: attack-pattern\n---\n"
    )
    (att_dir / "pass-the-hash-def45678.md").write_text(
        "---\ntitle: T1550.002 Pass the Hash\nsource: mitre-attack\nmatrix: enterprise-attack\n---\n"
    )
    names = _scan_name_lookup(tmp_path)
    assert names.get("os credential dumping") == "os-credential-dumping-abc12345"
    assert names.get("pass the hash") == "pass-the-hash-def45678"


def test_scan_name_lookup_skips_generic_attack_blocklist(tmp_path):
    from sentinel.corpus.obsidian_writer import _scan_name_lookup
    att_dir = tmp_path / "mitre-attack"
    att_dir.mkdir()
    (att_dir / "phishing-ghi98765.md").write_text(
        "---\ntitle: T1566 Phishing\nsource: mitre-attack\nmatrix: enterprise-attack\n---\n"
    )
    (att_dir / "spearphishing-link-jkl12345.md").write_text(
        "---\ntitle: T1566.002 Spearphishing Link\nsource: mitre-attack\nmatrix: enterprise-attack\n---\n"
    )
    names = _scan_name_lookup(tmp_path)
    # Bare "Phishing" is blocklisted (too generic)
    assert "phishing" not in names
    # Multi-word "Spearphishing Link" IS allowed
    assert names.get("spearphishing link") == "spearphishing-link-jkl12345"


def test_scan_name_lookup_skips_mobile_and_ics_matrices(tmp_path):
    from sentinel.corpus.obsidian_writer import _scan_name_lookup
    att_dir = tmp_path / "mitre-attack"
    att_dir.mkdir()
    (att_dir / "access-calendar-entries-mno12345.md").write_text(
        "---\ntitle: Access Calendar Entries\nsource: mitre-attack\nmatrix: mobile-attack\n---\n"
    )
    (att_dir / "ics-stuff-pqr67890.md").write_text(
        "---\ntitle: Brute Force I O\nsource: mitre-attack\nmatrix: ics-attack\n---\n"
    )
    names = _scan_name_lookup(tmp_path)
    assert "access calendar entries" not in names
    assert "brute force i o" not in names


# ---------------------------------------------------------------------------
# Part 2 — Concept-hub layer
# ---------------------------------------------------------------------------

def test_scan_name_lookup_extracts_concept_hub_titles(tmp_path):
    from sentinel.corpus.obsidian_writer import _scan_name_lookup
    cdir = tmp_path / "concepts"
    cdir.mkdir()
    (cdir / "wordpress.md").write_text(
        "---\ntitle: \"WordPress\"\nsource: concepts\n---\n"
    )
    (cdir / "fortinet-fortios.md").write_text(
        "---\ntitle: \"Fortinet FortiOS\"\nsource: concepts\n---\n"
    )
    names = _scan_name_lookup(tmp_path)
    assert names.get("wordpress") == "wordpress"
    assert names.get("fortinet fortios") == "fortinet-fortios"


def test_scan_name_lookup_does_not_link_capitalized_words_outside_concepts(tmp_path):
    """Single capitalized word from CWE/ATT&CK still filtered — only concepts/ allows it."""
    from sentinel.corpus.obsidian_writer import _scan_name_lookup
    cdir = tmp_path / "mitre-cwe"
    cdir.mkdir()
    (cdir / "cwe-X-something.md").write_text(
        "---\ntitle: \"CWE-X: ('Authentication')\"\nsource: mitre-cwe\ncwe_id: X\n---\n"
    )
    names = _scan_name_lookup(tmp_path)
    assert "authentication" not in names  # CWE single word still filtered


# ---------------------------------------------------------------------------
# Part 3 — VULN_CLASS_SYNONYMS curated phrase resolution
# ---------------------------------------------------------------------------

def test_scan_name_lookup_resolves_curated_synonyms(tmp_path):
    """Curated vuln-class phrases resolve to existing CWE stems."""
    from sentinel.corpus.obsidian_writer import _scan_name_lookup
    cwe_dir = tmp_path / "mitre-cwe"
    cwe_dir.mkdir()
    (cwe_dir / "cwe-120-buffer-aaaaaaaa.md").write_text(
        "---\ntitle: \"CWE-120: Buffer Copy without Checking Size of Input\"\n"
        "source: mitre-cwe\ncwe_id: 120\n---\n"
    )
    (cwe_dir / "cwe-416-uaf-bbbbbbbb.md").write_text(
        "---\ntitle: \"CWE-416: Use After Free\"\nsource: mitre-cwe\ncwe_id: 416\n---\n"
    )
    names = _scan_name_lookup(tmp_path)
    assert names.get("buffer overflow") == "cwe-120-buffer-aaaaaaaa"
    assert names.get("use after free") == "cwe-416-uaf-bbbbbbbb"
    assert names.get("use-after-free") == "cwe-416-uaf-bbbbbbbb"


def test_scan_name_lookup_skips_synonyms_when_cwe_missing(tmp_path):
    """If the target CWE isn't in the vault, the synonym is silently skipped."""
    from sentinel.corpus.obsidian_writer import _scan_name_lookup
    cwe_dir = tmp_path / "mitre-cwe"
    cwe_dir.mkdir()
    # Empty mitre-cwe — no CWEs present
    names = _scan_name_lookup(tmp_path)
    assert "buffer overflow" not in names
    assert "use after free" not in names


def test_parenthetical_alias_wins_over_synonym(tmp_path):
    """When a CWE has a parenthetical alias AND a curated synonym for the same phrase,
    the parenthetical alias resolution wins (since it's built first; setdefault doesn't overwrite)."""
    from sentinel.corpus.obsidian_writer import _scan_name_lookup
    cwe_dir = tmp_path / "mitre-cwe"
    cwe_dir.mkdir()
    # CWE-89 has the parenthetical 'SQL Injection'
    (cwe_dir / "cwe-89-sql-inj-aaaaaaaa.md").write_text(
        "---\ntitle: \"CWE-89: ... ('SQL Injection')\"\nsource: mitre-cwe\ncwe_id: 89\n---\n"
    )
    names = _scan_name_lookup(tmp_path)
    assert names.get("sql injection") == "cwe-89-sql-inj-aaaaaaaa"
