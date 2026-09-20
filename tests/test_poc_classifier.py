"""VERIFY-02 — destructive-PoC classifier contract.

Pins the registry of patterns that the Phase 3 sandbox (Plan 03-04) will
consult BEFORE attempting any subprocess.run on agent-generated PoCs.

False-positive cost is low (operator re-categorizes); false-negative cost
is high (we'd auto-execute a destructive command). The classifier is
therefore deliberately permissive on destructive patterns.

Coverage MUST include:
- 15 canonical patterns (SQL DROP/TRUNCATE/DELETE/UPDATE-pwd, shell rm/mkfs/dd/redirect/chmod/fork/kill-init/sqlmap-destructive, python os.remove/shutil.rmtree)
- shell_b64_pipe_shell (T-03-03-05 mitigation — base64 wrap bypass)
- python_eval_dynamic (T-03-03-06 mitigation)
- python_pickle_loads (T-03-03-07 mitigation; absorbs Plan 03-04 T-03-04-08 pickle leg)
- yaml_unsafe_load (T-03-03-08 mitigation; absorbs Plan 03-04 T-03-04-08 yaml leg)
- Negative tests covering REST DELETE, grep, sqlmap boolean-blind, kill <high-pid>, requests.get, playwright.goto, pickle.dumps, yaml.safe_load, yaml.load+SafeLoader
- Tripwire: len(DESTRUCTIVE_PATTERNS) >= 17 so future PRs can't silently drop coverage
"""

from __future__ import annotations

import re

import pytest

from sentinel.agent.poc import (
    DESTRUCTIVE_PATTERNS,
    ClassifierVerdict,
    DestructivePattern,
    classify_destructive,
)
from sentinel.core.findings import EvidenceState


# ---------------------------------------------------------------------------
# Positive: SQL destructive patterns
# ---------------------------------------------------------------------------


def test_classify_destructive_sql_drop_table():
    v = classify_destructive("SELECT * FROM users; DROP TABLE users; --", "sql")
    assert v.is_destructive is True
    assert v.pattern_name == "sql_drop_table"


def test_classify_destructive_sql_drop_table_case_insensitive():
    v = classify_destructive("drop table foo", "sql")
    assert v.is_destructive is True


def test_classify_destructive_sql_drop_database():
    v = classify_destructive("DROP DATABASE clientdb", "sql")
    assert v.is_destructive is True
    assert v.pattern_name == "sql_drop_database"


def test_classify_destructive_sql_truncate_with_table_keyword():
    v = classify_destructive("TRUNCATE TABLE users", "sql")
    assert v.is_destructive is True
    assert v.pattern_name == "sql_truncate"


def test_classify_destructive_sql_truncate_without_table_keyword():
    v = classify_destructive("TRUNCATE users", "sql")
    assert v.is_destructive is True
    assert v.pattern_name == "sql_truncate"


def test_classify_destructive_sql_delete_unrestricted():
    v = classify_destructive("DELETE FROM users", "sql")
    assert v.is_destructive is True
    assert v.pattern_name == "sql_delete_unrestricted"


def test_classify_destructive_sql_delete_with_where_is_safe():
    v = classify_destructive("DELETE FROM users WHERE id=1", "sql")
    assert v.is_destructive is False


def test_classify_destructive_sql_update_password():
    v = classify_destructive(
        "UPDATE users SET password='x' WHERE id=1", "sql"
    )
    assert v.is_destructive is True
    assert v.pattern_name == "sql_update_password"


# ---------------------------------------------------------------------------
# Positive: Shell destructive patterns
# ---------------------------------------------------------------------------


def test_classify_destructive_shell_rm_rf():
    v = classify_destructive("rm -rf /var/log/*", "shell")
    assert v.is_destructive is True
    assert v.pattern_name == "shell_rm_rf"


def test_classify_destructive_shell_rm_rf_alt_syntax():
    assert classify_destructive("rm -fr foo", "shell").is_destructive is True
    assert (
        classify_destructive("rm --recursive --force /tmp/x", "shell").is_destructive
        is True
    )


def test_classify_destructive_shell_mkfs():
    v = classify_destructive("mkfs.ext4 /dev/sda1", "shell")
    assert v.is_destructive is True
    assert v.pattern_name == "shell_mkfs"


def test_classify_destructive_shell_dd_to_disk():
    v = classify_destructive("dd if=/dev/zero of=/dev/sda", "shell")
    assert v.is_destructive is True
    assert v.pattern_name == "shell_dd_to_disk"


def test_classify_destructive_shell_redirect_to_root():
    v = classify_destructive("echo evil > /etc/passwd", "shell")
    assert v.is_destructive is True
    assert v.pattern_name == "shell_redirect_to_root"


def test_classify_destructive_shell_chmod_777():
    assert (
        classify_destructive("chmod 777 /etc/shadow", "shell").is_destructive is True
    )
    assert classify_destructive("chmod -R 777 /var/", "shell").is_destructive is True


def test_classify_destructive_shell_fork_bomb():
    v = classify_destructive(":(){ :|:& };:", "shell")
    assert v.is_destructive is True
    assert v.pattern_name == "shell_fork_bomb"


def test_classify_destructive_shell_kill_init():
    v = classify_destructive("kill -9 1", "shell")
    assert v.is_destructive is True
    assert v.pattern_name == "shell_kill_init"


def test_classify_destructive_sqlmap_destructive_flags():
    v = classify_destructive(
        "sqlmap -u http://target/?id=1 --drop --batch", "shell"
    )
    assert v.is_destructive is True
    assert v.pattern_name == "sqlmap_destructive"


def test_classify_destructive_shell_base64_to_shell():
    v = classify_destructive(
        "echo cm0gLXJmIC8= | base64 -d | sh", "shell"
    )
    assert v.is_destructive is True
    assert v.pattern_name == "shell_b64_pipe_shell"


# ---------------------------------------------------------------------------
# Positive: Python destructive patterns
# ---------------------------------------------------------------------------


def test_classify_destructive_python_os_remove_root():
    v = classify_destructive("import os; os.remove('/etc/passwd')", "python")
    assert v.is_destructive is True
    assert v.pattern_name == "python_os_remove_root"


def test_classify_destructive_python_shutil_rmtree_root():
    v = classify_destructive("import shutil; shutil.rmtree('/var/log')", "python")
    assert v.is_destructive is True
    assert v.pattern_name == "python_shutil_rmtree_root"


def test_classify_destructive_python_eval_dynamic():
    v = classify_destructive("eval(open('/tmp/x').read())", "python")
    assert v.is_destructive is True
    assert v.pattern_name == "python_eval_dynamic"


def test_classify_destructive_python_pickle_loads():
    """T-03-03-07 / absorbs Plan 03-04's T-03-04-08 pickle leg."""
    v = classify_destructive("import pickle; pickle.loads(data)", "python")
    assert v.is_destructive is True
    assert v.pattern_name == "python_pickle_loads"

    # Also matches pickle.load (no 's')
    v2 = classify_destructive(
        "pickle.load(open('/tmp/x','rb'))", "python"
    )
    assert v2.is_destructive is True
    assert v2.pattern_name == "python_pickle_loads"


def test_classify_destructive_yaml_unsafe_load():
    """T-03-03-08 / absorbs Plan 03-04's T-03-04-08 yaml leg."""
    v = classify_destructive("yaml.unsafe_load(s)", "python")
    assert v.is_destructive is True
    assert v.pattern_name == "yaml_unsafe_load"


def test_classify_destructive_yaml_load_with_loader():
    """yaml.load(..., Loader=yaml.Loader|FullLoader) is documented unsafe."""
    v1 = classify_destructive("yaml.load(s, Loader=yaml.Loader)", "python")
    assert v1.is_destructive is True
    assert v1.pattern_name == "yaml_unsafe_load"

    v2 = classify_destructive(
        "yaml.load(s, Loader=yaml.FullLoader)", "python"
    )
    assert v2.is_destructive is True
    assert v2.pattern_name == "yaml_unsafe_load"


def test_classify_destructive_yaml_load_no_loader():
    """Bare yaml.load(x) (no Loader kwarg) was unsafe pre-PyYAML 5.1; still flag."""
    v = classify_destructive("yaml.load(s)", "python")
    assert v.is_destructive is True
    assert v.pattern_name == "yaml_unsafe_load"


# ---------------------------------------------------------------------------
# Negative: must classify SAFE
# ---------------------------------------------------------------------------


def test_classify_safe_rest_delete_method():
    """HTTP DELETE method is not SQL DELETE FROM."""
    v = classify_destructive(
        "curl -X DELETE http://target/api/users/1", "shell"
    )
    assert v.is_destructive is False, v


def test_classify_safe_read_only_grep():
    """`grep -rf` is not `rm -rf` — keyword boundary must be on `rm`."""
    v = classify_destructive("grep -rf /etc/passwd", "shell")
    assert v.is_destructive is False, v


def test_classify_safe_select_query():
    v = classify_destructive(
        "SELECT * FROM users WHERE id=1", "sql"
    )
    assert v.is_destructive is False


def test_classify_safe_sqlmap_boolean_blind():
    """Boolean-blind dump is read-only — not destructive."""
    v = classify_destructive(
        "sqlmap -u http://target/?id=1 --technique=B --batch --dump", "shell"
    )
    assert v.is_destructive is False, v


def test_classify_safe_kill_high_pid():
    """`kill 9999` is not `kill -9 1`."""
    v = classify_destructive("kill 9999", "shell")
    assert v.is_destructive is False, v


def test_classify_safe_python_requests_get():
    v = classify_destructive(
        "import requests; r = requests.get('http://target/api'); print(r.status_code)",
        "python",
    )
    assert v.is_destructive is False


def test_classify_safe_playwright_goto():
    v = classify_destructive(
        "await page.goto('http://target/login')", "python"
    )
    assert v.is_destructive is False


def test_classify_safe_pickle_dumps():
    """pickle.dumps SERIALIZATION is safe — only LOADS is the sink."""
    v = classify_destructive("pickle.dumps(obj)", "python")
    assert v.is_destructive is False, v


def test_classify_safe_yaml_safe_load():
    """yaml.safe_load is the documented safe API."""
    v = classify_destructive("yaml.safe_load(s)", "python")
    assert v.is_destructive is False, v


def test_classify_safe_yaml_load_safeloader():
    """yaml.load(..., Loader=yaml.SafeLoader) is the safe-explicit form."""
    v = classify_destructive(
        "yaml.load(s, Loader=yaml.SafeLoader)", "python"
    )
    assert v.is_destructive is False, v


# ---------------------------------------------------------------------------
# Contract: ClassifierVerdict.suggested_evidence_state
# ---------------------------------------------------------------------------


def test_classifier_verdict_suggests_manual_required_when_destructive():
    v = classify_destructive("rm -rf /", "shell")
    assert v.is_destructive is True
    assert v.suggested_evidence_state is EvidenceState.MANUAL_REQUIRED


def test_classifier_verdict_suggests_pending_when_safe():
    v = classify_destructive("curl http://target/api", "shell")
    assert v.is_destructive is False
    assert v.suggested_evidence_state is EvidenceState.PENDING


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_classifier_oversized_poc_is_destructive():
    """T-03-03-04 — pathological/oversized PoCs short-circuit to MANUAL_REQUIRED."""
    v = classify_destructive("A" * 40000, "shell")
    assert v.is_destructive is True
    assert v.pattern_name == "oversized"
    assert v.suggested_evidence_state is EvidenceState.MANUAL_REQUIRED


def test_classifier_empty_poc_is_safe():
    """Empty/whitespace-only PoC — let the sandbox simply fail to execute."""
    assert classify_destructive("", None).is_destructive is False
    assert classify_destructive("   ", None).is_destructive is False
    assert classify_destructive("\n\t \n", None).is_destructive is False


def test_classifier_strips_sql_comments_before_match():
    """T-03-03-01 — comment-injection bypass `DR/*x*/OP TABLE` must NOT evade."""
    v = classify_destructive("DR/*comment*/OP TABLE users", "sql")
    assert v.is_destructive is True


def test_classifier_strips_sql_line_comments_before_match():
    """SQL `--` line comments stripped before matching."""
    v = classify_destructive(
        "DROP --inline-comment\nTABLE users", "sql"
    )
    assert v.is_destructive is True


def test_classifier_returns_first_matching_pattern_name():
    """When multiple patterns match, pattern_name is deterministic by registry order."""
    v = classify_destructive(
        "rm -rf /tmp; DROP TABLE users", "shell"
    )
    assert v.is_destructive is True
    # Both `shell_rm_rf` and `sql_drop_table` would match. We don't pin which
    # one wins — only that ONE of them does and it's deterministic.
    assert v.pattern_name in {"shell_rm_rf", "sql_drop_table"}

    # Run it again — same input should give same answer.
    v2 = classify_destructive(
        "rm -rf /tmp; DROP TABLE users", "shell"
    )
    assert v2.pattern_name == v.pattern_name


def test_classifier_language_filter_skips_mismatched_hint():
    """Patterns with language_hint != caller-supplied language are skipped.

    A 'shell' caller supplying `os.remove('/etc/passwd')` shouldn't trigger
    the python_os_remove_root pattern — that's a python-specific heuristic.
    """
    # The same string passed with language='python' would match; with 'shell' it shouldn't.
    py = classify_destructive("os.remove('/etc/passwd')", "python")
    assert py.is_destructive is True
    assert py.pattern_name == "python_os_remove_root"

    sh = classify_destructive("os.remove('/etc/passwd')", "shell")
    # The pure os.remove text doesn't trigger any SHELL pattern, so safe under shell.
    assert sh.is_destructive is False


def test_classifier_language_none_matches_any_language_pattern():
    """When language=None, ALL patterns (regardless of language_hint) apply."""
    v = classify_destructive("pickle.loads(data)", None)
    assert v.is_destructive is True
    assert v.pattern_name == "python_pickle_loads"


# ---------------------------------------------------------------------------
# Registry invariants + tripwire
# ---------------------------------------------------------------------------


def test_classifier_registry_invariants():
    """Every entry has non-empty name, compiled regex, non-empty rationale."""
    for pattern in DESTRUCTIVE_PATTERNS:
        assert isinstance(pattern, DestructivePattern)
        assert pattern.name and isinstance(pattern.name, str)
        # Must be a compiled regex — Pattern object from re.compile().
        assert isinstance(pattern.regex, re.Pattern), (
            f"Pattern {pattern.name!r} regex is not pre-compiled "
            f"({type(pattern.regex).__name__})"
        )
        assert pattern.rationale and isinstance(pattern.rationale, str)
        # language_hint is optional but if set must be a known language string
        if pattern.language_hint is not None:
            assert pattern.language_hint in {"sql", "shell", "python"}, (
                f"Pattern {pattern.name!r} has unknown language_hint "
                f"{pattern.language_hint!r}"
            )


def test_classifier_pattern_count_minimum():
    """Tripwire: future PRs cannot silently delete coverage.

    15 canonical patterns + shell_b64_pipe_shell + python_eval_dynamic +
    python_pickle_loads + yaml_unsafe_load = 19 minimum. The acceptance
    criterion in the plan is >= 17 (slightly loose to allow regex merging),
    so we pin at 17 here.
    """
    assert len(DESTRUCTIVE_PATTERNS) >= 17, (
        f"DESTRUCTIVE_PATTERNS has {len(DESTRUCTIVE_PATTERNS)} entries; "
        "expected at least 17 (15 canonical + b64-pipe + eval + pickle + yaml-unsafe)"
    )


def test_classifier_named_patterns_present():
    """Spot-check that the canonical pattern NAMES exist in the registry."""
    names = {p.name for p in DESTRUCTIVE_PATTERNS}
    required = {
        "sql_drop_table",
        "sql_drop_database",
        "sql_truncate",
        "sql_delete_unrestricted",
        "sql_update_password",
        "shell_rm_rf",
        "shell_mkfs",
        "shell_dd_to_disk",
        "shell_redirect_to_root",
        "shell_chmod_777",
        "shell_fork_bomb",
        "shell_kill_init",
        "sqlmap_destructive",
        "python_os_remove_root",
        "python_shutil_rmtree_root",
        "shell_b64_pipe_shell",
        "python_eval_dynamic",
        "python_pickle_loads",
        "yaml_unsafe_load",
    }
    missing = required - names
    assert not missing, f"DESTRUCTIVE_PATTERNS missing required names: {missing}"


def test_poc_package_exports_classifier():
    """Re-exports from sentinel.agent.poc are wired up."""
    from sentinel.agent.poc import (
        DESTRUCTIVE_PATTERNS as RE_DESTRUCTIVE,
        ClassifierVerdict as RE_VERDICT,
        DestructivePattern as RE_PATTERN,
        classify_destructive as re_classify,
    )

    assert RE_DESTRUCTIVE is DESTRUCTIVE_PATTERNS
    assert RE_VERDICT is ClassifierVerdict
    assert RE_PATTERN is DestructivePattern
    assert re_classify is classify_destructive


def test_classifier_verdict_is_frozen_dataclass():
    """ClassifierVerdict is immutable — protects callers against accidental mutation."""
    v = classify_destructive("rm -rf /", "shell")
    with pytest.raises((AttributeError, Exception)):
        v.is_destructive = False  # type: ignore[misc]


def test_destructive_pattern_is_frozen_dataclass():
    """DestructivePattern is immutable — registry can't be mutated at runtime."""
    p = DESTRUCTIVE_PATTERNS[0]
    with pytest.raises((AttributeError, Exception)):
        p.name = "tampered"  # type: ignore[misc]
