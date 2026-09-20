"""Destructive-PoC classifier (VERIFY-02).

Pure-function gate that the Phase 3 sandbox (Plan 03-04) calls BEFORE invoking
subprocess.run on any agent-generated PoC. Returns a `ClassifierVerdict`; when
`is_destructive` is True, the sandbox short-circuits to MANUAL_REQUIRED with no
execution attempt — the operator must hand-review and rerun the verifier under
their direct supervision.

Design contract
---------------

*   **False negative is acceptable** — operator catches the destructive PoC in
    review, the sandbox simply doesn't auto-execute on its own.
*   **False positive is the preferred failure mode** — flag manual-required and
    skip auto-execution rather than risk auto-running a destructive command.

The asymmetric cost (an auto-executed destructive command is irreversible; a
false manual-required just means an operator clicks "rerun") makes the
classifier deliberately permissive on destructive patterns.

Pattern coverage
----------------

*   **SQL destructive verbs:** `DROP TABLE`, `DROP DATABASE`, `TRUNCATE`,
    `DELETE FROM` (without `WHERE`), `UPDATE ... SET password`.
*   **Shell filesystem writes:** `rm -rf` / `rm -fr` / `rm --recursive --force`,
    `mkfs`, `dd if=... of=/dev/...`, `> /etc/...`, `chmod 777`, fork bomb
    `:(){:|:&};:`, `kill -9 1` (init), `sqlmap --drop|--purge|--destroy`.
*   **Python destructive sinks:** `os.remove('/etc/...')`, `shutil.rmtree('/...')`,
    `eval(open(...).read())`, `exec(... open(...))`.
*   **Deserialization sinks** (absorbs Plan 03-04's T-03-04-08 so the sandbox
    doesn't need duplicate logic): `pickle.loads(...)` / `pickle.load(...)`,
    `yaml.unsafe_load(...)`, `yaml.load(...)` without an explicit SafeLoader
    (the `yaml.load` default was unsafe pre-PyYAML 5.1 and the API is still
    documented as unsafe-by-default for older code).
*   **Wrap bypass:** `base64 -d | sh` style obfuscation (T-03-03-05).

Known limits (residual risk — accepted per asymmetric-cost design)
------------------------------------------------------------------

*   Multi-level base64 wraps (`base64 -d | base64 -d | sh`) only flag the first
    layer; deeper obfuscation slips through. Documented in the threat model.
*   Novel SQL keyword variants beyond DROP/TRUNCATE/DELETE/UPDATE-password are
    not catalogued. Adding new patterns is an additive PR change.
*   The classifier does not run any execution itself — it operates entirely on
    the PoC string. No filesystem, no network, no subprocess.

yaml_unsafe_load implementation note
------------------------------------

The yaml-unsafe coverage uses TWO `DESTRUCTIVE_PATTERNS` entries sharing the
same `name="yaml_unsafe_load"`:

1.  Direct `yaml.unsafe_load(...)` literal.
2.  `yaml.load(...)` UNLESS the call argument span contains `SafeLoader`.

The two-entry pattern is clearer than a single mega-regex with both branches
(the second entry's negative lookahead `(?![^)]*SafeLoader)` only needs to
worry about the bare-load case, which keeps the regex readable). Both entries
produce verdicts with `pattern_name='yaml_unsafe_load'` so callers see a
single canonical pattern name regardless of which leg fired.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Pattern

from sentinel.core.findings import EvidenceState

# Cap PoC string length to 32 KB. T-03-03-04 mitigation against pathological
# regex backtracking; over-long PoCs short-circuit to MANUAL_REQUIRED rather
# than risk a catastrophic-backtrack DoS in the classifier itself.
MAX_POC_LENGTH = 32 * 1024


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DestructivePattern:
    """One pattern in the DESTRUCTIVE_PATTERNS registry.

    Attributes:
        name:           Stable identifier surfaced in verdicts and tests
                        (e.g. 'sql_drop_table'). Multiple entries MAY share a
                        name when they cover variants of the same semantic
                        pattern (see yaml_unsafe_load).
        regex:          Pre-compiled regex with appropriate flags.
        language_hint:  'sql' / 'shell' / 'python' / None. When set, the
                        classifier skips this pattern if the caller pinned a
                        DIFFERENT language. When the caller passes None the
                        pattern always applies.
        rationale:      Human-readable explanation surfaced in verdicts and in
                        the audit log when this pattern fires.
    """

    name: str
    regex: Pattern[str]
    language_hint: Optional[str]
    rationale: str


@dataclass(frozen=True)
class ClassifierVerdict:
    """Output of `classify_destructive`.

    Attributes:
        is_destructive:             True iff the PoC string matched a pattern
                                    in DESTRUCTIVE_PATTERNS (or hit the
                                    oversized/empty short-circuits).
        pattern_name:               Name of the matched pattern (or 'oversized'
                                    for the size short-circuit). None when no
                                    pattern matched.
        rationale:                  Why this verdict was reached — surfaces in
                                    Finding.destructive_classifier_match and
                                    the audit log.
        suggested_evidence_state:   `EvidenceState.MANUAL_REQUIRED` when
                                    destructive; `EvidenceState.PENDING`
                                    otherwise. Plan 03-04's sandbox promotes
                                    PENDING -> VERIFIED / UNREPRODUCIBLE based
                                    on execution outcome.
    """

    is_destructive: bool
    pattern_name: Optional[str]
    rationale: str
    suggested_evidence_state: EvidenceState


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------
#
# Registry order matters: the classifier iterates top-to-bottom and returns the
# first match (T-03-03 "deterministic first match"). Highest-impact / most
# common patterns first so the verdict's pattern_name surfaces the most useful
# label when a PoC matches multiple categories.

DESTRUCTIVE_PATTERNS: list[DestructivePattern] = [
    # ---------------------------------------------------------------- SQL
    DestructivePattern(
        name="sql_drop_table",
        regex=re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
        language_hint="sql",
        rationale="PoC contains DROP TABLE — irreversibly removes a table.",
    ),
    DestructivePattern(
        name="sql_drop_database",
        regex=re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE),
        language_hint="sql",
        rationale="PoC contains DROP DATABASE — irreversibly removes a database.",
    ),
    DestructivePattern(
        name="sql_truncate",
        regex=re.compile(r"\bTRUNCATE\s+(?:TABLE\s+)?\w+", re.IGNORECASE),
        language_hint="sql",
        rationale="PoC contains TRUNCATE — irreversibly empties a table.",
    ),
    DestructivePattern(
        name="sql_delete_unrestricted",
        # The trailing `\b` anchors `\w+` so the regex engine can't backtrack
        # from `users` to `user` to dodge the `(?!\s+WHERE)` negative lookahead.
        # Without the `\b`, "DELETE FROM users WHERE id=1" wrongly matched by
        # shrinking `\w+` to `user` and treating the trailing `s` as "no WHERE
        # found right after `user`".
        regex=re.compile(
            r"\bDELETE\s+FROM\s+\w+\b(?!\s+WHERE)", re.IGNORECASE
        ),
        language_hint="sql",
        rationale=(
            "PoC contains DELETE FROM without a WHERE clause — wipes the "
            "entire table. WHERE-clause-restricted DELETEs are exempt."
        ),
    ),
    DestructivePattern(
        name="sql_update_password",
        # Match UPDATE <table-with-users> SET password
        # The plan's reference regex is `\bUPDATE\s+\w*users?\w*\s+SET\s+password`
        regex=re.compile(
            r"\bUPDATE\s+\w*users?\w*\s+SET\s+password", re.IGNORECASE
        ),
        language_hint="sql",
        rationale=(
            "PoC contains UPDATE ... SET password — credential mutation, "
            "high risk of locking out real accounts."
        ),
    ),
    # ---------------------------------------------------------------- Shell
    DestructivePattern(
        name="shell_rm_rf",
        regex=re.compile(
            r"\brm\s+-rf\b|\brm\s+-fr\b|\brm\s+--recursive\s+--force",
            re.IGNORECASE,
        ),
        language_hint="shell",
        rationale=(
            "PoC contains `rm -rf` (or equivalent flags) — recursive force "
            "removal is documented destructive."
        ),
    ),
    DestructivePattern(
        name="shell_mkfs",
        regex=re.compile(r"\bmkfs\b", re.IGNORECASE),
        language_hint="shell",
        rationale="PoC contains `mkfs` — reformats a filesystem.",
    ),
    DestructivePattern(
        name="shell_dd_to_disk",
        regex=re.compile(r"\bdd\s+if=.*\s+of=/dev/", re.IGNORECASE),
        language_hint="shell",
        rationale=(
            "PoC pipes `dd` output to /dev/ — overwrites a raw block device."
        ),
    ),
    DestructivePattern(
        name="shell_redirect_to_root",
        regex=re.compile(
            r">\s*/(?:etc|usr|var|bin|sbin|root|home)/", re.IGNORECASE
        ),
        language_hint="shell",
        rationale=(
            "PoC redirects shell output into a system-owned path "
            "(/etc, /usr, /var, /bin, /sbin, /root, /home)."
        ),
    ),
    DestructivePattern(
        name="shell_chmod_777",
        regex=re.compile(r"\bchmod\s+(?:-R\s+)?777\b", re.IGNORECASE),
        language_hint="shell",
        rationale=(
            "PoC contains `chmod 777` — world-writable permission flip is "
            "documented destructive (lateral privilege escalation primitive)."
        ),
    ),
    DestructivePattern(
        name="shell_fork_bomb",
        regex=re.compile(r":\(\)\s*\{\s*:\s*\|\s*:&\s*\}\s*;\s*:"),
        language_hint="shell",
        rationale="PoC contains the canonical bash fork-bomb signature.",
    ),
    DestructivePattern(
        name="shell_kill_init",
        regex=re.compile(r"\bkill\s+-9?\s+1\b"),
        language_hint="shell",
        rationale=(
            "PoC sends a signal to PID 1 (init) — would take the host down."
        ),
    ),
    DestructivePattern(
        name="sqlmap_destructive",
        regex=re.compile(
            r"\bsqlmap\b.*--(?:drop|purge|destroy|delete)\b", re.IGNORECASE
        ),
        language_hint="shell",
        rationale=(
            "sqlmap invocation includes a destructive flag "
            "(--drop|--purge|--destroy|--delete)."
        ),
    ),
    DestructivePattern(
        name="shell_b64_pipe_shell",
        regex=re.compile(
            r"base64\s+-d\s*\|\s*(?:bash|sh|zsh)", re.IGNORECASE
        ),
        language_hint="shell",
        rationale=(
            "PoC pipes base64-decoded payload directly into a shell "
            "interpreter — wrap-bypass evasion of static analysis "
            "(T-03-03-05)."
        ),
    ),
    # ---------------------------------------------------------------- Python
    DestructivePattern(
        name="python_os_remove_root",
        regex=re.compile(
            r"os\.remove\s*\(\s*['\"]/(?:etc|usr|var|bin|sbin|root|home)",
            re.IGNORECASE,
        ),
        language_hint="python",
        rationale=(
            "PoC calls os.remove on a system-owned path — irreversible "
            "file deletion in a sensitive directory."
        ),
    ),
    DestructivePattern(
        name="python_shutil_rmtree_root",
        regex=re.compile(
            r"shutil\.rmtree\s*\(\s*['\"]/(?:etc|usr|var|bin|sbin|root|home)",
            re.IGNORECASE,
        ),
        language_hint="python",
        rationale=(
            "PoC calls shutil.rmtree on a system-owned path — recursive "
            "irreversible directory deletion."
        ),
    ),
    DestructivePattern(
        name="python_eval_dynamic",
        regex=re.compile(
            r"\beval\s*\(|\bexec\s*\(.*open\(", re.IGNORECASE
        ),
        language_hint="python",
        rationale=(
            "PoC uses eval() or exec(open(...)) — dynamic code execution "
            "from runtime strings (T-03-03-06)."
        ),
    ),
    # ------------------------ Deserialization sinks (T-03-04-08 absorbed)
    DestructivePattern(
        name="python_pickle_loads",
        regex=re.compile(r"\bpickle\.loads?\s*\(", re.IGNORECASE),
        language_hint="python",
        rationale=(
            "PoC calls pickle.loads/pickle.load — documented arbitrary-code-"
            "execution on parse. Use json or yaml.safe_load instead. "
            "(T-03-03-07; absorbs Plan 03-04 T-03-04-08 pickle leg.)"
        ),
    ),
    # yaml_unsafe_load — direct explicit-unsafe API call.
    DestructivePattern(
        name="yaml_unsafe_load",
        regex=re.compile(r"\byaml\.unsafe_load\s*\(", re.IGNORECASE),
        language_hint="python",
        rationale=(
            "PoC calls yaml.unsafe_load — documented arbitrary-code-"
            "execution on parse. Use yaml.safe_load or "
            "yaml.load(..., Loader=yaml.SafeLoader) instead. "
            "(T-03-03-08; absorbs Plan 03-04 T-03-04-08 yaml leg.)"
        ),
    ),
    # yaml_unsafe_load — yaml.load(...) WITHOUT an explicit SafeLoader.
    # Negative lookahead `(?![^)]*SafeLoader)` matches yaml.load( only when
    # the call's argument span (up to the next `)`) does NOT contain
    # `SafeLoader`. This is what catches:
    #   yaml.load(s)
    #   yaml.load(s, Loader=yaml.Loader)
    #   yaml.load(s, Loader=yaml.FullLoader)
    # while leaving:
    #   yaml.load(s, Loader=yaml.SafeLoader)
    #   yaml.safe_load(s)                          (different literal — no match)
    # alone. Both entries share name='yaml_unsafe_load' so callers see one
    # canonical pattern label regardless of which leg fired.
    DestructivePattern(
        name="yaml_unsafe_load",
        regex=re.compile(
            r"\byaml\.load\s*\((?![^)]*SafeLoader)", re.IGNORECASE
        ),
        language_hint="python",
        rationale=(
            "PoC calls yaml.load() without an explicit SafeLoader. The "
            "default loader was unsafe pre-PyYAML 5.1 and the API remains "
            "documented as unsafe-by-default; specify Loader=yaml.SafeLoader "
            "or switch to yaml.safe_load. (T-03-03-08; absorbs Plan 03-04 "
            "T-03-04-08 yaml leg.)"
        ),
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Strip block comments `/*...*/` (any case, multi-line) and SQL line comments
# `--...` up to newline. T-03-03-01 mitigation: an adversarial agent might wrap
# destructive verbs in SQL comments (e.g. `DR/*x*/OP TABLE`) to evade naive
# regex scanning.
_SQL_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_SQL_LINE_COMMENT = re.compile(r"--[^\n]*")


def _strip_sql_comments(poc: str) -> str:
    """Remove SQL comment syntax before pattern matching."""
    intermediate = _SQL_BLOCK_COMMENT.sub("", poc)
    return _SQL_LINE_COMMENT.sub("", intermediate)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_destructive(
    poc: str, language: Optional[str] = None
) -> ClassifierVerdict:
    """Classify a PoC string as destructive or safe.

    Args:
        poc:        The candidate PoC. Typically a shell one-liner, a SQL
                    payload, or a Python snippet emitted by an agent.
        language:   Optional language hint ('sql' / 'shell' / 'python' /
                    None). When set, patterns with a DIFFERENT language_hint
                    are skipped. When None, all patterns apply regardless of
                    their hint.

    Returns:
        A `ClassifierVerdict` whose `is_destructive` is True if any pattern
        fires (or the PoC exceeds `MAX_POC_LENGTH`). The verdict's
        `suggested_evidence_state` is `EvidenceState.MANUAL_REQUIRED` when
        destructive, else `EvidenceState.PENDING`.

    Notes:
        - Empty / whitespace-only PoCs return a SAFE verdict — the sandbox
          will simply fail to execute them.
        - Oversized PoCs return a DESTRUCTIVE verdict with
          pattern_name='oversized' to short-circuit T-03-03-04 regex
          backtracking risk.
        - SQL comments (`/* ... */` block + `-- ...` line) are stripped
          before pattern matching to mitigate T-03-03-01 comment-injection
          evasion.
    """
    # Empty / whitespace-only PoCs are not destructive — there's nothing to
    # execute. The sandbox layer handles the "empty PoC" case separately.
    if not poc or not poc.strip():
        return ClassifierVerdict(
            is_destructive=False,
            pattern_name=None,
            rationale="empty PoC",
            suggested_evidence_state=EvidenceState.PENDING,
        )

    # T-03-03-04: oversized PoCs short-circuit to MANUAL_REQUIRED to avoid
    # catastrophic regex backtracking.
    if len(poc) > MAX_POC_LENGTH:
        return ClassifierVerdict(
            is_destructive=True,
            pattern_name="oversized",
            rationale=(
                f"PoC exceeds {MAX_POC_LENGTH} bytes ({len(poc)} bytes) — "
                "refusing to classify, treat as manual."
            ),
            suggested_evidence_state=EvidenceState.MANUAL_REQUIRED,
        )

    # T-03-03-01: strip SQL comments for SQL pattern matching so embedded
    # `/*...*/` and `-- ...` cannot evade the registry. Stripped form is
    # ONLY used for SQL patterns — shell PoCs legitimately use `--flag`
    # arguments (e.g. `rm --recursive --force`, `sqlmap --drop`) that would
    # otherwise be eaten by the SQL line-comment regex.
    sql_normalized = _strip_sql_comments(poc)

    for pattern in DESTRUCTIVE_PATTERNS:
        # language hint is a FILTER, not a requirement: when the caller
        # pinned a language and the pattern hint disagrees, skip. When the
        # caller passed None we apply every pattern regardless of hint.
        if (
            pattern.language_hint
            and language
            and pattern.language_hint != language
        ):
            continue
        # Only SQL patterns see the comment-stripped form; every other
        # language matches against the raw PoC.
        candidate = sql_normalized if pattern.language_hint == "sql" else poc
        if pattern.regex.search(candidate):
            return ClassifierVerdict(
                is_destructive=True,
                pattern_name=pattern.name,
                rationale=pattern.rationale,
                suggested_evidence_state=EvidenceState.MANUAL_REQUIRED,
            )

    return ClassifierVerdict(
        is_destructive=False,
        pattern_name=None,
        rationale="no destructive pattern matched",
        suggested_evidence_state=EvidenceState.PENDING,
    )
