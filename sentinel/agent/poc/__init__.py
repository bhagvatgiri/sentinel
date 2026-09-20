"""PoC generation, classification, and sandbox-execution primitives for Phase 3.

This package houses the building blocks for the Phase 3 verification loop
(see `.planning/phases/03-exploit-verification-loop/` for the requirement spec,
VERIFY-01..08):

- Plan 03-03 ships the **classifier** — a pure-function gate that the Phase 3
  sandbox calls BEFORE invoking subprocess.run on any agent-generated PoC. The
  classifier returns a `ClassifierVerdict` whose `is_destructive` flag, when
  True, short-circuits the sandbox to `manual-required` with no execution
  attempt. False positives (flagging a borderline-safe PoC as manual-required)
  are the documented preferred failure mode — the asymmetric cost of
  auto-executing a destructive command makes the classifier deliberately
  permissive.
- Plan 03-04 will add the sandbox in this package; the sandbox will import
  `classify_destructive` from here and run its subprocess only when the
  verdict's `is_destructive` is False.
- Plan 03-05 wires the pipeline gate; Plan 03-06 renders the new evidence
  states in the dashboard.

Cross-plan note: this module ALSO absorbs Plan 03-04's T-03-04-08 (pickle /
yaml-unsafe-load) so the sandbox does not need duplicate deserialization
heuristics. The `python_pickle_loads` and `yaml_unsafe_load` patterns in
`DESTRUCTIVE_PATTERNS` are the single source of truth.
"""

from sentinel.agent.poc.classifier import (
    DESTRUCTIVE_PATTERNS,
    ClassifierVerdict,
    DestructivePattern,
    classify_destructive,
)
from sentinel.agent.poc.prompt import (
    ACCEPTED_LANGUAGES,
    MAX_PROMPT_LENGTH,
    POC_EXAMPLES,
    ParsedPoc,
    parse_poc_block,
    render_poc_prompt,
    render_poc_system_prefix,
    render_poc_finding_brief,
)
from sentinel.agent.poc.sandbox import (
    MAX_OUTPUT_BYTES,
    SANDBOX_TIMEOUT_SEC,
    SandboxResult,
    execute_poc,
)

__all__ = [
    # Plan 03-03 — classifier (VERIFY-02)
    "classify_destructive",
    "ClassifierVerdict",
    "DESTRUCTIVE_PATTERNS",
    "DestructivePattern",
    # Plan 03-04 Task 1 — prompt + parser (VERIFY-03)
    "render_poc_prompt",
    "render_poc_system_prefix",
    "render_poc_finding_brief",
    "parse_poc_block",
    "POC_EXAMPLES",
    "ParsedPoc",
    "ACCEPTED_LANGUAGES",
    "MAX_PROMPT_LENGTH",
    # Plan 03-04 Task 2 — execution sandbox (VERIFY-04 + VERIFY-06)
    "execute_poc",
    "SandboxResult",
    "SANDBOX_TIMEOUT_SEC",
    "MAX_OUTPUT_BYTES",
]
