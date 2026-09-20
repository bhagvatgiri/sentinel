"""Multi-provider model router.

Two kinds of model use in Sentinel:

1. **Phase-driving (Claude Agent SDK loop):** vuln/exploit/recon agents
   need a frontier model with reliable tool-use. We use Claude (Sonnet
   for most, Opus for cross-correlation). This routes via
   `ClaudeAgentOptions(model=...)`.

2. **One-shot tasks (Ollama):** narrative summaries, dedup judgments,
   screenshot descriptions, fix suggestions. Heavy volume, no tool-use
   needed. Local Ollama is faster + free.

The router carves the responsibility cleanly:
    router.phase_model(phase) -> Claude model name (string)
    router.task_model(task) -> (provider, model) tuple

Provider envs (Bedrock / Vertex / custom_base_url) flow through to the
SDK via env vars — see `apply_provider_env()`.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Callable, Literal, Optional


log = logging.getLogger(__name__)


Provider = Literal["claude", "ollama"]


# --- Phase routing (Claude Agent SDK loop) -------------------------------

# Phase name → Claude model. Sonnet 4.6 is the workhorse; Opus 4.7 for
# correlation (best chain reasoning). report uses Haiku via task_model
# below since it's mostly file-read + write — Sonnet is overkill there.
DEFAULT_PHASE_MODELS: dict[str, str] = {
    # recon stays Sonnet — enumeration/surface-mapping doesn't need Opus.
    "recon":            "claude-sonnet-4-6",
    # 2026-XX-XX (the operator): vuln + exploit moved to OPUS. The multi-step exploit
    # logic + chain-of-finding reasoning in these phases is where Opus clearly
    # beats Sonnet; quality of verified exploits is the priority. (Cost: Opus is
    # ~5x Sonnet — these are the heaviest phases, so this is the big cost lever.
    # Dial back per-class here, or via agents.yml override, if budget demands.)
    "vuln:auth":        "claude-opus-4-7",
    "vuln:authz":       "claude-opus-4-7",
    "vuln:idor":        "claude-opus-4-7",
    "vuln:injection":   "claude-opus-4-7",
    "vuln:xss":         "claude-opus-4-7",
    "vuln:ssrf":        "claude-opus-4-7",
    "exploit:auth":     "claude-opus-4-7",
    "exploit:authz":    "claude-opus-4-7",
    "exploit:idor":     "claude-opus-4-7",
    "exploit:injection": "claude-opus-4-7",
    "exploit:xss":      "claude-opus-4-7",
    "exploit:ssrf":     "claude-opus-4-7",
    # Wave 1 (2026-XX-XX) classes — same Opus tier as the rest of vuln/exploit.
    "vuln:csrf":        "claude-opus-4-7",
    "vuln:file_upload": "claude-opus-4-7",
    "vuln:jwt_oauth":   "claude-opus-4-7",
    "exploit:csrf":     "claude-opus-4-7",
    "exploit:file_upload": "claude-opus-4-7",
    "exploit:jwt_oauth": "claude-opus-4-7",
    # Zero-Day class (2026-XX-XX). Novel/design-inherent discovery is the most
    # reasoning-heavy phase: fingerprint → enumerate known-design surface →
    # differential variant/control → mechanism-from-framework-design → verified
    # PoC. Multi-step mechanism reasoning is exactly Opus's edge, so pin both
    # explicitly (the vuln:/exploit: prefix fallback below would also catch
    # these, but explicit entries document the intent + survive a fallback
    # refactor).
    "vuln:novel":       "claude-opus-4-7",
    "exploit:novel":    "claude-opus-4-7",
    # Phase 3.5 — chain-attack executor. Composition reasoning is the
    # same shape as correlation, so same opus tier.
    "chain_execute":    "claude-opus-4-7",
    "correlation":      "claude-opus-4-7",
    "report":           "claude-haiku-4-5",
}


# --- Task routing (one-shot Ollama) --------------------------------------

@dataclass
class TaskModel:
    provider: Provider
    model: str
    description: str = ""


# Task name → which Ollama model to use for one-shot calls. The router
# falls back to llama3.1:8b for any task name that isn't here.
DEFAULT_TASK_MODELS: dict[str, TaskModel] = {
    "summarize_deliverable":  TaskModel("ollama", "mistral-nemo:12b",
                                         "narrative summarization for the report agent"),
    "dedup_check":            TaskModel("ollama", "gemma2:9b",
                                         "fast yes/no judgments on similarity"),
    "code_recon":             TaskModel("ollama", "qwen2.5-coder:7b",
                                         "code-specialized analysis"),
    "screenshot_describe":    TaskModel("ollama", "llava:13b",
                                         "vision — describes WAF challenge pages and forms"),
    "suggest_fix":            TaskModel("ollama", "mistral-nemo:12b",
                                         "remediation suggestions per finding"),
    "exec_summary":           TaskModel("ollama", "mistral-nemo:12b",
                                         "executive summary writing"),
    "reasoning_check":        TaskModel("ollama", "deepseek-r1:8b",
                                         "second-opinion on chain analysis"),
    "general":                TaskModel("ollama", "llama3.1:8b",
                                         "general fallback"),
}


# Phase-level Ollama fallback: which Ollama model to use when a Claude
# pipeline phase fails (rate-limited, budget-exhausted, network-blip, or
# operator picked --phase-backend=ollama). Only the phases listed here
# are wired through the failover bridge today; heavier agent-loop phases
# (recon, vuln:*, exploit:*, chain_execute) still raise on Claude
# failure because they need MCP-tool subagent support the brain Ollama
# loop doesn't have yet.
DEFAULT_FALLBACK_PHASE_MODELS: dict[str, str] = {
    "report":      "qwen2.5:32b-instruct-q4_K_M",
    "correlation": "qwen2.5:32b-instruct-q4_K_M",
}


def fallback_for_phase(phase_name: str) -> Optional[str]:
    """Return the Ollama model to fail-over to for this phase, or None
    if the phase isn't wired for failover yet."""
    return DEFAULT_FALLBACK_PHASE_MODELS.get(phase_name)


@dataclass
class ModelRouter:
    phase_models: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_PHASE_MODELS))
    task_models: dict[str, TaskModel] = field(default_factory=lambda: dict(DEFAULT_TASK_MODELS))
    # Operator override: pin everything to one model (handy for cost control).
    pinned_phase_model: Optional[str] = None
    # Wave 9 — Opus teacher per-phase supervisor. Default review-only is the
    # cheapest mode that still produces RLAIF training-corpus tuples.
    teacher_model: str = "claude-opus-4-7"
    teacher_budget_usd: float = 30.0
    teacher_mode: str = "review-only"  # full | review-only | plan-only | off

    def is_teacher_enabled(self, hook: str) -> bool:
        if self.teacher_mode == "off":
            return False
        if hook == "plan":
            return self.teacher_mode in ("full", "plan-only")
        if hook == "critique":
            return self.teacher_mode == "full"
        if hook == "review":
            return self.teacher_mode in ("full", "review-only")
        return False

    def phase_model(self, phase: str) -> str:
        """Return the Claude model name for a pipeline phase."""
        if self.pinned_phase_model:
            return self.pinned_phase_model
        model = self.phase_models.get(phase)
        if model is not None:
            return model
        # 2026-XX-XX (the operator): vuln/exploit reasoning runs on Opus. Cover any
        # class not explicitly mapped above (crlf, websocket, future classes)
        # so the whole vuln:/exploit: family routes to Opus consistently.
        if phase.startswith(("vuln:", "exploit:")):
            return "claude-opus-4-7"
        return "claude-sonnet-4-6"

    def task_model(self, task: str) -> TaskModel:
        """Return the (provider, model) for a one-shot task."""
        return self.task_models.get(task, self.task_models["general"])

    def all_phase_models_unique(self) -> set[str]:
        return set(self.phase_models.values()) | (
            {self.pinned_phase_model} if self.pinned_phase_model else set()
        )

    def all_task_models(self) -> list[TaskModel]:
        return list({(t.provider, t.model): t for t in self.task_models.values()}.values())


# --- Provider env wiring -------------------------------------------------

# Default location for the Anthropic-format proxy.
# 2026-XX-XX: switched from LiteLLM (port 4001) to custom shim (port 4002).
# LiteLLM hung after 30-44 min of long agent loops; our minimal shim has
# per-chunk keepalive + flushes every byte. Start via
# tools/serving/start-anthropic-shim.sh --bg
# LiteLLM proxy still works as backup if needed (port 4001).
SILICONFLOW_PROXY_URL = "http://127.0.0.1:4002"
SILICONFLOW_PROXY_KEY = "sk-sentinel-local-only"  # not strictly used by shim


def apply_provider_env(*, bedrock: bool = False, vertex: bool = False,
                       custom_base_url: Optional[str] = None) -> None:
    """Some Claude Agent SDK installs need explicit provider env vars to
    route to AWS Bedrock / GCP Vertex / a LiteLLM-style proxy. Set them
    here so the SDK picks them up.

    For Bedrock: needs AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
    already present in env (we don't mint them; operator provides).
    For Vertex: needs GOOGLE_APPLICATION_CREDENTIALS path + GCP_PROJECT.
    For custom URL: pass it via CLAUDE_CODE_BASE_URL (LiteLLM proxy convention).
    """
    if bedrock:
        os.environ["CLAUDE_CODE_USE_BEDROCK"] = "1"
        log.info("provider: routing Claude calls to AWS Bedrock")
    if vertex:
        os.environ["CLAUDE_CODE_USE_VERTEX"] = "1"
        log.info("provider: routing Claude calls to GCP Vertex")
    if custom_base_url:
        os.environ["CLAUDE_CODE_BASE_URL"] = custom_base_url
        log.info("provider: routing Claude calls to %s", custom_base_url)


def enable_siliconflow_routing(proxy_url: str = SILICONFLOW_PROXY_URL,
                                 proxy_key: str = SILICONFLOW_PROXY_KEY) -> None:
    """Route Claude SDK calls through the local anthropic-shim that
    forwards to SiliconFlow.

    CRITICAL ENV VARS (both required — verified 2026-XX-XX):
      - CLAUDE_CODE_BASE_URL — read by some claude CLI subsystems
      - ANTHROPIC_BASE_URL   — read by the actual Anthropic SDK client
                               inside claude CLI for /v1/messages routing
                               (DISCOVERED to be the controlling one;
                               CLAUDE_CODE_BASE_URL alone is ignored)

    Also unsets ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN so claude CLI
    sends empty bearer (our shim doesn't require master_key auth).
    Setting an invalid API key triggers claude CLI's local auth check
    before any network call, breaking the routing.

    Prerequisite: `bash tools/serving/start-anthropic-shim.sh --bg`
    """
    apply_provider_env(custom_base_url=proxy_url)
    # ANTHROPIC_BASE_URL is the one the Anthropic SDK inside claude CLI
    # actually reads. Without this, claude CLI ignores
    # CLAUDE_CODE_BASE_URL and hits api.anthropic.com directly.
    os.environ["ANTHROPIC_BASE_URL"] = proxy_url
    # Unset auth env vars so claude CLI sends empty bearer (proxy ignores)
    for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        if k in os.environ:
            del os.environ[k]
    log.info("SiliconFlow routing enabled (proxy: %s, "
              "CLAUDE_CODE_BASE_URL + ANTHROPIC_BASE_URL set, auth unset)",
              proxy_url)


def siliconflow_proxy_is_up(proxy_url: str = SILICONFLOW_PROXY_URL,
                              proxy_key: str = SILICONFLOW_PROXY_KEY,
                              timeout_s: float = 2.0) -> bool:
    """Return True if the LiteLLM proxy is responding on `proxy_url`."""
    import urllib.error
    import urllib.request
    try:
        req = urllib.request.Request(
            f"{proxy_url}/v1/models",
            headers={"Authorization": f"Bearer {proxy_key}"},
        )
        with urllib.request.urlopen(req, timeout=timeout_s) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


# --- BUG-01 (2026-XX-XX): Qwen empty-args observability ------------------
#
# When `tools/serving/_shim_repair._repair_tool_args` falls through all 5
# heuristic passes and gives up returning `"{}"`, it increments this
# module-level counter. The dashboard / `sentinel state` will later poll
# `get_qwen_empty_args_counter()` to surface regressions in future Qwen
# model upgrades. Reset via `reset_qwen_empty_args_counter()` in tests.
qwen_empty_args_observed: int = 0


def reset_qwen_empty_args_counter() -> None:
    """Reset the Qwen empty-args fall-through counter to zero. Used for
    test isolation — never call from production code paths."""
    global qwen_empty_args_observed
    qwen_empty_args_observed = 0


def get_qwen_empty_args_counter() -> int:
    """Return the current count of `_repair_tool_args` pass-6 fall-throughs
    observed since process start (or since the last
    `reset_qwen_empty_args_counter()` call)."""
    return qwen_empty_args_observed


# --- BENCH-01 (2026-XX-XX): ModelRouter profile registry ------------------
#
# Phase 2 introduces named profiles that flip the entire Claude-tier agent
# loop between providers. Two profiles ship today; Plan 02-04 may add a
# third 'siliconflow-deepseek-r1' profile after the parity benchmark lands.
#
# Profile callables MUST be idempotent — the parity-eval harness flips
# profiles 2N times per run (once per profile per target). Each callable
# should:
#   1. mutate env vars to its target state, and
#   2. update the module-level _CURRENT_PROFILE so current_model_profile()
#      reflects what was just applied.
#
# Callers MUST go through `apply_model_profile()` rather than invoking
# entries directly — the helper handles the unknown-profile error path
# and the bookkeeping. Direct dict access is for introspection only
# (dashboard dropdowns, CLI choice lists in Plan 02-04).

_CURRENT_PROFILE: str = "anthropic-baseline"


def _apply_anthropic_baseline() -> None:
    """Restore the env to clean Anthropic routing.

    Clears the SiliconFlow shim env vars (ANTHROPIC_BASE_URL,
    CLAUDE_CODE_BASE_URL) so the Anthropic SDK inside claude CLI routes
    to api.anthropic.com directly. Does NOT mint an ANTHROPIC_API_KEY
    — if the operator's shell has one, the SDK picks it up via its
    existing precedence; if absent, the scan fails loudly which is the
    correct behavior (silent fall-through to a misconfigured provider
    is the bug we're avoiding).
    """
    global _CURRENT_PROFILE
    proxy = os.environ.get("SENTINEL_ANTHROPIC_PROXY", "").strip()
    if proxy:
        # Keepalive-proxy PASSTHROUGH (2026-XX-XX, Mode-B transport-freeze fix):
        # route the CLI's Anthropic calls through a local proxy
        # (tools/serving/anthropic-keepalive-proxy.py) that uses force_close (no
        # idle pooled connection for the network to drop) + a sock_read timeout
        # (mid-stream stall → fast downstream close → fast retry). Unlike the
        # SiliconFlow shim this is a PURE passthrough to api.anthropic.com, so we
        # KEEP the operator's auth (the proxy forwards it) — set the base-URL
        # vars but do NOT unset ANTHROPIC_API_KEY/AUTH_TOKEN.
        os.environ["CLAUDE_CODE_BASE_URL"] = proxy
        os.environ["ANTHROPIC_BASE_URL"] = proxy
        _CURRENT_PROFILE = "anthropic-baseline"
        log.info("model profile: anthropic-baseline via keepalive proxy %s", proxy)
        return
    for k in ("ANTHROPIC_BASE_URL", "CLAUDE_CODE_BASE_URL"):
        os.environ.pop(k, None)
    _CURRENT_PROFILE = "anthropic-baseline"
    log.info("model profile: anthropic-baseline (SiliconFlow routing env cleared)")


def _apply_siliconflow_qwen_235b() -> None:
    """Route Claude SDK calls through the local anthropic-shim that
    forwards to SiliconFlow models.

    Current shim mapping (anthropic-shim.py MODEL_ALIASES, as of 2026-XX-XX
    post COST-03 alias revision):

      claude-sonnet-4-6  -> Qwen/Qwen3.6-35B-A3B        (enable_thinking=False)
      claude-opus-4-7    -> deepseek-ai/DeepSeek-R1
      claude-haiku-4-5   -> Qwen/Qwen3-Coder-30B-A3B-Instruct

    Sonnet alias revised 2026-XX-XX (COST-03) — see .planning/phases/
    02-siliconflow-qwen-235b-parity-benchmark/post-mortem/
    2026-XX-XX-cost-finding.md. The prior Qwen3.5-397B-A17B billed
    25-40% MORE than the Anthropic Sonnet baseline on the parity bench;
    Qwen3.6-35B-A3B is a 3B-active MoE that drives the agent loop at
    materially lower per-token cost while preserving tool-call quality
    (verified by the live smoke test in tests/test_shim_sonnet_alias_smoke.py).

    Profile name kept as "siliconflow-qwen-235b" for stable CLI / config
    identifier — the original Qwen3-235B-A22B-Instruct-2507 returned HTTP
    403 "Model disabled" on the operator's account, but renaming the profile
    would invalidate the ModelRouter state file and existing eval JSONs.

    Delegates to the existing `enable_siliconflow_routing()` helper so
    the env-wiring contract has a single source of truth (the harness
    test, plus the existing `--cloud siliconflow` code path, both
    depend on that helper's exact behavior).
    """
    global _CURRENT_PROFILE
    enable_siliconflow_routing(SILICONFLOW_PROXY_URL, SILICONFLOW_PROXY_KEY)
    _CURRENT_PROFILE = "siliconflow-qwen-235b"
    log.info("model profile: siliconflow-qwen-235b (proxy %s)", SILICONFLOW_PROXY_URL)


MODEL_PROFILES: dict[str, Callable[[], None]] = {
    "anthropic-baseline": _apply_anthropic_baseline,
    "siliconflow-qwen-235b": _apply_siliconflow_qwen_235b,
}


def apply_model_profile(name: str) -> None:
    """Activate a named ModelRouter profile.

    Looks up the profile in `MODEL_PROFILES` and invokes its callable.
    Raises `ValueError` (with both the bad name and the valid options)
    if the profile is unknown — keeps the CLI flag's error message
    self-explanatory without spelunking the source.
    """
    fn = MODEL_PROFILES.get(name)
    if fn is None:
        valid = sorted(MODEL_PROFILES.keys())
        raise ValueError(
            f"unknown model profile: {name!r}. valid profiles: {valid}"
        )
    fn()


def current_model_profile() -> str:
    """Return the name of the profile most recently applied.

    Defaults to 'anthropic-baseline' if `apply_model_profile()` has not
    been called this process. The parity-eval harness reads this to
    label each run in the eval JSON's `runs[i].profile` field.
    """
    return _CURRENT_PROFILE


# --- BENCH-09 (Plan 02-04, 2026-XX-XX): persistent default-profile -------
#
# After a parity-eval pass, `flip_default(eval_json)` writes
# ~/.sentinel/model_profile_default.txt with the proven profile. ModelRouter
# reads it ONCE at module import time and exposes it as
# `DEFAULT_MODEL_PROFILE`. Callers go through `apply_default_model_profile()`
# to apply it.
#
# Read is lazy-via-try-except so a partial install (e.g. an older intermediate
# tree without the default_switch module) still imports the model_router
# cleanly and falls back to 'anthropic-baseline'.

try:
    from sentinel.benchmark.default_switch import read_current_default as _read_default
    DEFAULT_MODEL_PROFILE: str = _read_default()
except Exception as _e:  # noqa: BLE001 — defensive: any failure → baseline
    log.warning(
        "model_router: could not read persisted default profile (%s); "
        "falling back to 'anthropic-baseline'.", _e
    )
    DEFAULT_MODEL_PROFILE = "anthropic-baseline"


def apply_default_model_profile() -> None:
    """Apply `DEFAULT_MODEL_PROFILE` (the profile persisted by the most
    recent successful parity-eval). If the state file was absent at
    module import, this is a no-op apply of 'anthropic-baseline'."""
    apply_model_profile(DEFAULT_MODEL_PROFILE)
