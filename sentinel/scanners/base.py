"""Base scanner — every scanner inherits from this and runs through the same gate.

A scanner is a thin wrapper over an external tool (Semgrep, Trivy, etc.).
Subclasses implement:
  - tool_name: str
  - check_available() -> (bool, str): is the tool installed?
  - run(scope, target, **opts) -> list[Finding]: do the work

The scanner MUST call scope.authorize_*(target) before any work, and MUST
respect scope.rate_limit_rps for any tool that makes outbound network calls.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from sentinel.core.findings import Finding
from sentinel.core.scope import Scope


log = logging.getLogger(__name__)


class ScannerError(Exception):
    """Raised when a scanner fails for reasons unrelated to scope."""


class Scanner(ABC):
    tool_name: str = ""
    description: str = ""

    @classmethod
    def check_available(cls) -> tuple[bool, str]:
        """Default: tool is on PATH. Override for tools with custom install checks."""
        if not cls.tool_name:
            return False, f"{cls.__name__} has no tool_name"
        path = shutil.which(cls.tool_name)
        if path:
            return True, path
        return False, f"{cls.tool_name} not found on PATH"

    @abstractmethod
    def run(self, scope: Scope, target: str, **opts) -> list[Finding]:
        ...

    # ---- helpers --------------------------------------------------------

    def _run_subprocess(
        self,
        argv: list[str],
        cwd: Optional[Path] = None,
        timeout: int = 600,
        check_rc: bool = False,
    ) -> subprocess.CompletedProcess:
        """Run an external scanner. Captures stdout/stderr.

        check_rc=False because most scanners return non-zero when findings exist.
        """
        log.info("running: %s", " ".join(argv))
        try:
            return subprocess.run(
                argv,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=check_rc,
            )
        except FileNotFoundError as e:
            raise ScannerError(f"Tool not found: {argv[0]}") from e
        except subprocess.TimeoutExpired as e:
            raise ScannerError(f"Tool timed out after {timeout}s: {argv[0]}") from e
        except subprocess.CalledProcessError as e:
            raise ScannerError(f"{argv[0]} exited {e.returncode}: {e.stderr[:500]}") from e

    def _parse_json(self, text: str) -> dict | list:
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise ScannerError(f"Could not parse {self.tool_name} JSON output: {e}") from e


class RateLimiter:
    """Token-bucket-ish limiter. Used by live scanners. Best-effort, not strict."""

    def __init__(self, rps: float):
        self.min_interval = 1.0 / max(rps, 0.1)
        self._last = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        delta = now - self._last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self._last = time.monotonic()
