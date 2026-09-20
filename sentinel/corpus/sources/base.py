"""Source base class — every ingester implements this."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable, Optional

from sentinel.corpus.document import Document


log = logging.getLogger(__name__)


class Source(ABC):
    name: str = ""

    @abstractmethod
    def fetch(self, work_dir: Path) -> None:
        """Download/clone whatever this source needs into work_dir."""

    @abstractmethod
    def parse(self, work_dir: Path) -> Iterable[Document]:
        """Yield Documents from the fetched material."""

    # ---- helpers shared by sources --------------------------------------

    @staticmethod
    def git_clone(url: str, dest: Path, depth: int = 1) -> None:
        if dest.exists():
            shutil.rmtree(dest)
        cmd = ["git", "clone", "--depth", str(depth), "--quiet", url, str(dest)]
        log.info("cloning %s", url)
        subprocess.run(cmd, check=True)

    @staticmethod
    def http_get(url: str, dest: Path, timeout: int = 120) -> None:
        import urllib.request
        log.info("downloading %s", url)
        # Some CDNs (notably nvlpubs.nist.gov) 403 the default Python-urllib UA.
        req = urllib.request.Request(url, headers={"User-Agent": "sentinel-sec/0.2 (+https://github.com/sentinel-sec)"})
        with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as fh:
            shutil.copyfileobj(resp, fh)
