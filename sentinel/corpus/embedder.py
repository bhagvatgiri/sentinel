"""Ollama embeddings client.

Default model is `nomic-embed-text` (768 dims, ~100MB, very fast on CPU).
Pull it once on the user's machine: `ollama pull nomic-embed-text`.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Iterable, Optional


log = logging.getLogger(__name__)


class OllamaEmbedder:
    def __init__(
        self,
        host: str = "http://localhost:11434",
        model: str = "nomic-embed-text",
        timeout: int = 60,
        retries: int = 3,
    ):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.retries = retries

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.host}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    return False
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", [])]
                # Match either exact or "model:tag"
                return any(self.model == m or m.startswith(self.model + ":") for m in models)
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            return False

    def embed_one(self, text: str) -> Optional[list[float]]:
        body = json.dumps({"model": self.model, "prompt": text}).encode("utf-8")
        for attempt in range(self.retries):
            try:
                req = urllib.request.Request(
                    f"{self.host}/api/embeddings",
                    data=body,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    emb = data.get("embedding")
                    if isinstance(emb, list) and emb:
                        return [float(x) for x in emb]
                    log.warning("ollama returned empty embedding")
                    return None
            except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
                log.warning("embed attempt %d/%d failed: %s", attempt + 1, self.retries, e)
                time.sleep(min(2 ** attempt, 8))
        return None

    def embed_batch(self, texts: list[str]) -> list[Optional[list[float]]]:
        # Ollama doesn't accept batched embeddings yet — do sequential calls.
        return [self.embed_one(t) for t in texts]
