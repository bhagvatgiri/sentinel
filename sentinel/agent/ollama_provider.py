"""Direct Ollama HTTP client for one-shot tasks.

Separate from `claude-agent-sdk` (which drives the agent loop with tool
use). This is for non-loop, single-shot calls: deliverable summarization,
dedup judgments, fix-suggestion generation, image description for
screenshots.

Stays a thin wrapper — uses Ollama's HTTP API directly via httpx so we
don't pull in the heavy `ollama` Python package.

Public API:
    OllamaClient(host).generate(model, prompt, system, **kwargs) -> str
    OllamaClient(host).vision(model, prompt, image_path) -> str
    OllamaClient(host).embed(model, texts) -> list[list[float]]
    OllamaClient(host).chat(model, messages, tools=...) -> dict   # async, tool-use
"""

from __future__ import annotations

import base64
import logging
from pathlib import Path
from typing import Optional

import httpx


log = logging.getLogger(__name__)


class OllamaClient:
    def __init__(self, host: str = "http://localhost:11434", timeout: float = 120.0):
        self.host = host.rstrip("/")
        self.timeout = timeout

    def generate(
        self,
        model: str,
        prompt: str,
        *,
        system: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: Optional[int] = None,
        stop: Optional[list[str]] = None,
    ) -> str:
        """One-shot text generation. Returns the model's response string.

        Raises httpx.HTTPError on transport failure; returns "" on empty
        model output (which is rare but happens with bad prompts).
        """
        body: dict = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system:
            body["system"] = system
        if max_tokens:
            body["options"]["num_predict"] = max_tokens
        if stop:
            body["options"]["stop"] = stop

        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(f"{self.host}/api/generate", json=body)
            r.raise_for_status()
            data = r.json()
            return data.get("response", "") or ""

    def vision(self, model: str, prompt: str, image_path: Path | str) -> str:
        """Multimodal generation — model must support vision (llava, etc.).
        Reads the image, base64-encodes, sends to Ollama.
        """
        path = Path(image_path)
        if not path.is_file():
            raise FileNotFoundError(f"image not found: {path}")
        b64 = base64.b64encode(path.read_bytes()).decode()
        body = {
            "model": model,
            "prompt": prompt,
            "images": [b64],
            "stream": False,
            "options": {"temperature": 0.3},
        }
        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(f"{self.host}/api/generate", json=body)
            r.raise_for_status()
            return r.json().get("response", "") or ""

    def embed(self, model: str, texts: list[str]) -> list[list[float]]:
        """Embedding API. Returns one vector per input text."""
        out: list[list[float]] = []
        with httpx.Client(timeout=self.timeout) as client:
            for text in texts:
                r = client.post(
                    f"{self.host}/api/embeddings",
                    json={"model": model, "prompt": text},
                )
                r.raise_for_status()
                vec = r.json().get("embedding") or []
                out.append(vec)
        return out

    async def chat(
        self,
        model: str,
        messages: list[dict],
        *,
        tools: Optional[list[dict]] = None,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        num_ctx: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> dict:
        """POST /api/chat with optional tool-use. Returns raw response JSON
        so the caller can inspect message.tool_calls / message.content.

        `num_ctx` overrides the served context window. Critical for agent loops:
        many models ship no num_ctx in their modelfile and Ollama then defaults
        to 4096 tokens — far too small to hold an agent's system prompt + tool
        schemas + accumulating tool results, which silently truncates context
        (the model loses the thread) and eventually errors.

        `tools` follows Ollama's OpenAI-compatible function format:
            [{"type": "function",
              "function": {"name": "...", "description": "...",
                           "parameters": {"type":"object", "properties": {...},
                                          "required": [...]}}}]
        Async (uses httpx.AsyncClient) so it slots into the brain loop's
        async event loop without blocking.
        """
        body: dict = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if tools:
            body["tools"] = tools
        if max_tokens:
            body["options"]["num_predict"] = max_tokens
        if num_ctx:
            body["options"]["num_ctx"] = num_ctx
        async with httpx.AsyncClient(timeout=timeout or self.timeout) as client:
            r = await client.post(f"{self.host}/api/chat", json=body)
            r.raise_for_status()
            return r.json()

    def is_available(self, model: Optional[str] = None) -> bool:
        """Quick health check. If model is given, also verify it's pulled."""
        try:
            with httpx.Client(timeout=5.0) as client:
                r = client.get(f"{self.host}/api/tags")
                r.raise_for_status()
                if model is None:
                    return True
                tags = r.json().get("models", []) or []
                names = {m["name"] for m in tags}
                return model in names or any(n.startswith(model + ":") for n in names)
        except Exception:
            return False

    def list_models(self) -> list[dict]:
        try:
            with httpx.Client(timeout=5.0) as client:
                r = client.get(f"{self.host}/api/tags")
                r.raise_for_status()
                return r.json().get("models", []) or []
        except Exception:
            return []
