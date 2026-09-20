"""Multi-turn conversation state for the /chat page.

A `ConversationSession` is a list of `Turn`s plus minimal session metadata
(id, model, source filters). Sessions persist as append-only JSONL at
`~/.sentinel/chat_sessions/<sid>.jsonl` so an interrupted session can be
re-loaded after a restart and audited later.

`detect_engagement_scope(message)` is the smart-default hook that closes
Task #60 — when a user types "our recent finding" we auto-select the
past-engagements source filter on the next turn so the model isn't
RAG'd against the global 325k-chunk corpus.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


CHAT_SESSIONS_DIR = Path.home() / ".sentinel" / "chat_sessions"


# Pronouns and phrases that signal the user is asking about THEIR own
# engagement data, not the global cybersec corpus. Keep the list narrow:
# false positives auto-flip the filter and surprise the user, false
# negatives just leave the existing chip selection alone.
_ENGAGEMENT_SCOPE_RE = re.compile(
    r"\b(our|my|this engagement|this scan|the scan|recent finding|recent vulnerability|we found|we have)\b",
    re.IGNORECASE,
)


def detect_engagement_scope(message: str) -> bool:
    """Return True if the message reads like an engagement-scoped question."""
    if not message:
        return False
    return bool(_ENGAGEMENT_SCOPE_RE.search(message))


# Patterns that mean "the user is greeting/acknowledging, not asking a
# substantive question". These are the cases where naive RAG produces
# nonsense — embedding "hey" pulls random chunks like PATT's long-A LFI
# payloads, and the model then describes those payloads instead of just
# replying to the greeting. When this fires, skip retrieval entirely.
_LOW_INFO_PATTERNS = [
    re.compile(r"^\s*(hi|hello|hey|yo|sup|hiya|howdy|greetings)\b[\s!?.]*$", re.IGNORECASE),
    re.compile(r"^\s*(thanks|thx|ty|cheers|got it|ok|okay|cool|nice|great)\b[\s!?.]*$", re.IGNORECASE),
    re.compile(r"^\s*(bye|goodbye|cya|see you|later)\b[\s!?.]*$", re.IGNORECASE),
    re.compile(r"^\s*(yes|no|sure|nope|yep|yeah|maybe)\b[\s!?.]*$", re.IGNORECASE),
    re.compile(r"^\s*\?+\s*$"),  # just "?" or "??"
]


def is_low_info_query(message: str) -> bool:
    """Return True if the message is too generic for retrieval to help.

    Greetings, acknowledgments, single-word affirmations — these pull
    semantically irrelevant chunks because the embedding has no signal.
    The model then either ignores the chunks or, worse, describes them
    as if they were the answer.

    Also catches very short messages (≤ 3 non-space chars), since those
    are almost always low-information whether they match the pattern
    list or not.
    """
    if not message:
        return True
    stripped = message.strip()
    if len(stripped) <= 3:
        return True
    return any(p.match(stripped) for p in _LOW_INFO_PATTERNS)


@dataclass
class Turn:
    """One turn in the conversation. `role` is 'user' or 'assistant'."""
    role: str
    content: str
    ts: float = field(default_factory=time.time)
    # Citations attached to assistant turns. Each citation is a dict
    # {title, source, url, distance} mirroring RetrievedChunk.short_citation.
    citations: list[dict] = field(default_factory=list)
    # The exact retrieval query used for THIS turn (debug / audit).
    retrieval_query: Optional[str] = None
    # Per-turn model identifier so a session that switched backends
    # mid-flight stays auditable.
    model: Optional[str] = None

    def to_jsonl(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict) -> "Turn":
        return cls(
            role=d["role"],
            content=d["content"],
            ts=float(d.get("ts", time.time())),
            citations=list(d.get("citations") or []),
            retrieval_query=d.get("retrieval_query"),
            model=d.get("model"),
        )


@dataclass
class ConversationSession:
    """A single chat thread. Persists to <CHAT_SESSIONS_DIR>/<id>.jsonl.

    The first line of the file is a session header with metadata. Each
    subsequent line is a single Turn. Append-only — no edits, no deletes.
    """
    id: str
    created_at: float = field(default_factory=time.time)
    model: str = "llama3.1:8b"
    source_filters: list[str] = field(default_factory=list)
    title: str = ""
    history: list[Turn] = field(default_factory=list)

    @staticmethod
    def new(model: str = "llama3.1:8b", source_filters: Optional[list[str]] = None) -> "ConversationSession":
        # Human-readable id: 2026-XX-XXT2308-XXXX. Sortable + non-guessable.
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M")
        sid = f"{ts}-{secrets.token_hex(3)}"
        return ConversationSession(
            id=sid,
            model=model,
            source_filters=list(source_filters or []),
        )

    @property
    def path(self) -> Path:
        return CHAT_SESSIONS_DIR / f"{self.id}.jsonl"

    def append_turn(self, turn: Turn) -> None:
        """Append a turn in memory AND to disk in one shot."""
        self.history.append(turn)
        CHAT_SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        path = self.path
        # If the file is empty, write the header first.
        if not path.exists() or path.stat().st_size == 0:
            with path.open("a", encoding="utf-8") as f:
                f.write(self._header_line() + "\n")
        with path.open("a", encoding="utf-8") as f:
            f.write(turn.to_jsonl() + "\n")

    def _header_line(self) -> str:
        return json.dumps({
            "_header": True,
            "id": self.id,
            "created_at": self.created_at,
            "model": self.model,
            "source_filters": self.source_filters,
            "title": self.title,
        }, ensure_ascii=False)

    def update_title(self, title: str) -> None:
        """Set/update the title. Persisted as a new header-update line.

        We don't rewrite the file — header-update lines are appended; load()
        takes the LAST header line as authoritative. Append-only audit trail.
        """
        self.title = title
        if not self.path.exists():
            CHAT_SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(self._header_line() + "\n")

    @classmethod
    def load(cls, sid: str) -> Optional["ConversationSession"]:
        path = CHAT_SESSIONS_DIR / f"{sid}.jsonl"
        if not path.exists():
            return None
        header = None
        turns: list[Turn] = []
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("_header"):
                    header = obj  # last header wins (allows title updates)
                    continue
                turns.append(Turn.from_dict(obj))
        if header is None:
            return None
        return cls(
            id=header["id"],
            created_at=float(header.get("created_at", time.time())),
            model=header.get("model", "llama3.1:8b"),
            source_filters=list(header.get("source_filters") or []),
            title=header.get("title", ""),
            history=turns,
        )

    @classmethod
    def list_all(cls) -> list["ConversationSession"]:
        """List sessions, newest first. Heavy — only call from the index page.

        Loads each session header without iterating turns, so this stays
        cheap even with hundreds of sessions.
        """
        if not CHAT_SESSIONS_DIR.exists():
            return []
        out: list[ConversationSession] = []
        for path in CHAT_SESSIONS_DIR.glob("*.jsonl"):
            sid = path.stem
            sess = cls.load(sid)
            if sess is not None:
                out.append(sess)
        out.sort(key=lambda s: s.created_at, reverse=True)
        return out
