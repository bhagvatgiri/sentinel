"""Conversation-aware RAG retrieval.

Wraps `sentinel/rag/retriever.py:Retriever` with query construction that
considers the most recent user turns. Without this, follow-up questions
like "what about for that CVE specifically?" lose their referent and
retrieve random chunks. With this, the retrieval query is built from
the last 1-2 user messages PLUS the current message, so context carries.

Caps history at 2 prior user turns to keep the embedded query short
(embeddings are 1500-char chunks; an over-long query dilutes signal).
"""

from __future__ import annotations

from typing import Optional

from sentinel.rag.conversation import ConversationSession, Turn, is_low_info_query
from sentinel.rag.retriever import Retriever, RetrievedChunk


# How many prior user turns to fold into the retrieval query. 2 is empirical:
# > 2 starts to dilute and conflate distinct subtopics; 1 misses obvious
# referents like "what about that CVE?" needing the previous-but-one turn.
_MAX_PRIOR_USER_TURNS = 2

# Cosine-distance threshold above which we consider a chunk "not actually
# relevant" and drop it from the context. Chroma uses cosine distance:
# 0.0 = identical, ~0.3 = strongly related, ~0.5 = loosely related,
# ~1.0+ = unrelated. Anything > 0.5 in our corpus has historically been
# noise (random chunks that just happen to embed nearby). We err on the
# side of "no context > wrong context" — better for the model to say
# "I don't know" than to confidently answer from irrelevant chunks.
_DISTANCE_THRESHOLD = 0.5


class ConversationRetriever:
    def __init__(self, retriever: Retriever):
        self.retriever = retriever

    def build_query(self, session: ConversationSession, current_message: str) -> str:
        """Construct the retrieval query from current + recent user turns.

        Format: "<prior_user_2>\n<prior_user_1>\n<current_message>"
        Truncates each component to 400 chars. Assistant text is NEVER
        included — it's model output, not user intent.
        """
        prior: list[str] = []
        for turn in reversed(session.history):
            if turn.role != "user":
                continue
            prior.append(turn.content[:400])
            if len(prior) >= _MAX_PRIOR_USER_TURNS:
                break
        prior.reverse()
        components = prior + [current_message[:400]]
        return "\n".join(c.strip() for c in components if c.strip())

    def retrieve_for_turn(
        self,
        session: ConversationSession,
        current_message: str,
        top_k: int = 5,
        source_filter: Optional[list[str]] = None,
    ) -> tuple[str, list[RetrievedChunk]]:
        """Build query + retrieve. Returns (query_used, chunks).

        Two filters protect against the "garbage retrieval" failure mode
        where a low-info query like "hey" embeds near random chunks
        (e.g. PATT's long-A LFI payloads) and the model then describes
        those chunks as if they were the answer:

          1. If `current_message` is a greeting / acknowledgment / very
             short utterance, skip retrieval entirely (chunks=[]).
          2. Drop any chunk whose distance > _DISTANCE_THRESHOLD; these
             are not actually similar, the corpus just had no good match.

        Both filters are applied AFTER source_filter, so an operator who
        explicitly pinned past-engagements still gets their (possibly
        loose) hits — the design intent is to protect default queries,
        not override explicit user choices.
        """
        if is_low_info_query(current_message):
            return current_message, []
        query = self.build_query(session, current_message)
        sf = source_filter or session.source_filters or None
        chunks = self.retriever.retrieve(query, top_k=top_k, source_filter=sf)
        if not source_filter and not session.source_filters:
            # Only apply the distance threshold when no explicit filter
            # is pinned — pinned filters mean the user wants what's in
            # that source even if the embedding match is weak.
            chunks = [c for c in chunks if c.distance <= _DISTANCE_THRESHOLD]
        return query, chunks
