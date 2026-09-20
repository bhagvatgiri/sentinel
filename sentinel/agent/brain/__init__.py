"""Brain-Growth Agent.

Autonomous research agent whose job is to grow Sentinel's local knowledge
corpus (the "Brain") on a given topic. Searches the web, fetches sources,
deduplicates against existing knowledge, embeds new chunks into Chroma.

Use via `sentinel brain-grow --topic "<X>" --corpus-dir ~/sentinel-corpus`.
"""

from sentinel.agent.brain.loop import BrainAgent, BrainConfig

__all__ = ["BrainAgent", "BrainConfig"]
