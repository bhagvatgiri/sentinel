"""Sentinel — defensive security agent for authorized engagements.

Scope-gated. Every active operation is checked against a signed scope file
loaded at startup; out-of-scope targets are refused and the refusal is logged.
"""

__version__ = "0.1.0"
