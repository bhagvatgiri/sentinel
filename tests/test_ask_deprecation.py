"""Tests for the /ask soft-deprecation step (Task #63 conservative half).

Phase A.5 in the plan calls for hard deletion of /ask once /chat has
soaked for 2-3 days. This test set covers the intermediate state:

  - /ask still renders (direct URLs + bookmarks don't 404)
  - The deprecation banner is present and points to /chat
  - The "Ask" entry is no longer in the nav (users default to /chat)
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from sentinel.web.app import create_app


def test_ask_page_still_renders():
    """Direct GET /ask returns 200 — bookmarks and external links keep working."""
    client = TestClient(create_app())
    r = client.get("/ask")
    assert r.status_code == 200


def test_ask_page_shows_deprecation_banner():
    client = TestClient(create_app())
    r = client.get("/ask")
    assert "deprecated" in r.text.lower()
    assert "/chat" in r.text
    # Legacy badge on the heading
    assert "(legacy)" in r.text


def test_nav_does_not_include_ask_link():
    """The 'Ask' top-nav entry has been removed in favor of 'Chat'."""
    client = TestClient(create_app())
    r = client.get("/")
    # Find the nav block and check for "Ask" as a link label.
    # The nav uses literal label "Ask" only in the link case; the
    # deprecation banner's "Ask the corpus" heading lives on /ask, not /.
    nav_section = r.text.split("</header>")[0]
    # The nav literal "Ask" link should be gone — check the icon name pattern
    # used in base.html: ('/ask', 'message-square', 'Ask').
    assert ">Ask<" not in nav_section


def test_nav_includes_chat_link():
    """Chat is the recommended default — must appear in the nav."""
    client = TestClient(create_app())
    r = client.get("/")
    nav_section = r.text.split("</header>")[0]
    assert ">Chat<" in nav_section
    assert "/chat" in nav_section
