"""Regression tests for the security-books downloader helpers.

The downloader script lives outside the package (tools/) so it doesn't
have a stable import path; we load it as a module by file path. The
helpers under test are pure (no I/O), so this stays fast.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def dl():
    spec = importlib.util.spec_from_file_location(
        "dl_mod", REPO / "tools" / "download-security-books.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_sanitize_strips_pathsep(dl):
    assert dl.sanitize_path_component("foo/bar") == "foo_bar"
    assert dl.sanitize_path_component("foo:bar") == "foo_bar"
    assert dl.sanitize_path_component("..hidden") == "..hidden".strip(" .")
    assert dl.sanitize_path_component('a"b<c>d|e?f*') == "a_b_c_d_e_f_"


def test_sanitize_caps_length(dl):
    s = "x" * 300
    out = dl.sanitize_path_component(s, max_len=200)
    assert len(out) == 200
    assert out == "x" * 200


def test_sanitize_returns_untitled_for_empty(dl):
    assert dl.sanitize_path_component("") == "untitled"
    assert dl.sanitize_path_component("...") == "untitled"
    assert dl.sanitize_path_component("   ") == "untitled"


def test_attachment_regex_matches_pdf(dl):
    body = (
        '..."cgeU":[["Bug Bounty Playbook.pdf",[["a","attachment:'
        'fa46f3f7-5f0b-4eea-9f3f-45f3ec0512a3:Bug_Bounty_Playbook.pdf"]]]]...'
    )
    matches = list(dl.ATTACHMENT_RE.finditer(body))
    assert len(matches) == 1
    assert matches[0].group(1) == "fa46f3f7-5f0b-4eea-9f3f-45f3ec0512a3"
    assert matches[0].group(2) == "Bug_Bounty_Playbook.pdf"


def test_extract_file_attachment_finds_pdf(dl):
    page_id = "2301d398-8558-806c-88a5-fdfb712b4674"
    chunk = {
        "recordMap": {
            "block": {
                page_id: {
                    "spaceId": "091f6dde-6289-4f05-bb46-5e76d0772968",
                    "value": {
                        "value": {
                            "id": page_id,
                            "properties": {
                                "Ame@": [["Bug Hunting"]],
                                "cgeU": [[
                                    "Bug Bounty Playbook.pdf",
                                    [["a", "attachment:fa46f3f7-5f0b-4eea-9f3f-45f3ec0512a3:Bug_Bounty_Playbook.pdf"]],
                                ]],
                                "title": [["Bug Bounty Playbook"]],
                            },
                        },
                    },
                },
            },
        },
    }
    result = dl.extract_file_attachment(chunk, page_id)
    assert result is not None
    space_id, file_id, filename = result
    assert space_id == "091f6dde-6289-4f05-bb46-5e76d0772968"
    assert file_id == "fa46f3f7-5f0b-4eea-9f3f-45f3ec0512a3"
    assert filename == "Bug_Bounty_Playbook.pdf"


def test_extract_file_attachment_skips_non_pdf(dl):
    """Page-cover attachments (jpg/png) must be skipped — the property scan
    keeps walking until it finds a .pdf."""
    page_id = "test-id"
    chunk = {
        "recordMap": {
            "block": {
                page_id: {
                    "spaceId": "space",
                    "value": {
                        "value": {
                            "id": page_id,
                            "properties": {
                                "cover": [[
                                    "preview.jpg",
                                    [["a", "attachment:abcd1234-1234-1234-1234-abcdefabcdef:preview.jpg"]],
                                ]],
                                "file": [[
                                    "Real_Book.pdf",
                                    [["a", "attachment:1234abcd-5678-90ab-cdef-1234567890ab:Real_Book.pdf"]],
                                ]],
                            },
                        },
                    },
                },
            },
        },
    }
    space_id, file_id, filename = dl.extract_file_attachment(chunk, page_id)
    assert filename == "Real_Book.pdf"
    assert file_id == "1234abcd-5678-90ab-cdef-1234567890ab"


def test_extract_file_attachment_returns_none_when_no_pdf(dl):
    chunk = {"recordMap": {"block": {"id": {"value": {"value": {"properties": {}}}}}}}
    assert dl.extract_file_attachment(chunk, "id") is None


def test_extract_file_attachment_returns_none_for_missing_block(dl):
    chunk = {"recordMap": {"block": {}}}
    assert dl.extract_file_attachment(chunk, "missing-id") is None
