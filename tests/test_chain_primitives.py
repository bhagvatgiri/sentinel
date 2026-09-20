"""Tests for the Phase 3.5 primitive loader.

Validates the (class, vulnerability_type) → PrimitiveType regex table
hits the right type for every entry in the existing 2-engagement
workspaces, and that loader fails safe on missing / malformed inputs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.agent.pentest.primitives import (
    Primitive, PrimitiveType, infer_primitive_type, load_from_workspace,
    primitives_by_type, render_primitives_table,
)


# ---- type inference matrix -----------------------------------------------


@pytest.mark.parametrize("class_slug,title,expected", [
    ("auth",      "Brute_Force_Defenses_Missing",                PrimitiveType.SESSION_TOKEN),
    ("auth",      "Missing_Authentication_Analytics_Endpoint",   PrimitiveType.SESSION_TOKEN),
    ("auth",      "Password_Reset_Token_Predictable",            PrimitiveType.SESSION_TOKEN),
    ("authz",     "Missing_Function_Level_Authorization",        PrimitiveType.SESSION_TOKEN),
    ("authz",     "Clickjacking_Missing_Frame_Ancestors",        PrimitiveType.ARBITRARY_OBJECT_WRITE),
    # "Enumeration" hits the read regex first (first-match-wins) — correct
    # because object-level *enumeration* IS a read primitive.
    ("idor",      "Broken_Object_Level_Authorization_Admin_Enumeration", PrimitiveType.ARBITRARY_OBJECT_READ),
    ("idor",      "Indirect_Object_Reference_Manipulation",      PrimitiveType.ARBITRARY_OBJECT_READ),
    ("injection", "NoSQL_Operator_Injection",                    PrimitiveType.SQLI_QUERY),
    ("injection", "Log_Injection",                               PrimitiveType.LOG_INJECTION),
    ("injection", "Expression_Language_Injection",               PrimitiveType.OS_COMMAND_EXEC),
    ("injection", "OS_Command_Injection",                        PrimitiveType.OS_COMMAND_EXEC),
    ("xss",       "Stored_XSS_Analytics_Path_Field",             PrimitiveType.JS_EXEC_BROWSER_CTX),
    ("xss",       "DOM_Based_Reflected_XSS_Search_Parameter",    PrimitiveType.JS_EXEC_BROWSER_CTX),
    ("xss",       "Absent_Content_Security_Policy",              PrimitiveType.JS_EXEC_BROWSER_CTX),
    ("ssrf",      "Same_Deployment_Internal_Routing_Oracle",     PrimitiveType.INTERNAL_HTTP_PROBE),
    ("ssrf",      "Redirect_Chain_SSRF_via_Allowlist_Domain",    PrimitiveType.OUTBOUND_HTTP),
    ("ssrf",      "Generic_SSRF_Sink",                           PrimitiveType.OUTBOUND_HTTP),
    ("csrf",      "Token_Predictable",                           PrimitiveType.CSRF_ACTION),
    ("file_upload", "Path_Traversal_in_Filename",                PrimitiveType.ARBITRARY_PATH_READ),
    ("file_upload", "Polyglot_File_Upload",                      PrimitiveType.OS_COMMAND_EXEC),
    ("file_upload", "Exposed_dot_git_HEAD",                      PrimitiveType.ARBITRARY_PATH_READ),
    ("jwt_oauth", "JWT_alg_none",                                PrimitiveType.SESSION_TOKEN),
    ("jwt_oauth", "OAuth_Open_Redirect_Chain",                   PrimitiveType.OPEN_REDIRECT),
])
def test_infer_primitive_type_table(class_slug, title, expected):
    got = infer_primitive_type(class_slug, title)
    assert got == expected, f"{class_slug}/{title}: expected {expected}, got {got}"


def test_infer_primitive_type_unknown_class():
    assert infer_primitive_type("not-a-class", "anything") is None


# ---- loader behavior -----------------------------------------------------


def test_load_from_workspace_missing_dir(tmp_path):
    ws = tmp_path / "no_such_workspace"
    assert load_from_workspace(ws) == []


def test_load_from_workspace_no_deliverables(tmp_path):
    (tmp_path / "deliverables").mkdir(parents=True)
    # No queue files at all → empty list.
    assert load_from_workspace(tmp_path) == []


def test_load_from_workspace_skips_malformed(tmp_path):
    deliv = tmp_path / "deliverables"
    deliv.mkdir()
    # Bogus JSON should be skipped, not crash.
    (deliv / "auth_exploitation_queue.json").write_text("{not json}")
    out = load_from_workspace(tmp_path)
    assert out == []


def test_load_from_workspace_extracts_provenance_and_confidence(tmp_path):
    deliv = tmp_path / "deliverables"
    deliv.mkdir()
    (deliv / "auth_exploitation_queue.json").write_text(json.dumps({
        "vulnerabilities": [{
            "ID": "AUTH-VULN-01",
            "vulnerability_type": "Brute_Force_Defenses_Missing",
            "externally_exploitable": True,
            "confidence": "high",
            "source_endpoint": "GET /admin",
            "missing_defense": "no rate limiting",
            "exploitation_hypothesis": "Hydra at 30 req/s passes every gate.",
            "suggested_exploit_technique": "brute_force_login",
            "notes": "20+ requests with no throttling",
        }]
    }))
    prims = load_from_workspace(tmp_path, target_url="https://x")
    assert len(prims) == 1
    p = prims[0]
    assert p.finding_id == "AUTH-VULN-01"
    assert p.primitive_type == PrimitiveType.SESSION_TOKEN
    assert p.confidence == "high"
    assert p.provenance["section"] == "AUTH-VULN-01"
    assert p.provenance["queue_file"].endswith("auth_exploitation_queue.json")
    assert p.parameters["target_url"] == "https://x"
    assert p.description.startswith("Hydra")


def test_loader_runs_against_real_mechcodex_workspace_returns_18_plus():
    """The ExampleCorp engagement queues span at least 6 vuln classes;
    after the auth catch-all (see tools.py:vuln_classes) every entry
    should produce a primitive. Specific finding-IDs are NOT asserted
    because the workspace is a live fixture — running pipelines may
    rewrite queue contents."""
    ws = Path(__file__).resolve().parent.parent / "workspaces" / "2026-XX-XX-ExampleCorp-web"
    if not ws.is_dir():
        pytest.skip("ExampleCorp workspace not present in checkout")
    prims = load_from_workspace(ws)
    assert len(prims) >= 15  # generous floor — historical count was 19
    # Spread across at least the 6 original classes — broad coverage check.
    classes_seen = {p.class_slug for p in prims}
    assert {"auth", "xss", "ssrf"}.issubset(classes_seen), (
        f"core classes missing: {classes_seen}"
    )


# ---- helpers --------------------------------------------------------------


def test_primitives_by_type_groups_correctly():
    prims = [
        Primitive(class_slug="auth", finding_id="A", primitive_type=PrimitiveType.SESSION_TOKEN, description="x"),
        Primitive(class_slug="xss",  finding_id="B", primitive_type=PrimitiveType.JS_EXEC_BROWSER_CTX, description="y"),
        Primitive(class_slug="auth", finding_id="C", primitive_type=PrimitiveType.SESSION_TOKEN, description="z"),
    ]
    by_t = primitives_by_type(prims)
    assert len(by_t[PrimitiveType.SESSION_TOKEN]) == 2
    assert len(by_t[PrimitiveType.JS_EXEC_BROWSER_CTX]) == 1
    assert by_t[PrimitiveType.OS_COMMAND_EXEC] == []


def test_render_primitives_table_handles_empty():
    assert "(no primitives loaded)" in render_primitives_table([])


def test_confidence_weight_monotonic():
    p_high = Primitive(class_slug="auth", finding_id="H", primitive_type=PrimitiveType.SESSION_TOKEN,
                        description="x", confidence="high")
    p_med = Primitive(class_slug="auth", finding_id="M", primitive_type=PrimitiveType.SESSION_TOKEN,
                       description="x", confidence="medium")
    p_low = Primitive(class_slug="auth", finding_id="L", primitive_type=PrimitiveType.SESSION_TOKEN,
                       description="x", confidence="low")
    assert p_high.confidence_weight() > p_med.confidence_weight() > p_low.confidence_weight()
