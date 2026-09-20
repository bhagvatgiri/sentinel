"""Smoke tests for B2 — GraphQL introspect + field-auth diff.

Tests pure helpers (_summarize_schema, _zero_args_query, _parse_headers_arg)
+ ALL_TOOLS export shape. Network-side functions (_post_graphql,
graphql_introspect, graphql_field_auth_diff) are exercised by integration
tests against a real GraphQL server (out of scope for unit tests).
"""

from __future__ import annotations

import json

from sentinel.agent.pentest.graphql_tool import (
    _INTROSPECTION_QUERY,
    _parse_headers_arg,
    _summarize_schema,
    _zero_args_query,
    ALL_TOOLS,
)


def test_all_tools_export():
    assert isinstance(ALL_TOOLS, list)
    assert len(ALL_TOOLS) == 2
    names = {t.name for t in ALL_TOOLS}
    assert "graphql_introspect" in names
    assert "graphql_field_auth_diff" in names


def test_introspection_query_is_well_formed():
    """The standard introspection query must include the canonical
    fragments — every GraphQL server recognizes this exact shape."""
    assert "IntrospectionQuery" in _INTROSPECTION_QUERY
    assert "__schema" in _INTROSPECTION_QUERY
    assert "queryType" in _INTROSPECTION_QUERY
    assert "mutationType" in _INTROSPECTION_QUERY
    assert "FullType" in _INTROSPECTION_QUERY
    assert "TypeRef" in _INTROSPECTION_QUERY


# ──────────── _parse_headers_arg ─────────────────────────────────────────

def test_parse_headers_empty_returns_empty_dict():
    assert _parse_headers_arg("") == {}
    assert _parse_headers_arg(None or "") == {}
    assert _parse_headers_arg("   ") == {}


def test_parse_headers_valid_json():
    h = _parse_headers_arg('{"Authorization": "Bearer abc"}')
    assert h == {"Authorization": "Bearer abc"}


def test_parse_headers_coerces_to_strings():
    """Defensive: even if values come through as ints, coerce to str."""
    h = _parse_headers_arg('{"X-Count": 5}')
    assert h == {"X-Count": "5"}


def test_parse_headers_invalid_json_returns_empty():
    """Malformed JSON shouldn't crash — return empty dict."""
    assert _parse_headers_arg("not json") == {}
    assert _parse_headers_arg("{") == {}
    assert _parse_headers_arg('{"oops"}') == {}


def test_parse_headers_non_dict_returns_empty():
    assert _parse_headers_arg('["a", "b"]') == {}
    assert _parse_headers_arg('"just a string"') == {}


# ──────────── _summarize_schema ──────────────────────────────────────────

def test_summarize_schema_handles_empty_response():
    """No __schema field in response → return error indicator."""
    s = _summarize_schema({})
    assert "error" in s


def test_summarize_schema_extracts_query_root():
    intro = {
        "data": {
            "__schema": {
                "queryType": {"name": "MyQuery"},
                "mutationType": None,
                "subscriptionType": None,
                "types": [
                    {"name": "MyQuery", "kind": "OBJECT", "fields": [
                        {"name": "user", "args": [{"name": "id"}], "isDeprecated": False, "description": "fetch user"},
                        {"name": "posts", "args": [], "isDeprecated": False, "description": "list posts"},
                    ]},
                ],
            },
        },
    }
    s = _summarize_schema(intro)
    assert s["query_type"] == "MyQuery"
    assert s["mutation_type"] is None
    assert s["queries_count"] == 2
    names = {q["name"] for q in s["queries"]}
    assert names == {"user", "posts"}
    user_q = next(q for q in s["queries"] if q["name"] == "user")
    assert user_q["args"] == ["id"]


def test_summarize_schema_extracts_mutations():
    intro = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {"name": "Query", "kind": "OBJECT", "fields": []},
                    {"name": "Mutation", "kind": "OBJECT", "fields": [
                        {"name": "createUser", "args": [{"name": "input"}], "isDeprecated": False, "description": "create"},
                        {"name": "deleteUser", "args": [{"name": "id"}], "isDeprecated": True, "description": "delete"},
                    ]},
                ],
            },
        },
    }
    s = _summarize_schema(intro)
    assert s["mutations_count"] == 2
    delete_m = next(m for m in s["mutations"] if m["name"] == "deleteUser")
    assert delete_m["deprecated"] is True


def test_summarize_schema_excludes_internal_types():
    """Built-in introspection types (__Schema, __Type, __Field, etc.)
    must NOT be reported as 'custom types' to the operator."""
    intro = {
        "data": {
            "__schema": {
                "queryType": {"name": "Q"},
                "mutationType": None,
                "types": [
                    {"name": "Q", "kind": "OBJECT", "fields": []},
                    {"name": "User", "kind": "OBJECT", "fields": []},
                    {"name": "__Schema", "kind": "OBJECT", "fields": []},
                    {"name": "__Type", "kind": "OBJECT", "fields": []},
                    {"name": "__Field", "kind": "OBJECT", "fields": []},
                ],
            },
        },
    }
    s = _summarize_schema(intro)
    assert "User" in s["custom_types"]
    assert "__Schema" not in s["custom_types"]
    assert "__Type" not in s["custom_types"]


def test_summarize_schema_caps_lists_at_50():
    """Pathological huge schemas don't blow the prompt size."""
    fields = [{"name": f"f{i}", "args": [], "isDeprecated": False,
                "description": ""} for i in range(200)]
    intro = {
        "data": {
            "__schema": {
                "queryType": {"name": "Q"},
                "mutationType": None,
                "types": [{"name": "Q", "kind": "OBJECT", "fields": fields}],
            },
        },
    }
    s = _summarize_schema(intro)
    assert s["queries_count"] == 200  # the COUNT is exact
    assert len(s["queries"]) == 50    # but the LIST is capped


# ──────────── _zero_args_query ──────────────────────────────────────────

def test_zero_args_query_basic():
    q = _zero_args_query("user", [])
    assert "query" in q
    assert "user" in q
    assert "__typename" in q


def test_zero_args_query_with_args():
    """Even when the field has required args, we generate a no-args probe
    (server returns validation error consistently across both sessions)."""
    q = _zero_args_query("posts", ["limit", "offset"])
    assert "posts" in q
    # Args don't appear in the probe — by design
    assert "limit" not in q
    assert "offset" not in q


def test_zero_args_query_field_name_in_alias():
    """The query alias includes the field name for trace clarity in logs."""
    q = _zero_args_query("getUser", [])
    assert "AutoProbe_getUser" in q


def test_event_styles_register_graphql_events():
    from sentinel.web.event_styles import EVENT_STYLES
    for kind in ("graphql_introspect_run", "graphql_introspection_open",
                  "graphql_field_auth_scan", "graphql_field_no_authz"):
        assert kind in EVENT_STYLES, f"missing event style: {kind}"
    assert EVENT_STYLES["graphql_field_no_authz"]["chip"] == "critical"
