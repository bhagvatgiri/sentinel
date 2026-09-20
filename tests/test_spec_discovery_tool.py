"""Smoke tests for B9 — OpenAPI / Swagger / Postman spec discovery."""

from __future__ import annotations

import json

from sentinel.agent.pentest.spec_discovery_tool import (
    _SPEC_PATHS,
    _is_openapi_json,
    _summarize_spec,
    ALL_TOOLS,
)


def test_all_tools_export():
    assert isinstance(ALL_TOOLS, list)
    assert len(ALL_TOOLS) == 1
    assert ALL_TOOLS[0].name == "discover_api_spec"


def test_spec_paths_cover_major_patterns():
    """Defensive: cover OpenAPI 3, Swagger 2, Postman, Spring Boot."""
    must_have = {
        "/openapi.json",       # OpenAPI 3.x
        "/swagger.json",       # Swagger 2.0
        "/v3/api-docs",        # Springdoc
        "/api-docs",           # Swagger UI default
        "/postman.json",
    }
    missing = must_have - set(_SPEC_PATHS)
    assert not missing, f"missing spec paths: {missing}"
    assert len(_SPEC_PATHS) >= 15


def test_is_openapi_json_detects_openapi3():
    body = json.dumps({"openapi": "3.0.3",
                        "info": {"title": "Test", "version": "1.0"},
                        "paths": {}})
    is_spec, spec_type = _is_openapi_json(body)
    assert is_spec is True
    assert spec_type == "openapi3"


def test_is_openapi_json_detects_swagger2():
    body = json.dumps({"swagger": "2.0",
                        "info": {"title": "Test", "version": "1.0"},
                        "paths": {}})
    is_spec, spec_type = _is_openapi_json(body)
    assert is_spec is True
    assert spec_type == "swagger2"


def test_is_openapi_json_detects_postman():
    body = json.dumps({
        "info": {"name": "My API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [{"name": "Endpoint 1"}],
    })
    is_spec, spec_type = _is_openapi_json(body)
    assert is_spec is True
    assert spec_type == "postman"


def test_is_openapi_json_rejects_non_spec():
    """Generic HTML / non-JSON / random JSON → not a spec."""
    assert _is_openapi_json("<html><body>Hello</body></html>") == (False, "")
    assert _is_openapi_json("") == (False, "")
    assert _is_openapi_json('{"foo": "bar"}') == (False, "")
    assert _is_openapi_json("just text") == (False, "")


def test_is_openapi_json_handles_short_input():
    """Pathologically tiny bodies — fast-fail."""
    assert _is_openapi_json("x") == (False, "")
    assert _is_openapi_json("{}") == (False, "")


def test_summarize_spec_extracts_endpoints():
    body = json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "Demo API", "version": "1.0"},
        "paths": {
            "/users": {"get": {}, "post": {}},
            "/users/{id}": {"get": {}, "delete": {}},
            "/admin/secrets": {"get": {}},
        },
    })
    s = _summarize_spec(body, "openapi3")
    assert s["title"] == "Demo API"
    assert s["version"] == "1.0"
    assert s["type"] == "openapi3"
    endpoints = s["endpoints"]
    assert "GET /users" in endpoints
    assert "POST /users" in endpoints
    assert "GET /admin/secrets" in endpoints


def test_summarize_spec_extracts_auth_schemes_openapi3():
    body = json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "X", "version": "1"},
        "paths": {},
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"},
                "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            },
        },
    })
    s = _summarize_spec(body, "openapi3")
    schemes = s["auth_schemes"]
    assert any("bearerAuth" in a for a in schemes)
    assert any("apiKey" in a for a in schemes)


def test_summarize_spec_extracts_postman_endpoints():
    body = json.dumps({
        "info": {"name": "T", "schema": "https://schema.getpostman.com/x"},
        "item": [
            {
                "name": "ep1",
                "request": {"method": "GET", "url": {"raw": "https://x.com/users", "path": ["users"]}},
            },
            {
                "name": "ep2",
                "request": {"method": "POST", "url": {"raw": "https://x.com/admin", "path": ["admin"]}},
            },
        ],
    })
    s = _summarize_spec(body, "postman")
    assert len(s["endpoints"]) == 2
    assert any("GET" in ep for ep in s["endpoints"])
    assert any("POST" in ep for ep in s["endpoints"])


def test_summarize_spec_handles_invalid_json():
    s = _summarize_spec("not json", "openapi3")
    assert s == {}


def test_event_styles_register_spec_events():
    from sentinel.web.event_styles import EVENT_STYLES
    assert "api_spec_scan" in EVENT_STYLES
    assert "api_spec_found" in EVENT_STYLES
    assert EVENT_STYLES["api_spec_found"]["chip"] == "high"
