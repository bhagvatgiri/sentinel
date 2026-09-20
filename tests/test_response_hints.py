"""Hermetic tests for response_hints.extract_response_hints / format_hints."""
from __future__ import annotations
import pytest

from sentinel.agent.pentest.response_hints import extract_response_hints, format_hints


def test_no_hints_in_plain_success_response():
    assert extract_response_hints('{"ok": true, "data": {"users": []}}', {}) == []


def test_extracts_use_x_instead_hint_slack_oauth():
    """The exact pattern from the 2026-XX-XX ExampleChat incident."""
    body = ('{"ok":false,"error":"refresh_token_invalid",'
            '"response_metadata":{"messages":['
            '"Refresh token provided corresponds to oauth developer token, '
            'please try using oauth.v2.access instead"]}}')
    hints = extract_response_hints(body, {})
    use = [h for h in hints if h.kind == "use_alternative_endpoint"]
    assert use, f"no use_alternative_endpoint hint in {hints!r}"
    assert "oauth.v2.access" in use[0].suggested_action
    assert "please try using" in use[0].source_snippet.lower()


def test_extracts_use_path_instead_hint():
    """Suggestion that is a path (leading slash) must be captured too."""
    hints = extract_response_hints('{"error":"please try using /api/v2/token instead"}', {})
    use = [h for h in hints if h.kind == "use_alternative_endpoint"]
    assert use and use[0].suggested_action == "/api/v2/token"


def test_extracts_method_not_allowed_hint():
    hints = extract_response_hints('{"error": "Method not allowed, use POST instead of GET"}', {})
    h = [x for x in hints if x.kind == "use_alternative_method"]
    assert h and "POST" in h[0].suggested_action.upper()


def test_extracts_deprecated_endpoint_hint():
    body = '{"error": "This endpoint is deprecated. Migrate to /api/v2/users before 2026-12-01."}'
    hints = extract_response_hints(body, {})
    h = [x for x in hints if x.kind == "deprecated_endpoint"]
    assert h and "/api/v2/users" in h[0].suggested_action


def test_extracts_required_parameter_hint():
    body = '{"error":"missing_field","detail":"Parameter \'client_id\' is required for this grant type"}'
    hints = extract_response_hints(body, {})
    h = [x for x in hints if x.kind == "missing_required_parameter"]
    assert h and "client_id" in h[0].suggested_action


def test_extracts_authorization_header_hint():
    hints = extract_response_hints('{"error": "Provide Authorization: Bearer <token> header"}', {})
    assert any(h.kind == "missing_auth_header" for h in hints)


def test_extracts_redirect_via_location_header():
    hints = extract_response_hints(
        "<html>301 Moved</html>",
        {"Location": "https://example.com/api/v3/new-endpoint"},
    )
    h = [x for x in hints if x.kind == "follow_redirect"]
    assert h and "/api/v3/new-endpoint" in h[0].suggested_action


def test_extracts_www_authenticate_header_hint():
    hints = extract_response_hints("unauthorized", {"WWW-Authenticate": 'Bearer realm="api"'})
    assert any(h.kind == "missing_auth_header" for h in hints)


def test_extracts_oauth_grant_type_hint():
    body = ('{"error":"unsupported_grant_type","error_description":'
            '"Use authorization_code or client_credentials for this client"}')
    hints = extract_response_hints(body, {})
    h = [x for x in hints if x.kind == "use_alternative_grant_type"]
    assert h
    assert "authorization_code" in h[0].suggested_action


def test_multiple_hints_returned_in_one_response():
    body = '{"error":"Method not allowed, use POST instead. Also try the /api/v2/login endpoint."}'
    hints = extract_response_hints(body, {})
    kinds = {h.kind for h in hints}
    assert "use_alternative_method" in kinds
    assert "try_alternative_path" in kinds


def test_hint_source_snippet_truncated():
    body = "x" * 50 + "use /api/v2/foo instead of /api/v1/foo" + "y" * 5000
    for h in extract_response_hints(body, {}):
        assert len(h.source_snippet) <= 200


def test_extractor_returns_empty_for_non_string_body():
    assert extract_response_hints(None, {}) == []
    assert extract_response_hints(b"binary\x00\x01", {}) == []
    assert extract_response_hints(12345, {}) == []


def test_non_string_body_still_yields_header_hints():
    hints = extract_response_hints(None, {"Location": "https://x/api/v2"})
    assert any(h.kind == "follow_redirect" for h in hints)


def test_format_hints_empty_is_empty_string():
    assert format_hints([]) == ""


def test_format_hints_concise():
    body = '{"error":"refresh_token_invalid","messages":["please try using oauth.v2.access instead"]}'
    formatted = format_hints(extract_response_hints(body, {}))
    assert "SERVER HINTS" in formatted.upper()
    assert "oauth.v2.access" in formatted
    assert len(formatted) < 1500
