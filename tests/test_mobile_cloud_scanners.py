"""Tests for B-Mobile + B-Cloud scanner integrations.

Network calls + binary invocations are mocked; tests focus on:

- Module imports cleanly (no missing fields / Severity references)
- check_available behaviour (binary missing → False)
- Severity mapping for MobSF response shapes
- Argument plumbing for the bucket-keyword + AWS-profile flows
- _ensure_binary helper for cloud scanners
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from sentinel.scanners import mobile, cloud
from sentinel.core.findings import Severity


# --------------------------------------------------------------------------
# Mobile
# --------------------------------------------------------------------------


def test_mobile_severity_mapping_includes_high_warning_info():
    assert mobile._MOBSF_SEVERITY_MAP["high"] is Severity.HIGH
    assert mobile._MOBSF_SEVERITY_MAP["warning"] is Severity.MEDIUM
    assert mobile._MOBSF_SEVERITY_MAP["info"] is Severity.INFO


def test_mobile_mobsf_check_available_no_creds(monkeypatch):
    # No env vars + no config file → ScannerError → check returns False.
    monkeypatch.delenv("MOBSF_API_URL", raising=False)
    monkeypatch.delenv("MOBSF_API_KEY", raising=False)
    monkeypatch.setattr(mobile.Path, "is_file", lambda self: False)
    ok, info = mobile.MobSFScanner.check_available()
    assert not ok
    assert "MOBSF_API_URL" in info or "credentials" in info.lower()


def test_apkleaks_run_missing_apk_raises(tmp_path):
    from sentinel.scanners.base import ScannerError
    scope = mock.MagicMock()
    with pytest.raises(ScannerError):
        mobile.ApkleaksScanner().run(scope, str(tmp_path / "nope.apk"))


def test_mobsf_findings_extracts_code_analysis_entries():
    scanner = mobile.MobSFScanner()
    fake_report = {
        "code_analysis": {
            "weak_crypto": {
                "MD5_USED": {
                    "severity": "warning",
                    "metadata": {"description": "MD5 used", "cwe": "CWE-327"},
                },
            },
        },
        "manifest_analysis": {
            "manifest_findings": [
                {"rule": "exported_activity",
                 "severity": "high", "description": "exported intent"},
            ],
        },
    }
    findings = list(scanner._mobsf_findings(fake_report, Path("/tmp/fake.apk")))
    titles = [f.title for f in findings]
    assert any("weak_crypto" in t for t in titles)
    assert any("exported_activity" in t or "manifest" in t for t in titles)


# --------------------------------------------------------------------------
# Cloud
# --------------------------------------------------------------------------


def test_cloud_ensure_binary_returns_false_for_missing(monkeypatch):
    monkeypatch.setattr(cloud.shutil, "which", lambda _: None)
    ok, msg = cloud._ensure_binary("nonexistent-binary")
    assert not ok
    assert "not on PATH" in msg


def test_cloud_ensure_binary_returns_true_for_present(monkeypatch):
    monkeypatch.setattr(cloud.shutil, "which", lambda _: "/usr/local/bin/X")
    ok, path = cloud._ensure_binary("X")
    assert ok
    assert path == "/usr/local/bin/X"


def test_s3scanner_requires_keywords():
    from sentinel.scanners.base import ScannerError
    scope = mock.MagicMock()
    with pytest.raises(ScannerError):
        cloud.S3ScannerScanner().run(scope, "ignored", keywords=[])


def test_cloudenum_requires_keywords():
    from sentinel.scanners.base import ScannerError
    scope = mock.MagicMock()
    with pytest.raises(ScannerError):
        cloud.CloudEnumScanner().run(scope, "ignored", keywords=[])


def test_prowler_requires_aws_profile():
    from sentinel.scanners.base import ScannerError
    scope = mock.MagicMock()
    with pytest.raises(ScannerError):
        cloud.ProwlerScanner().run(scope, "ignored", aws_profile="")


def test_cloudfox_requires_aws_profile():
    from sentinel.scanners.base import ScannerError
    scope = mock.MagicMock()
    with pytest.raises(ScannerError):
        cloud.CloudFoxScanner().run(scope, "ignored", aws_profile="")


def test_check_available_consistent_for_all_cloud_scanners(monkeypatch):
    monkeypatch.setattr(cloud.shutil, "which", lambda _: None)
    for cls in (cloud.S3ScannerScanner, cloud.CloudEnumScanner,
                cloud.ProwlerScanner, cloud.CloudFoxScanner):
        ok, _ = cls.check_available()
        assert ok is False
