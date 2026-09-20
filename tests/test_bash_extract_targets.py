"""Regression tests for _extract_targets output-file handling.

Juice-shop spike (2026-XX-XX): `ffuf -u <url> -o ffuf.json` was blocked because
`ffuf.json` matched the hostname regex → `https://ffuf.json` → out-of-scope. This
silently broke EVERY scanner that writes an output file. The fix must skip
output-file values WITHOUT weakening real URL/host/IP detection.
"""

from sentinel.agent.pentest.bash_tool import _extract_targets as ext
from sentinel.agent.pentest.bash_tool import _extract_output_files as outs


class TestOutputFilesNotTargets:
    def test_ffuf_output_file_not_a_target(self):
        t = ext(["ffuf", "-u", "http://localhost:3000/FUZZ",
                 "-w", "/usr/share/seclists/raft.txt", "-of", "json", "-o", "ffuf.json"])
        assert "http://localhost:3000/FUZZ" in t
        assert "https://ffuf.json" not in t
        assert not any("raft.txt" in x for x in t)

    def test_nuclei_output_file_not_a_target(self):
        t = ext(["nuclei", "-u", "http://localhost:3000", "-severity", "high", "-o", "nuclei.json"])
        assert "http://localhost:3000" in t
        assert "https://nuclei.json" not in t

    def test_bare_output_filename_with_ext_skipped(self):
        # filename not behind a flag, but a known non-host extension
        t = ext(["sometool", "results.csv", "scan.xml", "report.html"])
        assert t == []


class TestScopeDetectionIntact:
    def test_out_of_scope_url_still_caught(self):
        assert "http://evil.com/x" in ext(["curl", "http://evil.com/x"])

    def test_bare_out_of_scope_host_still_caught(self):
        assert "https://evil.com" in ext(["nmap", "evil.com"])

    def test_url_after_output_flag_still_caught(self):
        # A real URL must still be caught even if it follows -o (the file-flag
        # skip only suppresses the bare-hostname branch, not URL/IP detection).
        assert "http://evil.com" in ext(["curl", "-o", "out.json", "http://evil.com"])

    def test_ip_still_caught(self):
        assert "https://10.0.0.5" in ext(["nmap", "10.0.0.5"])


class TestExtractOutputFiles:
    """Output-file readback: identify the -o values to feed back to the agent."""

    def test_ffuf_output_file(self):
        # the -o value, NOT the -w wordlist and NOT the -of format keyword
        o = outs(["ffuf", "-u", "http://x/FUZZ", "-w", "wl.txt", "-of", "json", "-o", "ffuf.json"])
        assert o == ["ffuf.json"]

    def test_nmap_output_file(self):
        assert outs(["nmap", "-oN", "scan.txt", "host"]) == ["scan.txt"]

    def test_katana_output_file(self):
        assert outs(["katana", "-u", "http://x", "-jc", "-o", "crawl.txt"]) == ["crawl.txt"]

    def test_no_output_flag(self):
        assert outs(["whatweb", "http://x"]) == []

    def test_flag_value_must_not_be_another_flag(self):
        # `-o` followed by a flag (malformed) is not treated as a filename
        assert outs(["tool", "-o", "-v"]) == []
