"""Past-engagement memory source — workspace walking + client inference."""

from __future__ import annotations

from pathlib import Path

from sentinel.corpus.sources.past_engagements import PastEngagementsSource


def _make_workspace(root: Path, engagement_id: str, deliverables: dict[str, str]) -> Path:
    ws = root / engagement_id
    deliv = ws / "deliverables"
    deliv.mkdir(parents=True)
    for name, body in deliverables.items():
        (deliv / name).write_text(body)
    return ws


def test_skips_files_that_are_not_recognized_deliverables(tmp_path):
    _make_workspace(tmp_path, "2026-Q2-acmecorp-001", {
        "scratch_notes.md": "x" * 500,  # not a recognized deliverable
        "queue.json": "{}",  # not markdown
    })
    src = PastEngagementsSource(tmp_path)
    docs = list(src.parse(work_dir=tmp_path))
    assert docs == []


def test_yields_documents_for_recognized_deliverables(tmp_path):
    body = "## Recon\n" + ("evidence body " * 100)
    _make_workspace(tmp_path, "2026-Q2-acmecorp-001", {
        "recon_deliverable.md": body,
        "auth_analysis_deliverable.md": body,
        "comprehensive_security_assessment_report.md": body,
    })
    docs = list(PastEngagementsSource(tmp_path).parse(work_dir=tmp_path))
    assert len(docs) == 3
    assert all("past-engagement-acmecorp-2026-Q2-acmecorp-001" in d.source for d in docs)


def test_client_inference_picks_third_segment(tmp_path):
    _make_workspace(tmp_path, "2026-Q1-ExampleCorp-pentest-014", {
        "recon_deliverable.md": "x" * 500,
    })
    docs = list(PastEngagementsSource(tmp_path).parse(work_dir=tmp_path))
    assert any(d.metadata.get("client") == "ExampleCorp" for d in docs)


def test_only_engagements_filter_restricts_walk(tmp_path):
    _make_workspace(tmp_path, "engagement-a", {"recon_deliverable.md": "x" * 500})
    _make_workspace(tmp_path, "engagement-b", {"recon_deliverable.md": "x" * 500})
    src = PastEngagementsSource(tmp_path, only_engagements=["engagement-a"])
    docs = list(src.parse(work_dir=tmp_path))
    assert len(docs) == 1
    assert docs[0].metadata["engagement_id"] == "engagement-a"


def test_skips_too_short_deliverables(tmp_path):
    _make_workspace(tmp_path, "2026-Q1-x-001", {
        "recon_deliverable.md": "tiny",  # < 200 chars; skipped
    })
    docs = list(PastEngagementsSource(tmp_path).parse(work_dir=tmp_path))
    assert docs == []


def test_missing_workspaces_dir_does_not_raise(tmp_path):
    # Source pointed at a nonexistent dir should yield nothing, not crash.
    src = PastEngagementsSource(tmp_path / "does_not_exist")
    docs = list(src.parse(work_dir=tmp_path))
    assert docs == []
