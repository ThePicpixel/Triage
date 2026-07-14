import csv
from pathlib import Path
from unittest.mock import patch
from triage.batch import run_batch

FAKE_VERDICT = {
    "classification": "benign", "confidence": 0.9,
    "summary": "s", "key_evidence": [], "mitre_attack": [], "iocs": [],
}

def test_batch_creates_csv(tmp_path, eicar_path):
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    (samples_dir / "a.exe").write_bytes(b"MZ")
    (samples_dir / "b.exe").write_bytes(b"MZ")

    with patch("triage.batch.graph") as mock_graph, \
         patch("triage.nodes.report.REPORTS_DIR", tmp_path):
        mock_graph.invoke.return_value = {
            "verdict": FAKE_VERDICT,
            "sha256": "abc" * 21 + "a",
            "report_path": str(tmp_path / "r.md"),
            "json_path": str(tmp_path / "r.json"),
        }
        csv_path = run_batch(str(samples_dir), str(tmp_path))
        # Verify mock was actually called twice (once per sample)
        assert mock_graph.invoke.call_count == 2

    assert Path(csv_path).exists()
    rows = list(csv.DictReader(Path(csv_path).open()))
    assert len(rows) == 2
    assert "filename" in rows[0]
    assert "classification" in rows[0]

def test_batch_records_error_rows(tmp_path):
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    (samples_dir / "bad.exe").write_bytes(b"MZ")

    with patch("triage.batch.graph") as mock_graph:
        mock_graph.invoke.side_effect = RuntimeError("analysis failed")
        csv_path = run_batch(str(samples_dir), str(tmp_path))
        # Verify mock was called once
        assert mock_graph.invoke.call_count == 1

    rows = list(csv.DictReader(Path(csv_path).open()))
    assert rows[0]["classification"] == "error"
