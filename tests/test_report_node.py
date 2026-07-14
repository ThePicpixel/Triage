import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from triage.nodes.report import report_node, _invoke_ollama
from triage.state import Verdict

FAKE_VERDICT = {
    "classification": "malicious",
    "confidence": 0.9,
    "summary": "Sample exhibits injection behaviour.",
    "key_evidence": ["high entropy .text section", "imports VirtualAlloc"],
    "mitre_attack": ["T1055"],
    "iocs": ["1.2.3.4"],
}

def _make_state(tmp_path):
    return {
        "file_path": str(tmp_path / "sample.exe"),
        "sha256": "abcdef1234567890" * 4,
        "file_type": "PE32",
        "static": {}, "dynamic": {}, "memory": {},
        "findings": [
            {"source": "entropy", "signal": "high_entropy_section",
             "severity": "high", "evidence": "entropy=7.9", "weight": 0.5}
        ],
        "verdict": {}, "report_path": "", "json_path": "",
    }

def test_report_node_creates_md_file(tmp_path):
    (tmp_path / "sample.exe").write_bytes(b"MZ")
    with patch("triage.nodes.report.REPORTS_DIR", tmp_path), \
         patch("triage.nodes.report._invoke_ollama", return_value=FAKE_VERDICT):
        result = report_node(_make_state(tmp_path))
    md_path = Path(result["report_path"])
    assert md_path.exists()
    assert md_path.suffix == ".md"

def test_report_node_creates_json_file(tmp_path):
    (tmp_path / "sample.exe").write_bytes(b"MZ")
    with patch("triage.nodes.report.REPORTS_DIR", tmp_path), \
         patch("triage.nodes.report._invoke_ollama", return_value=FAKE_VERDICT):
        result = report_node(_make_state(tmp_path))
    json_path = Path(result["json_path"])
    assert json_path.exists()
    data = json.loads(json_path.read_text())
    assert "verdict" in data
    assert "findings" in data

def test_report_node_filename_format(tmp_path):
    (tmp_path / "sample.exe").write_bytes(b"MZ")
    with patch("triage.nodes.report.REPORTS_DIR", tmp_path), \
         patch("triage.nodes.report._invoke_ollama", return_value=FAKE_VERDICT):
        result = report_node(_make_state(tmp_path))
    md_name = Path(result["report_path"]).name
    assert "sample" in md_name
    assert "abcdef12" in md_name   # first 8 chars of sha256


def test_invoke_ollama_retries_then_succeeds(tmp_path):
    fake_verdict = Verdict(**FAKE_VERDICT)
    good_raw = MagicMock(content="whatever")
    with patch("triage.nodes.report._llm") as mock_llm, \
         patch("triage.nodes.report._parser") as mock_parser:
        # First invoke() call raises (simulating Ollama being unreachable),
        # second invoke() call succeeds and parses cleanly.
        mock_llm.invoke.side_effect = [ConnectionError("ollama unreachable"), good_raw]
        mock_parser.parse.return_value = fake_verdict

        result = _invoke_ollama(_make_state(tmp_path))

    assert mock_llm.invoke.call_count == 2
    assert mock_parser.parse.call_count == 1
    assert result == fake_verdict.model_dump()


def test_invoke_ollama_falls_back_on_repeated_invoke_failure(tmp_path):
    with patch("triage.nodes.report._llm") as mock_llm, \
         patch("triage.nodes.report._parser") as mock_parser:
        mock_llm.invoke.side_effect = ConnectionError("ollama unreachable")

        result = _invoke_ollama(_make_state(tmp_path))

    assert mock_llm.invoke.call_count == 2
    assert mock_parser.parse.call_count == 0
    assert result["classification"] == "inconclusive"
    assert result["confidence"] == 0.0


def test_invoke_ollama_falls_back_on_repeated_parse_failure(tmp_path):
    raw = MagicMock(content="not valid json")
    with patch("triage.nodes.report._llm") as mock_llm, \
         patch("triage.nodes.report._parser") as mock_parser:
        mock_llm.invoke.return_value = raw
        mock_parser.parse.side_effect = ValueError("could not parse")

        result = _invoke_ollama(_make_state(tmp_path))

    assert mock_llm.invoke.call_count == 2
    assert mock_parser.parse.call_count == 2
    assert result["classification"] == "inconclusive"
    assert result["confidence"] == 0.0
