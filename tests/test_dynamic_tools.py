import pytest
from unittest.mock import patch, MagicMock
from triage.tools.dynamic_tools import detonate, run_capa, scan_yara, analyze_pcap, analyze_memory, _run_cli

FAKE_TASK_RESPONSE = {"data": {"task_id": 1}}
FAKE_STATUS_PENDING = {"data": {"status": "pending"}}
FAKE_STATUS_REPORTED = {"data": {"status": "reported"}}
FAKE_REPORT = {
    "data": {
        "info": {"id": 1, "score": 7},
        "behavior": {"processes": [], "summary": {}},
        "network": {"hosts": [], "dns": []},
    }
}

def _mock_http(responses: list):
    """Return a mock httpx.Client that yields successive json() returns."""
    client = MagicMock()
    resp_mock = MagicMock()
    resp_mock.json.side_effect = responses
    resp_mock.raise_for_status = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.post.return_value = resp_mock
    client.get.return_value = resp_mock
    return client

def test_detonate_returns_task_id(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x00")

    with patch("triage.tools.dynamic_tools.httpx.Client") as MockClient:
        MockClient.return_value = _mock_http([
            FAKE_TASK_RESPONSE,        # POST submit
            FAKE_STATUS_REPORTED,      # GET status (done immediately)
            FAKE_REPORT,               # GET report
        ])
        result = detonate.invoke({"file_path": str(sample)})

    assert "task_id" in result
    assert result["task_id"] == 1

def test_detonate_returns_findings(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x00")

    with patch("triage.tools.dynamic_tools.httpx.Client") as MockClient:
        MockClient.return_value = _mock_http([
            FAKE_TASK_RESPONSE,
            FAKE_STATUS_REPORTED,
            FAKE_REPORT,
        ])
        result = detonate.invoke({"file_path": str(sample)})

    assert "findings" in result
    assert isinstance(result["findings"], list)

def test_detonate_handles_timeout(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x00")

    # Simulate CAPE never finishing
    with patch("triage.tools.dynamic_tools.httpx.Client") as MockClient:
        MockClient.return_value = _mock_http([FAKE_TASK_RESPONSE] + [FAKE_STATUS_PENDING] * 20)
        with patch("triage.tools.dynamic_tools.CAPE_MAX_POLLS", 2):
            with patch("triage.tools.dynamic_tools.time.sleep"):
                result = detonate.invoke({"file_path": str(sample)})

    assert result["findings"][0]["signal"] == "detonation_timeout"

def test_run_capa_returns_techniques(tmp_path):
    report = tmp_path / "report.json"
    report.write_text('{"rules": []}')
    fake_output = (
        '{"rules": {"some-rule-name": {"meta": {"attack": [{"technique": "T1055"}]}, '
        '"matches": {}}}}'
    )
    with patch("triage.tools.dynamic_tools.shutil.which", return_value="/usr/bin/capa"):
        with patch("triage.tools.dynamic_tools._run_cli", return_value=fake_output):
            result = run_capa.invoke({"file_path": str(report)})
    assert "techniques" in result
    assert isinstance(result["techniques"], list)
    assert "T1055" in result["techniques"]

def test_run_capa_handles_missing_binary(tmp_path):
    report = tmp_path / "report.json"
    report.write_text("{}")
    with patch("triage.tools.dynamic_tools._run_cli", side_effect=FileNotFoundError("capa not found")):
        result = run_capa.invoke({"file_path": str(report)})
    assert result["findings"][0]["signal"] == "capa_unavailable"

def test_scan_yara_returns_matches(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
    fake_output = "test_rule sample.bin"
    with patch("triage.tools.dynamic_tools.shutil.which", return_value="/usr/bin/yr"):
        with patch("triage.tools.dynamic_tools._run_cli", return_value=fake_output):
            result = scan_yara.invoke({"file_path": str(sample)})
    assert "matches" in result
    assert "test_rule" in result["matches"]

def test_analyze_pcap_returns_iocs(tmp_path):
    pcap = tmp_path / "dump.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1")  # minimal pcap magic
    with patch("triage.tools.dynamic_tools._parse_pcap_with_pyshark", return_value={
        "hosts": ["1.2.3.4"], "dns": ["evil.com"], "http_hosts": [], "ja3": []
    }):
        result = analyze_pcap.invoke({"file_path": str(pcap)})
    assert "hosts" in result
    assert "1.2.3.4" in result["hosts"]

def test_analyze_memory_returns_shape(tmp_path):
    mem = tmp_path / "memory.dmp"
    mem.write_bytes(b"\x00" * 16)
    fake_pslist = "Offset(V) Name PID\n0x1234 explorer.exe 1234\n"
    fake_malfind = ""
    with patch("triage.tools.dynamic_tools._run_cli", side_effect=[fake_pslist, fake_malfind, "", ""]):
        result = analyze_memory.invoke({"file_path": str(mem)})
    assert "processes" in result
    assert "injected_regions" in result

def test_analyze_memory_flags_malfind(tmp_path):
    mem = tmp_path / "memory.dmp"
    mem.write_bytes(b"\x00" * 16)
    fake_pslist = ""
    fake_malfind = "Process: bad.exe Pid: 666\nVAD node @ 0xDEADBEEF\nMZ header found\n"
    with patch("triage.tools.dynamic_tools._run_cli", side_effect=[fake_pslist, fake_malfind, "", ""]):
        result = analyze_memory.invoke({"file_path": str(mem)})
    signals = [f["signal"] for f in result["findings"]]
    assert "injected_code_region" in signals

def test_analyze_memory_handles_missing_volatility(tmp_path):
    mem = tmp_path / "memory.dmp"
    mem.write_bytes(b"\x00" * 16)
    with patch("triage.tools.dynamic_tools._run_cli", side_effect=FileNotFoundError("vol not found")):
        result = analyze_memory.invoke({"file_path": str(mem)})
    assert result["findings"][0]["signal"] == "volatility_unavailable"

def test_run_cli_raises_on_nonzero_returncode():
    with pytest.raises(RuntimeError):
        _run_cli(["python3", "-c", "import sys; sys.exit(1)"])

def test_run_cli_returns_stdout_on_success():
    out = _run_cli(["python3", "-c", "print('ok')"])
    assert out.strip() == "ok"

def test_analyze_memory_reports_error_on_internal_module_failure(tmp_path):
    """Regression test: a subprocess that runs but fails internally (e.g. a
    missing python module invoked via `python3 -m`) must surface as an error
    finding, not silently succeed with empty output."""
    mem = tmp_path / "memory.dmp"
    mem.write_bytes(b"\x00" * 16)
    with patch("triage.tools.dynamic_tools._run_cli", side_effect=RuntimeError(
        "command failed (1): python3 -m volatility3.cli -f x windows.pslist: "
        "ModuleNotFoundError: No module named 'volatility3'"
    )):
        result = analyze_memory.invoke({"file_path": str(mem)})
    assert result["findings"][0]["signal"] == "memory_analysis_error"
