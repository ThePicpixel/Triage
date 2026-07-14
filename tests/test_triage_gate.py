from triage.nodes.triage_gate import triage_gate


def _make_state(weights: list[float]) -> dict:
    findings = [
        {"source": "test", "signal": "s", "severity": "high",
         "evidence": "e", "weight": w}
        for w in weights
    ]
    return {
        "file_path": "/tmp/a.exe", "sha256": "abc", "file_type": "PE",
        "static": {}, "dynamic": {}, "memory": {},
        "findings": findings, "verdict": {}, "report_path": "", "json_path": "",
    }


def test_gate_routes_to_dynamic_above_threshold():
    state = _make_state([0.3, 0.3])   # total 0.6 >= 0.5
    assert triage_gate(state) == "dynamic_runner"


def test_gate_routes_to_report_below_threshold():
    state = _make_state([0.1, 0.1])   # total 0.2 < 0.5
    assert triage_gate(state) == "report"


def test_gate_routes_to_dynamic_at_exact_threshold():
    state = _make_state([0.25, 0.25])  # total 0.5 >= 0.5
    assert triage_gate(state) == "dynamic_runner"
