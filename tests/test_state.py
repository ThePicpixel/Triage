from triage.state import TriageState, Finding, Verdict


def test_finding_requires_fields():
    f = Finding(source="entropy", signal="packed_section",
                severity="high", evidence=".text entropy=7.9", weight=0.6)
    assert f.weight == 0.6


def test_finding_rejects_bad_severity():
    import pytest
    with pytest.raises(Exception):
        Finding(source="x", signal="y", severity="extreme",
                evidence="z", weight=0.5)


def test_verdict_classification_enum():
    import pytest
    with pytest.raises(Exception):
        Verdict(classification="unknown", confidence=0.5,
                summary="s", key_evidence=[], mitre_attack=[], iocs=[])


def test_triage_state_findings_default():
    state: TriageState = {
        "file_path": "/tmp/a.exe",
        "sha256": "", "file_type": "",
        "static": {}, "dynamic": {}, "memory": {},
        "findings": [],
        "verdict": {}, "report_path": "", "json_path": "",
    }
    assert state["findings"] == []
