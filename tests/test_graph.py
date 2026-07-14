# tests/test_graph.py
import json
from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, MagicMock

from triage.graph import graph
from triage.tools import dynamic_tools

FAKE_VERDICT = {
    "classification": "suspicious",
    "confidence": 0.7,
    "summary": "EICAR test file detected.",
    "key_evidence": ["EICAR string found"],
    "mitre_attack": [],
    "iocs": [],
}


def _patch_tool_invoke(tool, return_value):
    """Patch `.invoke` directly on the shared LangChain tool *object*'s own
    __dict__ (not the module-level name it happens to be imported under).

    triage/nodes/dynamic.py's `_ANALYSIS_TOOLS` dict and the `_make_worker`
    closures capture a reference to the real tool objects at import time
    (when `dynamic_graph = _build_dynamic_graph()` runs). Patching
    `triage.nodes.dynamic.run_capa`/`scan_yara`/`analyze_pcap`/`analyze_memory`
    only rebinds the module attribute name - it does not reach into
    `_ANALYSIS_TOOLS`'s already-captured values or the workers' closed-over
    `tool_fn`, so those tools would run for real. This is the same failure
    class fixed in Task 13 (see tests/test_dynamic_subgraph.py). Mutating
    `.invoke` on the tool object itself (via patch.dict on its __dict__,
    since these are pydantic BaseTool instances) affects every reference to
    that shared object regardless of which module-level name points at it.
    """
    mock = MagicMock(return_value=return_value)
    return mock, patch.dict(tool.__dict__, {"invoke": mock})


def test_graph_end_to_end_benign_skips_dynamic(tmp_path, eicar_path):
    called = {"dynamic": False}

    def fake_dynamic(state):
        called["dynamic"] = True
        return state

    # NOTE: `_run_dynamic` in triage/graph.py calls `dynamic_graph.invoke(state)`,
    # not `dynamic_graph(state)`. Patching the module attribute with
    # `patch("triage.graph.dynamic_graph", side_effect=fake_dynamic)` (as
    # originally given in the task brief) sets `side_effect` on the mock's
    # own __call__, which is never exercised - `.invoke` is a separate
    # auto-mocked attribute that returns an unrelated MagicMock by default,
    # never routing through `fake_dynamic`. Confirmed empirically: forcing
    # the dynamic_runner branch with that pattern raised
    # `InvalidUpdateError: Expected dict, got <MagicMock ...>` because
    # `.invoke()` returned a bare MagicMock instead of a dict. The fix is to
    # set `.invoke.side_effect` on the mock instead.
    with patch("triage.graph.dynamic_graph") as mock_dynamic_graph, \
         patch("triage.nodes.report._invoke_ollama", return_value=FAKE_VERDICT), \
         patch("triage.nodes.report.REPORTS_DIR", tmp_path):
        mock_dynamic_graph.invoke.side_effect = fake_dynamic
        result = graph.invoke({"file_path": eicar_path, "findings": []})

    # EICAR's real static findings are empty (weight 0), so triage_gate
    # routes straight to "report" and skips dynamic_runner entirely.
    assert called["dynamic"] is False
    assert result["verdict"]["classification"] in (
        "benign", "suspicious", "malicious", "inconclusive"
    )
    assert result["report_path"] != ""


def test_graph_end_to_end_dynamic_runner_reached_when_score_high(tmp_path, eicar_path):
    """Directly proves `triage.graph.dynamic_graph` patching genuinely
    intercepts the dynamic_runner node when triage_gate actually routes
    there. Forced by seeding an initial high-weight finding so the
    triage_gate score clears the 0.5 threshold regardless of EICAR's
    (always-empty) real static findings. `dynamic_graph` is a plain
    module-level global looked up at call time inside `_run_dynamic` (no
    closure capture at graph.py import time), so patching
    `triage.graph.dynamic_graph` genuinely intercepts it - as long as the
    mock's `.invoke` (not the mock itself) is wired up, see the note in
    test_graph_end_to_end_benign_skips_dynamic above."""
    called = {"dynamic": False}

    def fake_dynamic(state):
        called["dynamic"] = True
        return state

    seed_finding = [{"source": "test", "signal": "forced", "severity": "critical",
                      "evidence": "forced for test", "weight": 0.9}]

    with patch("triage.graph.dynamic_graph") as mock_dynamic_graph, \
         patch("triage.nodes.report._invoke_ollama", return_value=FAKE_VERDICT), \
         patch("triage.nodes.report.REPORTS_DIR", tmp_path):
        mock_dynamic_graph.invoke.side_effect = fake_dynamic
        graph.invoke({"file_path": eicar_path, "findings": seed_finding})

    assert called["dynamic"] is True


def test_graph_creates_output_files(tmp_path, eicar_path):
    empty = {"findings": [], "techniques": [], "matches": [],
             "hosts": [], "dns": [], "http_hosts": [], "ja3": [],
             "processes": [], "injected_regions": [], "connections": [], "ldrmodules": []}

    m_det, p_det = _patch_tool_invoke(
        dynamic_tools.detonate, {"task_id": 1, "report": {}, "findings": []})
    m_capa, p_capa = _patch_tool_invoke(dynamic_tools.run_capa, empty)
    m_yara, p_yara = _patch_tool_invoke(dynamic_tools.scan_yara, empty)
    m_pcap, p_pcap = _patch_tool_invoke(dynamic_tools.analyze_pcap, empty)
    m_mem, p_mem = _patch_tool_invoke(dynamic_tools.analyze_memory, empty)

    with patch("triage.nodes.report._invoke_ollama", return_value=FAKE_VERDICT), \
         patch("triage.nodes.report.REPORTS_DIR", tmp_path), \
         ExitStack() as stack:
        for p in (p_det, p_capa, p_yara, p_pcap, p_mem):
            stack.enter_context(p)
        result = graph.invoke({"file_path": eicar_path, "findings": []})

    assert Path(result["report_path"]).exists()
    assert Path(result["json_path"]).exists()

    # EICAR's real static findings are empty (score 0 < 0.5 threshold), so
    # triage_gate skips dynamic_runner and none of these 5 dynamic-tool
    # mocks are ever called for this fixture. Assert that explicitly so the
    # test doesn't silently rely on unreached mocks - genuine interception
    # of these tool objects (when the dynamic path IS taken) is proven with
    # call-count assertions in tests/test_dynamic_subgraph.py.
    for name, mock in (("detonate", m_det), ("capa", m_capa), ("yara", m_yara),
                        ("pcap", m_pcap), ("memory", m_mem)):
        assert mock.call_count == 0, (
            f"expected dynamic tool '{name}' to be skipped for EICAR's zero-weight "
            f"static findings, but it was called {mock.call_count} time(s)"
        )


def test_graph_creates_output_files_via_dynamic_path(tmp_path, eicar_path):
    """Forces the dynamic_runner branch (via a seeded high-weight finding)
    and proves the 5 dynamic-tool mocks are genuinely reached through the
    full top-level graph, using the tool-object-level patch mechanism."""
    empty = {"findings": [], "techniques": [], "matches": [],
             "hosts": [], "dns": [], "http_hosts": [], "ja3": [],
             "processes": [], "injected_regions": [], "connections": [], "ldrmodules": []}

    m_det, p_det = _patch_tool_invoke(
        dynamic_tools.detonate, {"task_id": 1, "report": {}, "findings": []})
    m_capa, p_capa = _patch_tool_invoke(dynamic_tools.run_capa, empty)
    m_yara, p_yara = _patch_tool_invoke(dynamic_tools.scan_yara, empty)
    m_pcap, p_pcap = _patch_tool_invoke(dynamic_tools.analyze_pcap, empty)
    m_mem, p_mem = _patch_tool_invoke(dynamic_tools.analyze_memory, empty)

    seed_finding = [{"source": "test", "signal": "forced", "severity": "critical",
                      "evidence": "forced for test", "weight": 0.9}]

    with patch("triage.nodes.report._invoke_ollama", return_value=FAKE_VERDICT), \
         patch("triage.nodes.report.REPORTS_DIR", tmp_path), \
         ExitStack() as stack:
        for p in (p_det, p_capa, p_yara, p_pcap, p_mem):
            stack.enter_context(p)
        result = graph.invoke({"file_path": eicar_path, "findings": seed_finding})

    assert Path(result["report_path"]).exists()
    assert Path(result["json_path"]).exists()

    for name, mock in (("detonate", m_det), ("capa", m_capa), ("yara", m_yara),
                        ("pcap", m_pcap), ("memory", m_mem)):
        assert mock.call_count == 1, (
            f"expected dynamic tool '{name}'.invoke to be called exactly once via "
            f"the real compiled dynamic_graph reached through the full top-level "
            f"graph, but call_count={mock.call_count} (real tool implementation "
            f"may have run instead of the mock)"
        )


def test_graph_dynamic_path_does_not_duplicate_findings(tmp_path, eicar_path):
    """Regression test for the subgraph-wrapper duplication bug: `_run_static`
    and `_run_dynamic` in triage/graph.py used to return the subgraph's FULL
    accumulated `findings` list (which already included everything passed
    into the subgraph), so the parent's `add`-reducer channel re-appended
    findings that were already present, duplicating them. This only
    manifests through the dynamic_runner branch - see
    test_graph_end_to_end_benign_skips_dynamic for the (unaffected)
    static-only path.

    Seeds one pre-existing high-weight finding, mocks the 5 dynamic tools so
    capa and yara each contribute exactly one *new* finding (detonate/pcap/
    memory contribute none), and asserts each finding appears EXACTLY ONCE
    in both the final graph state and the persisted JSON report - not
    merely that findings is non-empty. Under the old buggy code this would
    have produced 5 findings (seed + capa + yara duplicated, i.e. counts of
    2 each) instead of 3.
    """
    capa_result = {"findings": [{"source": "capa", "signal": "attack_techniques_detected",
                                  "severity": "high", "evidence": "T1055", "weight": 0.6}],
                   "techniques": ["T1055"]}
    yara_result = {"findings": [{"source": "yara", "signal": "yara_rule_match",
                                  "severity": "high", "evidence": "EICAR_Test_File", "weight": 0.6}],
                   "matches": ["EICAR_Test_File"]}
    empty = {"findings": [], "techniques": [], "matches": [],
             "hosts": [], "dns": [], "http_hosts": [], "ja3": [],
             "processes": [], "injected_regions": [], "connections": [], "ldrmodules": []}

    m_det, p_det = _patch_tool_invoke(
        dynamic_tools.detonate, {"task_id": 1, "report": {}, "findings": []})
    m_capa, p_capa = _patch_tool_invoke(dynamic_tools.run_capa, capa_result)
    m_yara, p_yara = _patch_tool_invoke(dynamic_tools.scan_yara, yara_result)
    m_pcap, p_pcap = _patch_tool_invoke(dynamic_tools.analyze_pcap, empty)
    m_mem, p_mem = _patch_tool_invoke(dynamic_tools.analyze_memory, empty)

    seed_finding = {"source": "test", "signal": "forced", "severity": "critical",
                    "evidence": "forced for test", "weight": 0.9}

    with patch("triage.nodes.report._invoke_ollama", return_value=FAKE_VERDICT), \
         patch("triage.nodes.report.REPORTS_DIR", tmp_path), \
         ExitStack() as stack:
        for p in (p_det, p_capa, p_yara, p_pcap, p_mem):
            stack.enter_context(p)
        result = graph.invoke({"file_path": eicar_path, "findings": [seed_finding]})

    # EICAR's real static findings are empty (weight 0), so the only
    # findings feeding the final state should be: seed + capa + yara = 3,
    # each appearing exactly once.
    counts = Counter(f["evidence"] for f in result["findings"])
    assert counts["forced for test"] == 1, f"seeded finding duplicated: counts={counts}"
    assert counts["T1055"] == 1, f"capa finding duplicated: counts={counts}"
    assert counts["EICAR_Test_File"] == 1, f"yara finding duplicated: counts={counts}"
    assert len(result["findings"]) == 3, (
        f"expected exactly 3 findings (seed + capa + yara), got "
        f"{len(result['findings'])}: {result['findings']}"
    )

    # The report node must receive the corrected (non-duplicated) findings
    # list and persist it verbatim into the JSON report.
    json_report = json.loads(Path(result["json_path"]).read_text())
    assert json_report["findings"] == result["findings"]
