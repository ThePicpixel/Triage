from contextlib import ExitStack
from unittest.mock import patch, MagicMock
from triage.nodes.dynamic import dynamic_graph
from triage.tools import dynamic_tools

FAKE_DETONATE = {
    "task_id": 1,
    "report": {"info": {"score": 8}, "network": {"hosts": [], "dns": []}},
    "findings": [{"source": "dynamic", "signal": "high_cape_score",
                  "severity": "critical", "evidence": "score=8", "weight": 0.8}],
}
FAKE_EMPTY = {"techniques": [], "matches": [], "hosts": [], "dns": [],
              "http_hosts": [], "ja3": [], "processes": [],
              "injected_regions": [], "connections": [], "ldrmodules": [],
              "findings": []}


def _patch_tool_invoke(tool, return_value):
    """Patch the `.invoke` attribute directly on a LangChain tool *object*
    (as opposed to patching the module-level name it's imported under).

    The compiled dynamic_graph's worker closures captured a reference to
    these exact tool objects at import time (see triage/nodes/dynamic.py:
    _ANALYSIS_TOOLS and _run_detonate's global lookup). Since the objects
    are mutable and shared by reference, mutating `.invoke` in place here
    affects every closure holding a reference to the same object -
    regardless of what module-level name currently points at it.

    LangChain tools are pydantic BaseModel instances, so plain
    `unittest.mock.patch.object(tool, "invoke", ...)` fails at teardown:
    pydantic's __setattr__/__delattr__ reject attributes that aren't
    declared model fields (raises AttributeError). `invoke` is inherited
    from BaseTool as a class-level method, not an instance field, so it
    can't be set/deleted via pydantic's normal attribute machinery.

    Instead we use `patch.dict` on the instance's own __dict__. Setting
    "invoke" as a key in the instance __dict__ shadows the inherited
    method for plain attribute lookup (instance __dict__ takes precedence
    over a class's non-data-descriptor methods), and `patch.dict` cleanly
    restores the __dict__ to its original state afterwards.
    """
    mock = MagicMock(return_value=return_value)
    return mock, patch.dict(tool.__dict__, {"invoke": mock})


def _patched_state(state):
    """Invoke dynamic_graph with all 5 tool objects' .invoke methods patched
    directly on the tool objects held by the compiled graph's worker
    closures (patching the module-level name is too late for closures that
    already captured the real object at import time).

    Returns (result, mocks) where mocks is a dict of name -> MagicMock for
    each patched .invoke, so callers can assert call counts.
    """
    m_detonate, p_detonate = _patch_tool_invoke(dynamic_tools.detonate, FAKE_DETONATE)
    m_capa, p_capa = _patch_tool_invoke(dynamic_tools.run_capa, {**FAKE_EMPTY, "techniques": []})
    m_yara, p_yara = _patch_tool_invoke(dynamic_tools.scan_yara, {**FAKE_EMPTY, "matches": []})
    m_pcap, p_pcap = _patch_tool_invoke(dynamic_tools.analyze_pcap, FAKE_EMPTY)
    m_memory, p_memory = _patch_tool_invoke(dynamic_tools.analyze_memory, FAKE_EMPTY)

    with ExitStack() as stack:
        for p in (p_detonate, p_capa, p_yara, p_pcap, p_memory):
            stack.enter_context(p)
        result = dynamic_graph.invoke(state)

    mocks = {
        "detonate": m_detonate,
        "capa": m_capa,
        "yara": m_yara,
        "pcap": m_pcap,
        "memory": m_memory,
    }
    return result, mocks


def _assert_all_mocks_called(mocks):
    for name, mock in mocks.items():
        assert mock.call_count == 1, (
            f"expected tool '{name}'.invoke to be called exactly once via the "
            f"compiled graph, but call_count={mock.call_count} (real tool "
            f"implementation may have run instead of the mock)"
        )


def test_dynamic_graph_returns_findings():
    state = {
        "file_path": "/tmp/a.exe", "sha256": "abc", "file_type": "PE",
        "static": {}, "dynamic": {}, "memory": {},
        "findings": [], "verdict": {}, "report_path": "", "json_path": "",
    }
    result, mocks = _patched_state(state)

    assert "findings" in result
    assert len(result["findings"]) > 0
    _assert_all_mocks_called(mocks)


def test_dynamic_graph_populates_dynamic_key():
    state = {
        "file_path": "/tmp/a.exe", "sha256": "abc", "file_type": "PE",
        "static": {}, "dynamic": {}, "memory": {},
        "findings": [], "verdict": {}, "report_path": "", "json_path": "",
    }
    result, mocks = _patched_state(state)

    assert "dynamic" in result
    assert "cape" in result["dynamic"]
    _assert_all_mocks_called(mocks)
