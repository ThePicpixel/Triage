# triage/nodes/dynamic.py
from typing import Any
from langgraph.graph import StateGraph, START, END
from langgraph.types import Send

from triage.state import TriageState
from triage.tools.dynamic_tools import (
    detonate,
    run_capa,
    scan_yara,
    analyze_pcap,
    analyze_memory,
)

_ANALYSIS_TOOLS = {
    "capa": run_capa,
    "yara": scan_yara,
    "pcap": analyze_pcap,
    "memory": analyze_memory,
}


def _run_detonate(state: TriageState) -> dict:
    result = detonate.invoke({"file_path": state["file_path"]})
    cape_report = result.get("report", {})
    pcap_path = cape_report.get("pcap", "")
    mem_path = cape_report.get("memory", "")
    return {
        "dynamic": {"cape": cape_report, "pcap_path": pcap_path, "memory_path": mem_path},
        "findings": result.get("findings", []),
    }


def _fanout(state: TriageState) -> list[Send]:
    cape = state.get("dynamic", {})
    pcap_path = cape.get("pcap_path", state["file_path"])
    mem_path = cape.get("memory_path", state["file_path"])
    paths = {
        "capa": state["file_path"],
        "yara": state["file_path"],
        "pcap": pcap_path,
        "memory": mem_path,
    }
    return [Send(f"run_dyn_{name}", {"file_path": paths[name], "findings": []})
            for name in _ANALYSIS_TOOLS]


def _make_worker(name: str, tool_fn: Any):
    def worker(state: dict) -> dict:
        result = tool_fn.invoke({"file_path": state["file_path"]})
        return {
            "dynamic": {name: result},
            "findings": result.get("findings", []),
        }
    worker.__name__ = f"run_dyn_{name}"
    return worker


def _build_dynamic_graph() -> Any:
    builder = StateGraph(TriageState)
    builder.add_node("detonation", _run_detonate)
    builder.add_conditional_edges("detonation", _fanout, [f"run_dyn_{n}" for n in _ANALYSIS_TOOLS])
    builder.add_edge(START, "detonation")
    for name, tool_fn in _ANALYSIS_TOOLS.items():
        node_name = f"run_dyn_{name}"
        builder.add_node(node_name, _make_worker(name, tool_fn))
        builder.add_edge(node_name, END)
    return builder.compile()


dynamic_graph = _build_dynamic_graph()
