# triage/nodes/static.py
from typing import Any
from langgraph.graph import StateGraph, START, END
from langgraph.types import Send

from triage.state import TriageState
from triage.nodes.intake import intake
from triage.tools.static_tools import (
    compute_entropy,
    extract_strings,
    parse_imports,
    parse_sections,
)

_STATIC_TOOLS = {
    "entropy": compute_entropy,
    "strings": extract_strings,
    "imports": parse_imports,
    "sections": parse_sections,
}


def _fanout(state: TriageState) -> list[Send]:
    return [
        Send(f"run_{name}", {"file_path": state["file_path"], "findings": []})
        for name in _STATIC_TOOLS
    ]


def _make_worker(name: str, tool_fn: Any):
    def worker(state: dict) -> dict:
        result = tool_fn.invoke({"file_path": state["file_path"]})
        return {
            "static": {name: result},
            "findings": result.get("findings", []),
        }
    worker.__name__ = f"run_{name}"
    return worker


def _build_static_graph() -> Any:
    builder = StateGraph(TriageState)
    builder.add_node("intake", intake)
    builder.add_conditional_edges("intake", _fanout, [f"run_{n}" for n in _STATIC_TOOLS])
    builder.add_edge(START, "intake")

    for name, tool_fn in _STATIC_TOOLS.items():
        node_name = f"run_{name}"
        builder.add_node(node_name, _make_worker(name, tool_fn))
        builder.add_edge(node_name, END)

    return builder.compile()


static_graph = _build_static_graph()
