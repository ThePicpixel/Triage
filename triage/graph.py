# triage/graph.py
from langgraph.graph import StateGraph, START, END

from triage.state import TriageState
from triage.nodes.static import static_graph
from triage.nodes.triage_gate import triage_gate
from triage.nodes.dynamic import dynamic_graph
from triage.nodes.report import report_node


def _run_static(state: TriageState) -> dict:
    print("Running the static node")
    prior_findings = state.get("findings", [])
    result = static_graph.invoke(state)
    new_findings = result["findings"][len(prior_findings):]
    return {**result, "findings": new_findings}


def _run_dynamic(state: TriageState) -> dict:
    prior_findings = state.get("findings", [])
    result = dynamic_graph.invoke(state)
    new_findings = result["findings"][len(prior_findings):]
    return {**result, "findings": new_findings}


def _build_graph():
    builder = StateGraph(TriageState)

    builder.add_node("static_analysis", _run_static)
    builder.add_node("dynamic_runner", _run_dynamic)
    builder.add_node("report", report_node)

    builder.add_edge(START, "static_analysis")
    builder.add_conditional_edges(
        "static_analysis",
        triage_gate,
        {"dynamic_runner": "dynamic_runner", "report": "report"},
    )
    builder.add_edge("dynamic_runner", "report")
    builder.add_edge("report", END)

    return builder.compile()


graph = _build_graph()
