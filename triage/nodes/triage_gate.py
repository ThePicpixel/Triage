from triage.state import TriageState

TRIAGE_THRESHOLD = 0.5


def triage_gate(state: TriageState) -> str:
    """Route to dynamic analysis if static risk score >= threshold, else skip to report."""
    score = sum(f["weight"] for f in state["findings"])
    return "dynamic_runner" if score >= TRIAGE_THRESHOLD else "report"
