# triage/nodes/intake.py
from triage.state import TriageState
from triage.tools.static_tools import file_identity


def intake(state: TriageState) -> dict:
    """Hash the file, detect type, and seed sha256/file_type into state."""
    result = file_identity.invoke({"file_path": state["file_path"]})
    return {
        "sha256": result["sha256"],
        "file_type": result["file_type"],
        "static": {"identity": result},
        "findings": result["findings"],
    }
