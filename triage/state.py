from typing import Annotated, Literal
from typing_extensions import TypedDict
from operator import add
from pydantic import BaseModel, Field


def _merge_dicts(a: dict, b: dict) -> dict:
    """Shallow-merge two dicts; reducer for parallel writes to static/dynamic/memory."""
    return {**a, **b}


class Finding(BaseModel):
    source: str
    signal: str
    severity: Literal["low", "medium", "high", "critical"]
    evidence: str
    weight: float = Field(ge=0.0, le=1.0)


class Verdict(BaseModel):
    classification: Literal["benign", "suspicious", "malicious", "inconclusive"]
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    key_evidence: list[str]
    mitre_attack: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)


class TriageState(TypedDict):
    file_path: str
    sha256: str
    file_type: str
    static: Annotated[dict, _merge_dicts]
    dynamic: Annotated[dict, _merge_dicts]
    memory: Annotated[dict, _merge_dicts]
    findings: Annotated[list, add]
    verdict: dict
    report_path: str
    json_path: str
