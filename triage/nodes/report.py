import json
import os
from pathlib import Path
from typing import Any

from langchain_ollama import ChatOllama
from langchain_core.output_parsers import PydanticOutputParser

from triage.state import TriageState, Verdict

REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "reports"))
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

_parser = PydanticOutputParser(pydantic_object=Verdict)
_llm = ChatOllama(model=OLLAMA_MODEL)

_SYSTEM_PROMPT = (
    "You are a malware analyst. Synthesize only the evidence provided. "
    "Never speculate beyond what is in the data. "
    "Choose 'inconclusive' when signals are weak or contradictory. "
    "Return ONLY valid JSON matching this schema:\n"
    "{format_instructions}"
)

_USER_PROMPT = (
    "SHA256: {sha256}\n"
    "File type: {file_type}\n"
    "Findings:\n{findings}\n"
    "ATT&CK techniques: {mitre_attack}\n"
    "Network IOCs: {iocs}\n"
    "Emit the Verdict JSON."
)


def _invoke_ollama(state: TriageState) -> dict[str, Any]:
    techniques = []
    iocs: list[str] = []
    for key, val in state.get("dynamic", {}).items():
        if isinstance(val, dict):
            techniques.extend(val.get("techniques", []))
            iocs.extend(val.get("hosts", []))
            iocs.extend(val.get("dns", []))

    system = _SYSTEM_PROMPT.format(
        format_instructions=_parser.get_format_instructions()
    )
    user = _USER_PROMPT.format(
        sha256=state["sha256"],
        file_type=state["file_type"],
        findings=json.dumps(state["findings"], indent=2),
        mitre_attack=", ".join(set(techniques)) or "none",
        iocs=", ".join(set(iocs)) or "none",
    )

    for attempt in range(2):
        try:
            raw = _llm.invoke([("system", system), ("human", user)])
            verdict: Verdict = _parser.parse(raw.content)
            return verdict.model_dump()
        except Exception as err:
            print(f"ERROR: {err}")
            if attempt == 0:
                user += f"\n\nError: {err}. Return valid JSON only."
            else:
                return Verdict(
                    classification="inconclusive",
                    confidence=0.0,
                    summary="LLM output could not be parsed.",
                    key_evidence=[],
                    mitre_attack=list(set(techniques)),
                    iocs=list(set(iocs)),
                ).model_dump()


def _render_markdown(state: TriageState, verdict: dict) -> str:
    cls = verdict["classification"].upper()
    conf_pct = int(verdict["confidence"] * 100)
    evidence_lines = "\n".join(f"- {e}" for e in verdict["key_evidence"])
    attack_rows = "\n".join(
        f"| {t} | — |" for t in verdict["mitre_attack"]
    ) or "| — | No techniques detected |"
    ioc_lines = "\n".join(f"- `{i}`" for i in verdict["iocs"]) or "- None"

    return f"""# Triage Report

**Verdict:** `{cls}`
**Confidence:** {conf_pct}%
**SHA256:** `{state['sha256']}`
**File type:** {state['file_type']}

## Summary

{verdict['summary']}

## Key Evidence

{evidence_lines}

## MITRE ATT&CK

| Technique ID | Description |
|---|---|
{attack_rows}

## Indicators of Compromise

{ioc_lines}
"""


def report_node(state: TriageState) -> dict:
    """Synthesise all findings into a Verdict via Ollama, write .md and .json reports."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    binary_name = Path(state["file_path"]).stem
    short_hash = state["sha256"][:8]
    base_name = f"{binary_name}-{short_hash}"

    verdict = _invoke_ollama(state)
    md_content = _render_markdown(state, verdict)

    md_path = REPORTS_DIR / f"{base_name}.md"
    json_path = REPORTS_DIR / f"{base_name}.json"

    md_path.write_text(md_content)
    json_path.write_text(json.dumps({
        "verdict": verdict,
        "findings": state["findings"],
        "sha256": state["sha256"],
        "file_type": state["file_type"],
        "static": state["static"],
        "dynamic": state["dynamic"],
        "memory": state["memory"],
    }, indent=2))

    return {
        "verdict": verdict,
        "report_path": str(md_path),
        "json_path": str(json_path),
    }
