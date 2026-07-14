# triage

An agentic malware-triage pipeline built on [LangGraph](https://github.com/langchain-ai/langgraph). It ingests an arbitrary binary, runs static analysis (entropy, strings, imports, sections), conditionally detonates it in a sandbox for dynamic/behavioral analysis (CAPEv2, capa, YARA, pcap, memory forensics), and synthesizes a structured verdict — `benign` / `suspicious` / `malicious` / `inconclusive` — with evidence and MITRE ATT&CK mapping via a local LLM (Ollama).

> ⚠️ **This pipeline detonates untrusted binaries.** Be sure to deploy your CAPEv2 sandbox properly before running it against anything you didn't write yourself. Never point `file_path` at a sample outside an isolated analysis environment.

## How it works

```
              ┌─────────┐
 sample ───►  │ intake  │  sha256, file type
              └────┬────┘
                   │
        ┌──────────▼──────────┐
        │  static_analysis    │  parallel fan-out (Send API):
        │  (subgraph)         │  entropy · strings · imports · sections
        └──────────┬──────────┘
                   │
            ┌──────▼──────┐
            │ triage_gate │  conditional edge: weighted finding score ≥ 0.5?
            └──┬───────┬──┘
    suspicious │       │ benign-enough
               │       │
    ┌──────────▼─────┐ │
    │ dynamic_runner │ │  subgraph: detonate (CAPE) → capa · yara · pcap · memory
    └──────────┬─────┘ │
               │       │
              ┌▼───────▼┐
              │ report  │  LLM (Ollama) synthesizes a structured Verdict
              └─────────┘
```

State (`triage/state.py`) is a single `TypedDict` threaded through every node. Parallel workers append to a shared `findings` list via an `add` reducer, and each subgraph (`static`, `dynamic`, `memory`) shallow-merges its dict into state without clobbering siblings. Dynamic analysis is skipped whenever the static risk score is low, and a failed or timed-out detonation degrades to a finding rather than crashing the graph — the report node always runs.

## Requirements

- Python **3.11+**
- [Ollama](https://ollama.com/) running locally, with a model pulled (defaults to `llama3.1:8b` but also tested on `gemma4:e4b`) — used for the final verdict synthesis
- Optional external tools, each degrades gracefully to a low-severity "unavailable" finding if missing:
  - [`capa`](https://github.com/mandiant/capa) on `PATH` — ATT&CK technique extraction
  - [`yr`](https://github.com/VirusTotal/yara-x) (YARA-X) on `PATH` — rule matching
  - [Volatility 3](https://github.com/volatilityfoundation/volatility3) (`python3 -m volatility3.cli`) — memory forensics
  - `libmagic` (needed by `python-magic`; on Debian/Ubuntu: `apt install libmagic1`, on macOS: `brew install libmagic`)
- A reachable [CAPEv2](https://github.com/kevoreilly/CAPEv2) REST API for actual detonation (see [Sandbox / lab setup](#sandbox--lab-setup) below) — without it, `detonate` times out gracefully and the pipeline still produces a report from static findings alone

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# pull the model used for report synthesis
ollama pull llama3.1:8b
```

## Configuration

All configuration is via environment variables; every one has a sane default.

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_MODEL` | `llama3.1:8b` | Model used by the report node for verdict synthesis |
| `REPORTS_DIR` | `reports` | Where `.md` and `.json` reports are written |
| `CAPE_URL` | `http://localhost:8000` | Base URL of the CAPEv2 REST API |
| `CAPE_MAX_POLLS` | `60` | Max polling attempts while waiting for a detonation to finish |
| `CAPE_POLL_INTERVAL` | `5` | Seconds between polls |

## Usage

### Single sample

```python
from triage.graph import graph

result = graph.invoke({"file_path": "/path/to/sample", "findings": []})

print(result["verdict"])       # structured Verdict dict
print(result["report_path"])   # reports/<name>-<hash8>.md
print(result["json_path"])     # reports/<name>-<hash8>.json
```

Each run writes a Markdown report (verdict, confidence, key evidence, ATT&CK table, IOCs) and a JSON dump of the full state (findings, static/dynamic/memory data, verdict) to `REPORTS_DIR`.

### Batch / corpus mode

Run the graph over every file in a directory and get a CSV summary:

```bash
python -m triage.batch samples/            # defaults to reports/ for output
python -m triage.batch samples/ my_output_dir
```

This writes `my_output_dir/batch-<timestamp>.csv` with one row per sample: `filename, sha256, classification, confidence, report_path, error`. A sample that raises during processing is recorded with `classification=error` instead of aborting the whole batch.

### Smoke test

The EICAR test string (`samples/eicar.com`) is a safe, standard way to exercise the full pipeline end-to-end without handling live malware:

```python
from triage.graph import graph
result = graph.invoke({"file_path": "samples/eicar.com", "findings": []})
```

## Sandbox / lab setup

Dynamic analysis requires a running CAPEv2 instance reachable at `CAPE_URL`.

**Safety rules, non-negotiable:**
- Never run an unidentified binary outside an isolated environment (container/VM with no real network route).
- Take/restore a clean detonation environment between every sample — never reuse a "dirty" worker.
- Only analyze samples you're authorized to handle.

## Testing

```bash
pytest
```

Tests that need `samples/eicar.com` or `samples/minimal.exe` skip automatically if those files aren't present. External tools (CAPE, capa, yara-x, Volatility) are mocked in tests — no live sandbox is required to run the suite.

## Project layout

```
triage/
├── state.py                 # TriageState TypedDict, Finding & Verdict pydantic models
├── graph.py                 # top-level graph: static → triage_gate → (dynamic |) → report
├── batch.py                 # corpus mode: directory in, CSV of verdicts out
├── nodes/
│   ├── intake.py             # hash + file-type identification
│   ├── static.py              # static subgraph, parallel fan-out over static tools
│   ├── triage_gate.py         # conditional edge: weighted finding score
│   ├── dynamic.py             # dynamic subgraph: detonate then fan out to capa/yara/pcap/memory
│   └── report.py              # LLM verdict synthesis + Markdown/JSON report rendering
└── tools/
    ├── static_tools.py        # file_identity, compute_entropy, extract_strings, parse_imports, parse_sections
    └── dynamic_tools.py       # detonate (CAPE), run_capa, scan_yara, analyze_pcap, analyze_memory

samples/                     # EICAR + minimal PE test fixtures
reports/                     # generated .md / .json triage reports (gitignored)
tests/                       # pytest suite, mocks external tools/sandbox
```

## Findings & Verdict schema

Every analyzer emits normalized findings that feed the triage gate and the final report:

```python
{"source": "entropy", "signal": "high_entropy_section",
 "severity": "high", "evidence": "section '.text' entropy=7.42", "weight": 0.5}
```

The report node asks the LLM to ground its answer strictly in these findings and choose `inconclusive` over guessing:

```python
class Verdict(BaseModel):
    classification: Literal["benign", "suspicious", "malicious", "inconclusive"]
    confidence: float          # 0–1
    summary: str
    key_evidence: list[str]
    mitre_attack: list[str]    # ATT&CK technique IDs, from capa
    iocs: list[str]            # IPs, domains, hashes
```
