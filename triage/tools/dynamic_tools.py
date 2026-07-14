import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx
from langchain.tools import tool
from pydantic import BaseModel, Field

from triage.state import Finding

CAPE_BASE_URL = os.getenv("CAPE_URL", "http://localhost:8000")
CAPE_MAX_POLLS = int(os.getenv("CAPE_MAX_POLLS", "60"))
CAPE_POLL_INTERVAL = int(os.getenv("CAPE_POLL_INTERVAL", "5"))


class FileInput(BaseModel):
    file_path: str = Field(description="Absolute path to the binary sample")


@tool(args_schema=FileInput)
def detonate(file_path: str) -> dict[str, Any]:
    """Submit a binary to CAPEv2 sandbox, poll until complete, return the report JSON.
    On timeout or error, returns a degraded finding so the graph can continue."""
    print("Start the detonate tool")
    path = Path(file_path)
    try:
        with httpx.Client(base_url=CAPE_BASE_URL, timeout=30) as client:
            # Submit
            with open(file_path, "rb") as f:
                resp = client.post("/apiv2/tasks/create/file/", files={"file": (path.name, f)})
            resp.raise_for_status()
            task_id = resp.json()["data"]["task_id"]

            # Poll
            for _ in range(CAPE_MAX_POLLS):
                time.sleep(CAPE_POLL_INTERVAL)
                status_resp = client.get(f"/apiv2/tasks/view/{task_id}/")
                status_resp.raise_for_status()
                status = status_resp.json()["data"]["status"]
                if status == "reported":
                    break
            else:
                return {
                    "task_id": None,
                    "report": {},
                    "findings": [Finding(
                        source="dynamic",
                        signal="detonation_timeout",
                        severity="medium",
                        evidence=f"CAPE task did not complete after {CAPE_MAX_POLLS} polls",
                        weight=0.0,
                    ).model_dump()],
                }

            # Fetch report
            report_resp = client.get(f"/apiv2/tasks/get/report/{task_id}/")
            report_resp.raise_for_status()
            report = report_resp.json()["data"]

        score = report.get("info", {}).get("score", 0)
        findings: list[dict] = []
        if score >= 7:
            findings.append(Finding(
                source="dynamic",
                signal="high_cape_score",
                severity="critical",
                evidence=f"CAPE maliciousness score={score}",
                weight=0.8,
            ).model_dump())
        elif score >= 4:
            findings.append(Finding(
                source="dynamic",
                signal="medium_cape_score",
                severity="medium",
                evidence=f"CAPE maliciousness score={score}",
                weight=0.4,
            ).model_dump())

        return {"task_id": task_id, "report": report, "findings": findings}

    except Exception as exc:
        return {
            "task_id": None,
            "report": {},
            "findings": [Finding(
                source="dynamic",
                signal="detonation_failed",
                severity="medium",
                evidence=str(exc),
                weight=0.0,
            ).model_dump()],
        }


def _run_cli(cmd: list[str]) -> str:
    """Run an external CLI command, return stdout. Raises if binary not found or the command fails."""
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(cmd)}: {result.stderr.strip()}")
    return result.stdout


def _parse_pcap_with_pyshark(pcap_path: str) -> dict[str, list[str]]:
    import pyshark
    cap = pyshark.FileCapture(pcap_path, display_filter="ip", keep_packets=False)
    hosts: set[str] = set()
    dns: set[str] = set()
    http_hosts: set[str] = set()
    for pkt in cap:
        try:
            hosts.add(pkt.ip.dst)
        except AttributeError:
            pass
        try:
            if hasattr(pkt, "dns") and pkt.dns.qry_name:
                dns.add(pkt.dns.qry_name)
        except AttributeError:
            pass
        try:
            if hasattr(pkt, "http") and pkt.http.host:
                http_hosts.add(pkt.http.host)
        except AttributeError:
            pass
    cap.close()
    return {"hosts": list(hosts), "dns": list(dns), "http_hosts": list(http_hosts), "ja3": []}


@tool(args_schema=FileInput)
def run_capa(file_path: str) -> dict[str, Any]:
    """Run Mandiant capa on a binary or CAPE report to extract ATT&CK technique IDs."""
    print("Start the run_capa tool")
    try:
        if not shutil.which("capa"):
            raise FileNotFoundError("capa not found")
        raw = _run_cli(["capa", "-r", "./capa-rules", "--json", file_path])
        data = json.loads(raw) if raw.strip() else {}
        techniques: list[str] = []
        for rule in data.get("rules", {}).values():
            for attack in rule.get("meta", {}).get("attack", []):
                tid = attack.get("technique", "")
                if tid:
                    techniques.append(tid)
        findings: list[dict] = []
        if techniques:
            findings.append(Finding(
                source="capa",
                signal="attack_techniques_detected",
                severity="high",
                evidence=", ".join(set(techniques)),
                weight=0.6,
            ).model_dump())
        return {"techniques": list(set(techniques)), "findings": findings}
    except FileNotFoundError as exc:
        return {"techniques": [], "findings": [Finding(
            source="capa", signal="capa_unavailable", severity="low",
            evidence=str(exc), weight=0.0,
        ).model_dump()]}
    except Exception as exc:
        return {"techniques": [], "findings": [Finding(
            source="capa", signal="capa_error", severity="low",
            evidence=str(exc), weight=0.0,
        ).model_dump()]}


@tool(args_schema=FileInput)
def scan_yara(file_path: str) -> dict[str, Any]:
    """Scan a binary with yara-x using the bundled ruleset. Returns matched rule names."""
    print("Start the scan_yara tool")
    try:
        if not shutil.which("yr"):
            raise FileNotFoundError("yara-x (yr) not found")
        raw = _run_cli(["yr", "scan", file_path])
        matches = [line.split()[0] for line in raw.strip().splitlines() if line.strip()]
        findings: list[dict] = []
        if matches:
            findings.append(Finding(
                source="yara",
                signal="yara_rule_match",
                severity="high",
                evidence=", ".join(matches[:10]),
                weight=0.6,
            ).model_dump())
        return {"matches": matches, "findings": findings}
    except FileNotFoundError as exc:
        return {"matches": [], "findings": [Finding(
            source="yara", signal="yara_unavailable", severity="low",
            evidence=str(exc), weight=0.0,
        ).model_dump()]}
    except Exception as exc:
        return {"matches": [], "findings": [Finding(
            source="yara", signal="yara_error", severity="low",
            evidence=str(exc), weight=0.0,
        ).model_dump()]}


@tool(args_schema=FileInput)
def analyze_pcap(file_path: str) -> dict[str, Any]:
    """Parse a PCAP file for network IOCs: contacted hosts, DNS queries, HTTP hosts, JA3."""
    print("Start the analyze_pcap tool")
    try:
        iocs = _parse_pcap_with_pyshark(file_path)
        findings: list[dict] = []
        if iocs["hosts"] or iocs["dns"]:
            findings.append(Finding(
                source="pcap",
                signal="network_activity",
                severity="medium",
                evidence=f"hosts={iocs['hosts'][:5]}, dns={iocs['dns'][:5]}",
                weight=0.4,
            ).model_dump())
        return {**iocs, "findings": findings}
    except Exception as exc:
        return {"hosts": [], "dns": [], "http_hosts": [], "ja3": [], "findings": [Finding(
            source="pcap", signal="pcap_error", severity="low",
            evidence=str(exc), weight=0.0,
        ).model_dump()]}


@tool(args_schema=FileInput)
def analyze_memory(file_path: str) -> dict[str, Any]:
    """Run Volatility 3 plugins on a memory dump: pslist, malfind, netscan, ldrmodules."""
    print("Start the analyze_memory tool")
    try:
        vol_cmd = ["vol", "-f", file_path]
        pslist_raw = _run_cli(vol_cmd + ["windows.pslist"])
        malfind_raw = _run_cli(vol_cmd + ["windows.malfind"])
        netscan_raw = _run_cli(vol_cmd + ["windows.netscan"])
        ldr_raw = _run_cli(vol_cmd + ["windows.ldrmodules"])

        processes = [l for l in pslist_raw.splitlines() if l.strip() and not l.startswith("Offset")]
        injected = [l for l in malfind_raw.splitlines() if "MZ" in l or "VAD" in l]
        connections = [l for l in netscan_raw.splitlines() if "ESTABLISHED" in l or "CLOSE" in l]

        findings: list[dict] = []
        if injected:
            findings.append(Finding(
                source="memory",
                signal="injected_code_region",
                severity="critical",
                evidence=f"{len(injected)} malfind hits",
                weight=0.9,
            ).model_dump())
        if connections:
            findings.append(Finding(
                source="memory",
                signal="live_network_connections",
                severity="medium",
                evidence=f"{len(connections)} active connections at capture time",
                weight=0.4,
            ).model_dump())

        return {
            "processes": processes,
            "injected_regions": injected,
            "connections": connections,
            "ldrmodules": ldr_raw.splitlines()[:50],
            "findings": findings,
        }
    except FileNotFoundError as exc:
        return {
            "processes": [], "injected_regions": [], "connections": [], "ldrmodules": [],
            "findings": [Finding(
                source="memory", signal="volatility_unavailable", severity="low",
                evidence=str(exc), weight=0.0,
            ).model_dump()],
        }
    except Exception as exc:
        return {
            "processes": [], "injected_regions": [], "connections": [], "ldrmodules": [],
            "findings": [Finding(
                source="memory", signal="memory_analysis_error", severity="low",
                evidence=str(exc), weight=0.0,
            ).model_dump()],
        }
