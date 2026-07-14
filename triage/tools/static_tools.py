# triage/tools/static_tools.py
import hashlib
import math
import re
from pathlib import Path
from typing import Any

import magic
import pefile
from langchain.tools import tool
from pydantic import BaseModel, Field

from triage.state import Finding


class FileInput(BaseModel):
    file_path: str = Field(description="Absolute path to the binary sample")


_SUSPICIOUS_PATTERNS = [
    (r"(?i)https?://\S+", "url", "medium", 0.3),
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "ip_address", "medium", 0.3),
    (r"HKEY_[A-Z_]+", "registry_key", "medium", 0.2),
    (r"(?i)(?:cmd\.exe|powershell|wscript|cscript)", "shell_invocation", "high", 0.5),
    (r"(?i)VirtualAlloc|WriteProcessMemory|CreateRemoteThread", "suspicious_api_string", "high", 0.5),
]

_SUSPICIOUS_IMPORTS = {
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
    "CreateRemoteThread", "NtCreateThreadEx", "SetWindowsHookEx",
    "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
    "InternetOpenA", "InternetConnectA", "HttpSendRequestA",
    "WinExec", "ShellExecuteA", "ShellExecuteW",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    e = 0.0
    for count in freq.values():
        p = count / len(data)
        e -= p * math.log2(p)
    return round(e, 4)


@tool(args_schema=FileInput)
def file_identity(file_path: str) -> dict[str, Any]:
    """Return SHA-256 hash, magic file type, MIME type, extension, and size of a binary."""
    print("Start the file_identity tool")
    try:
        data = Path(file_path).read_bytes()
    except FileNotFoundError:
        return {"sha256": "", "file_type": "", "mime": "", "extension": Path(file_path).suffix.lower(), "size_bytes": 0, "findings": []}
    sha256 = hashlib.sha256(data).hexdigest()
    file_type = magic.from_file(file_path)
    mime = magic.from_file(file_path, mime=True)
    ext = Path(file_path).suffix.lower()

    findings: list[dict] = []
    if ext in (".exe", ".dll", ".sys") and "PE" not in file_type:
        findings.append(Finding(
            source="identity",
            signal="extension_type_mismatch",
            severity="medium",
            evidence=f"extension={ext} but magic='{file_type}'",
            weight=0.3,
        ).model_dump())

    return {
        "sha256": sha256,
        "file_type": file_type,
        "mime": mime,
        "extension": ext,
        "size_bytes": len(data),
        "findings": findings,
    }


@tool(args_schema=FileInput)
def compute_entropy(file_path: str) -> dict[str, Any]:
    """Compute overall and per-section Shannon entropy of a binary.
    Per-section entropy > 7.0 suggests packing or encryption."""
    print("Start the compute_entropy tool")
    try:
        data = Path(file_path).read_bytes()
    except FileNotFoundError:
        print(f"FileNotFound: {file_path}")
        return {"overall": 0.0, "sections": {}, "findings": []}
    overall = _entropy(data)

    sections: dict[str, float] = {}
    findings: list[dict] = []

    try:
        pe = pefile.PE(file_path, fast_load=True)
        try:
            for section in pe.sections:
                name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
                ent = section.get_entropy()
                print(f"calculated entropy: {ent}")
                sections[name] = round(ent, 4)
                if ent > 7.0:
                    findings.append(Finding(
                        source="entropy",
                        signal="high_entropy_section",
                        severity="high",
                        evidence=f"section '{name}' entropy={ent:.2f}",
                        weight=0.5,
                    ).model_dump())
        finally:
            pe.close()
    except pefile.PEFormatError:
        pass  # not a PE; overall entropy still valid

    return {"overall": overall, "sections": sections, "findings": findings}


@tool(args_schema=FileInput)
def extract_strings(file_path: str) -> dict[str, Any]:
    """Extract printable ASCII and UTF-16LE strings from a binary and flag suspicious patterns."""
    print("Start the extract_strings tool")
    try:
        data = Path(file_path).read_bytes()
    except FileNotFoundError:
        return {"strings": [], "count": 0, "findings": []}

    ascii_strings = [m.decode("ascii") for m in re.findall(rb"[\x20-\x7e]{4,}", data)]
    utf16_strings = [
        m.decode("utf-16-le")
        for m in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", data)
    ]
    all_strings = ascii_strings + utf16_strings

    findings: list[dict] = []
    for s in all_strings:
        for pattern, signal, severity, weight in _SUSPICIOUS_PATTERNS:
            if re.search(pattern, s):
                findings.append(Finding(
                    source="strings",
                    signal=signal,
                    severity=severity,  # type: ignore[arg-type]
                    evidence=s[:120],
                    weight=weight,
                ).model_dump())
                break  # one finding per string

    return {"strings": all_strings[:500], "count": len(all_strings), "findings": findings}


def _check_import_findings(imports: dict[str, list[str]]) -> list[dict]:
    findings: list[dict] = []
    for dll, funcs in imports.items():
        for func in funcs:
            if func in _SUSPICIOUS_IMPORTS:
                findings.append(Finding(
                    source="imports",
                    signal="suspicious_import",
                    severity="high",
                    evidence=f"{dll}::{func}",
                    weight=0.5,
                ).model_dump())
    return findings


@tool(args_schema=FileInput)
def parse_imports(file_path: str) -> dict[str, Any]:
    """Parse the PE Import Address Table (IAT). Flags process-injection and crypto APIs."""
    print("Start the parse_imports tool")
    try:
        pe = pefile.PE(file_path, fast_load=False)
    except (pefile.PEFormatError, FileNotFoundError):
        return {"imports": {}, "findings": []}

    imports: dict[str, list[str]] = {}
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace")
                funcs = [
                    imp.name.decode("utf-8", errors="replace")
                    for imp in entry.imports
                    if imp.name
                ]
                imports[dll] = funcs
    finally:
        pe.close()
    return {"imports": imports, "findings": _check_import_findings(imports)}


def _check_section_findings(sections: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for s in sections:
        if s["executable"] and s["writable"]:
            findings.append(Finding(
                source="sections",
                signal="rwx_section",
                severity="critical",
                evidence=f"section '{s['name']}' is executable+writable",
                weight=0.8,
            ).model_dump())
        if s["entropy"] > 7.0:
            findings.append(Finding(
                source="sections",
                signal="high_entropy_section",
                severity="high",
                evidence=f"section '{s['name']}' entropy={s['entropy']:.2f}",
                weight=0.5,
            ).model_dump())
        if s["virtual_size"] > 0 and s["raw_size"] > 0:
            ratio = s["virtual_size"] / s["raw_size"]
            if ratio > 10:
                findings.append(Finding(
                    source="sections",
                    signal="vsize_rawsize_mismatch",
                    severity="medium",
                    evidence=f"section '{s['name']}' vsize/rawsize ratio={ratio:.1f}",
                    weight=0.3,
                ).model_dump())
    return findings


@tool(args_schema=FileInput)
def parse_sections(file_path: str) -> dict[str, Any]:
    """Parse PE sections: name, sizes, entropy, and permission flags.
    RWX sections and vsize/rawsize mismatches indicate injection or packing."""
    print("Start the parse_sections tool")
    try:
        pe = pefile.PE(file_path, fast_load=True)
    except (pefile.PEFormatError, FileNotFoundError):
        return {"sections": [], "findings": []}

    sections = []
    try:
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            sections.append({
                "name": name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(section.get_entropy(), 4),
                "characteristics": hex(section.Characteristics),
                "executable": bool(section.Characteristics & 0x20000000),
                "writable": bool(section.Characteristics & 0x80000000),
            })
    finally:
        pe.close()
    return {"sections": sections, "findings": _check_section_findings(sections)}
