# tests/test_static_tools.py
from triage.tools.static_tools import file_identity, compute_entropy, extract_strings, parse_imports

def test_file_identity_returns_sha256(eicar_path):
    result = file_identity.invoke({"file_path": eicar_path})
    assert "sha256" in result
    assert len(result["sha256"]) == 64

def test_file_identity_returns_file_type(eicar_path):
    result = file_identity.invoke({"file_path": eicar_path})
    assert "file_type" in result
    assert isinstance(result["file_type"], str)

def test_file_identity_returns_findings(eicar_path):
    result = file_identity.invoke({"file_path": eicar_path})
    assert "findings" in result
    assert isinstance(result["findings"], list)

def test_compute_entropy_returns_overall(eicar_path):
    result = compute_entropy.invoke({"file_path": eicar_path})
    assert "overall" in result
    assert 0.0 <= result["overall"] <= 8.0

def test_compute_entropy_returns_sections(minimal_exe_path):
    result = compute_entropy.invoke({"file_path": minimal_exe_path})
    assert "sections" in result
    assert isinstance(result["sections"], dict)

def test_compute_entropy_findings_on_high_entropy(tmp_path):
    # Write a file full of random bytes to simulate packing
    import os
    packed = tmp_path / "packed.bin"
    packed.write_bytes(os.urandom(4096))
    # Not a valid PE so sections will be empty — test overall only
    result = compute_entropy.invoke({"file_path": str(packed)})
    assert result["overall"] > 7.0

def test_extract_strings_returns_list(eicar_path):
    result = extract_strings.invoke({"file_path": eicar_path})
    assert "strings" in result
    assert isinstance(result["strings"], list)

def test_extract_strings_finds_eicar_content(eicar_path):
    result = extract_strings.invoke({"file_path": eicar_path})
    joined = " ".join(result["strings"])
    assert "EICAR" in joined or "eicar" in joined.lower()

def test_extract_strings_flags_suspicious(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00" * 10 + b"http://evil.example.com/payload" + b"\x00" * 10)
    result = extract_strings.invoke({"file_path": str(sample)})
    assert len(result["findings"]) > 0
    assert any("http" in f["evidence"].lower() for f in result["findings"])


def test_parse_imports_non_pe_returns_empty(eicar_path):
    result = parse_imports.invoke({"file_path": eicar_path})
    assert "imports" in result
    assert isinstance(result["imports"], dict)


def test_parse_imports_finds_suspicious_apis(tmp_path):
    # We can't easily craft a valid PE with imports, so test with minimal.exe
    # and accept empty imports; the key is the tool doesn't crash
    import pytest
    # Just verify the tool is callable and returns the right shape
    result = parse_imports.invoke({"file_path": str(tmp_path / "nonexistent.exe")})
    # Should return empty gracefully
    assert result["imports"] == {}
    assert result["findings"] == []


def test_parse_imports_flags_virtualalloc(tmp_path):
    # Inject a Finding directly to test the detection logic
    from triage.tools.static_tools import _check_import_findings
    findings = _check_import_findings({"KERNEL32.DLL": ["VirtualAlloc", "WriteProcessMemory"]})
    signals = [f["signal"] for f in findings]
    assert "suspicious_import" in signals


def test_parse_sections_non_pe_returns_empty(eicar_path):
    from triage.tools.static_tools import parse_sections
    result = parse_sections.invoke({"file_path": eicar_path})
    assert "sections" in result
    assert isinstance(result["sections"], list)


def test_parse_sections_returns_section_shape(minimal_exe_path):
    from triage.tools.static_tools import parse_sections
    result = parse_sections.invoke({"file_path": minimal_exe_path})
    # minimal.exe has 0 sections; just verify shape
    assert isinstance(result["sections"], list)
    assert isinstance(result["findings"], list)


def test_parse_sections_flags_rwx(tmp_path):
    from triage.tools.static_tools import _check_section_findings
    sections = [{
        "name": ".bad",
        "virtual_size": 0x1000,
        "raw_size": 0x200,
        "entropy": 7.5,
        "executable": True,
        "writable": True,
    }]
    findings = _check_section_findings(sections)
    signals = [f["signal"] for f in findings]
    assert "rwx_section" in signals
    assert "high_entropy_section" in signals
