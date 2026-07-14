# tests/conftest.py
import pytest
from pathlib import Path

SAMPLES = Path(__file__).parent.parent / "samples"

@pytest.fixture
def eicar_path():
    p = SAMPLES / "eicar.com"
    if not p.exists():
        pytest.skip("eicar.com not found in samples/")
    return str(p)

@pytest.fixture
def minimal_exe_path():
    p = SAMPLES / "minimal.exe"
    if not p.exists():
        pytest.skip("minimal.exe not found in samples/")
    return str(p)
