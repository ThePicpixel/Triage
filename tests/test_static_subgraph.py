# tests/test_static_subgraph.py
import pytest
from triage.nodes.static import static_graph


def test_static_subgraph_populates_findings(eicar_path):
    result = static_graph.invoke({"file_path": eicar_path, "findings": []})
    assert "findings" in result
    assert isinstance(result["findings"], list)
    assert "static" in result
    assert "sha256" in result


def test_static_subgraph_sets_sha256(eicar_path):
    result = static_graph.invoke({"file_path": eicar_path, "findings": []})
    assert len(result["sha256"]) == 64


def test_static_subgraph_returns_file_type(eicar_path):
    result = static_graph.invoke({"file_path": eicar_path, "findings": []})
    assert isinstance(result["file_type"], str)
    assert len(result["file_type"]) > 0
