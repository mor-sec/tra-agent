import pytest

from tra_core.artefacts import ArtefactError, GitArtefactSource
from tra_core.classification import ClassificationError
from tra_core.mcp_servers import build_artefacts_server, build_reference_server
from tra_core.schemas import Classification
from tra_core.tools import McpToolClient, ToolError, ToolSet


def test_labelled_artefact_loads(toolset):
    a = toolset.artefacts_get("git", "payments-portal-design.md")
    assert a["classification"] == "OFFICIAL_SENSITIVE"
    assert len(a["sha256"]) == 64


def test_unlabelled_and_protected_refused(tmp_path):
    (tmp_path / "nolabel.md").write_text("# design\n")
    (tmp_path / "secret.md").write_text("classification: PROTECTED\n# design\n")
    (tmp_path / "side.md").write_text("# design\n")
    (tmp_path / "side.md.label").write_text("OFFICIAL\n")
    src = GitArtefactSource(tmp_path)
    with pytest.raises(ArtefactError, match="no classification"):
        src.get("nolabel.md")
    with pytest.raises(ClassificationError):
        src.get("secret.md")
    assert src.get("side.md").classification is Classification.OFFICIAL


def test_path_traversal_refused(tmp_path):
    (tmp_path / "inside").mkdir()
    with pytest.raises(ArtefactError, match="outside"):
        GitArtefactSource(tmp_path / "inside").get("../../etc/passwd")


def test_clearance_checked_on_read(reference):
    from tests.conftest import EXAMPLES

    low = ToolSet(reference, {"git": GitArtefactSource(EXAMPLES)}, clearance_of=lambda: Classification.OFFICIAL)
    with pytest.raises(ToolError, match="clearance"):
        low.artefacts_get("git", "payments-portal-design.md")


def test_unknown_tool_refused(toolset):
    with pytest.raises(ToolError):
        toolset.call("register_write", {})


def test_threat_search_gates_ai_threats(reference):
    plain = {t.id for t in reference.threats.search("process", include_ai=False)}
    ai = {t.id for t in reference.threats.search("process", include_ai=True)}
    assert "TL-050" not in plain and "TL-050" in ai


def test_library_controls_exist_in_catalogue(reference):
    for t in reference.threats.threats:
        for c in t.controls:
            assert reference.controls.exists(c), f"{t.id} references unknown {c}"


async def test_tools_over_mcp_match_local(toolset):
    client = McpToolClient(build_reference_server(toolset))
    via_mcp = await client.call("controls_lookup", {"ids": ["CC-001", "CC-999"]})
    assert via_mcp["unknown"] == ["CC-999"]
    assert via_mcp["controls"][0]["iso27001"] == ["8.5", "5.17"]
    art = await McpToolClient(build_artefacts_server(toolset)).call(
        "artefacts_get", {"source": "git", "locator": "payments-portal-design.md"}
    )
    assert art["classification"] == "OFFICIAL_SENSITIVE"
