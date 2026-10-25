from pathlib import Path
from agentguard.manifest import (
    Manifest,
    ToolInfo,
    _hash_embed,
    _heuristic_destructive,
    build_index,
    heuristic_manifest,
    retrieve_chunks,
    retrieve_context,
    scan_project,
)


def test_hash_embed():
    vec = _hash_embed("hello world")
    assert len(vec) == 256
    norm = sum(x * x for x in vec) ** 0.5
    assert abs(norm - 1.0) < 1e-5


def test_heuristic_destructive():
    assert _heuristic_destructive("transfer_funds", "Move money to recipient") is True
    assert _heuristic_destructive("delete_user", None) is True
    assert _heuristic_destructive("get_weather", "Check current weather in city") is False


def test_manifest_routing():
    # Only base attacks
    m1 = Manifest(tools=[], rag={"present": False}, memory={"present": False})
    assert m1.routing() == ["prompt_injection", "secret_extraction"]

    # Destructive tool triggers tool_misuse and data_exfiltration
    m2 = Manifest(tools=[ToolInfo(name="transfer_funds", destructive=True)])
    assert "tool_misuse" in m2.routing()
    assert "data_exfiltration" in m2.routing()

    # Admin/multi_agent triggers privilege_escalation
    m3 = Manifest(tools=[ToolInfo(name="admin_override")], multi_agent=True)
    assert "privilege_escalation" in m3.routing()

    # RAG triggers rag_poisoning
    m4 = Manifest(rag={"present": True})
    assert "rag_poisoning" in m4.routing()

    # Memory triggers memory_persistence
    m5 = Manifest(memory={"present": True})
    assert "memory_persistence" in m5.routing()


def test_manifest_yaml_roundtrip(tmp_path: Path):
    manifest = Manifest(
        tools=[ToolInfo(name="test_tool", args=["a", "b"], destructive=True, doc="sample")],
        rag={"present": True, "ingestion": "local"},
        memory={"present": False},
        multi_agent=True,
    )
    yaml_file = tmp_path / "manifest.yaml"
    manifest.to_yaml(yaml_file)

    loaded = Manifest.from_yaml(yaml_file)
    assert len(loaded.tools) == 1
    assert loaded.tools[0].name == "test_tool"
    assert loaded.tools[0].destructive is True
    assert loaded.rag.get("present") is True
    assert loaded.multi_agent is True


def test_scan_samples_unsafe_tool():
    # Test AST scanning of samples/unsafe_tool
    sample_dir = Path("samples/unsafe_tool")
    if sample_dir.exists():
        manifest = heuristic_manifest(sample_dir)
        tool_names = [t.name for t in manifest.tools]
        assert "transfer_funds" in tool_names
        transfer = next(t for t in manifest.tools if t.name == "transfer_funds")
        assert transfer.destructive is True
        assert "tool_misuse" in manifest.routing()
        assert "data_exfiltration" in manifest.routing()


def test_chroma_build_index_and_retrieve_chunks(tmp_path: Path):
    code_file = tmp_path / "agent_code.py"
    code_file.write_text(
        """
def transfer_money(to: str, amount: float):
    # Sensitive banking transfer
    return True

async def send_webhook(url: str, payload: dict):
    # Sends webhook data
    return url

class AdminManager:
    def grant_admin(self, user):
        return True
""",
        encoding="utf-8",
    )

    collection = build_index(tmp_path, collection_name="test-manifest-index")
    assert collection.count() >= 3

    # Test query context
    ctx = retrieve_context(collection, "transfer_money", n_results=3)
    assert "transfer_money" in ctx

    # Test multi-query chunk retrieval
    chunks = retrieve_chunks(collection, ["send_webhook", "AdminManager"], n_results=3)
    assert len(chunks) >= 2
    found_texts = " ".join(c["text"] for c in chunks)
    assert "send_webhook" in found_texts or "AdminManager" in found_texts
