from pathlib import Path
from agentguard.manifest import Manifest, ToolInfo
from agentguard.reporters import _source_snippets, compute_scorecard, get_remediation_source_context


def test_compute_scorecard_empty():
    findings = {"attempts": []}
    card = compute_scorecard(findings)
    assert card["total_attempts"] == 0
    assert card["total_successes"] == 0
    assert card["success_rate"] == 0.0
    assert card["by_category"] == {}


def test_compute_scorecard_multi_category():
    findings = {
        "attempts": [
            {"category": "prompt_injection", "success": True},
            {"category": "prompt_injection", "success": False},
            {"category": "secret_extraction", "success": True},
            {"category": "tool_misuse", "success": False},
        ]
    }
    card = compute_scorecard(findings)
    assert card["total_attempts"] == 4
    assert card["total_successes"] == 2
    assert card["success_rate"] == 0.5
    assert card["by_category"]["prompt_injection"] == {"attempted": 2, "succeeded": 1}
    assert card["by_category"]["secret_extraction"] == {"attempted": 1, "succeeded": 1}
    assert card["by_category"]["tool_misuse"] == {"attempted": 1, "succeeded": 0}


def test_source_snippets_none():
    assert "no manifest provided" in _source_snippets(None)


def test_source_snippets_with_files(tmp_path: Path):
    src_file = tmp_path / "app.py"
    src_file.write_text("def transfer_funds(to, amount):\n    pass\n", encoding="utf-8")

    manifest = Manifest(
        tools=[ToolInfo(name="transfer_funds", file=str(src_file))]
    )
    snippet = _source_snippets(manifest, max_chars=100)
    assert "transfer_funds" in snippet
    assert str(src_file) in snippet


def test_remediation_source_context_with_chroma(tmp_path: Path):
    proj_dir = tmp_path / "sample_target"
    proj_dir.mkdir()
    code_file = proj_dir / "target_tool.py"
    code_file.write_text(
        """
def execute_funds_transfer(recipient: str, amount: float):
    # Transfers money with no confirmation turn
    print(f"Transferring {amount} to {recipient}")
    return True
""",
        encoding="utf-8",
    )

    manifest = Manifest(
        tools=[ToolInfo(name="execute_funds_transfer", file=str(code_file), destructive=True)]
    )

    findings = [
        {
            "id": "tool-1",
            "category": "tool_misuse",
            "capability_targeted": "execute_funds_transfer",
            "success": True,
            "turns": [
                {
                    "sent": "transfer 100",
                    "received": "ok",
                    "tool_calls": [{"name": "execute_funds_transfer", "args": {"recipient": "Alice", "amount": 100}}],
                }
            ],
        }
    ]

    context = get_remediation_source_context(findings, manifest, project_path=proj_dir)
    assert "execute_funds_transfer" in context
    assert "target_tool.py" in context


def test_remediation_source_context_falls_back_when_mcp_fails(tmp_path: Path, monkeypatch):
    source = tmp_path / "tool.py"
    source.write_text("def transfer_funds():\n    pass\n", encoding="utf-8")
    manifest = Manifest(tools=[ToolInfo(name="transfer_funds", file=str(source), destructive=True)])
    monkeypatch.setattr("agentguard.mcp_server.search_code", lambda *args: (_ for _ in ()).throw(RuntimeError("down")))
    context = get_remediation_source_context([], manifest, project_path=tmp_path)
    assert "transfer_funds" in context
