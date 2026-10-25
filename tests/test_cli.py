from pathlib import Path
from click.testing import CliRunner
from agentguard.cli import main


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "AgentGuard" in result.output
    assert "init" in result.output
    assert "test" in result.output


def test_cli_init_no_llm(tmp_path: Path):
    runner = CliRunner()
    manifest_out = tmp_path / "out_manifest.yaml"
    result = runner.invoke(
        main,
        ["-v", "init", "samples/unsafe_tool", "--no-llm", "--manifest-out", str(manifest_out)],
    )
    assert result.exit_code == 0
    assert manifest_out.exists()
    assert "Wrote" in result.output
    assert "transfer_funds" in result.output


def test_cli_test_help():
    runner = CliRunner()
    result = runner.invoke(main, ["test", "--help"])
    assert result.exit_code == 0
    assert "--target-url" in result.output
    assert "--attacker-model" in result.output
    assert "--reporter-model" in result.output
