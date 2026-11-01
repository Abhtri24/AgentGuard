import json
from pathlib import Path
from typing import Optional

import click

from agentguard.attackers import run_attack_suite_sync
from agentguard.config import AgentGuardConfig, get_config, set_config
from agentguard.events import JSONLFileSink, get_event_bus
from agentguard.logging import get_logger, setup_logging
from agentguard.manifest import Manifest, synthesize
from agentguard.reporters import compute_scorecard, generate_report
from agentguard.schemas import TargetProfile
from agentguard.target import Target

logger = get_logger("cli")


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose debug logging.")
@click.option("-q", "--quiet", is_flag=True, help="Enable quiet mode (errors only).")
@click.option("--config", "config_file", type=click.Path(exists=True, dir_okay=False), help="Path to custom agentguard.yaml configuration file.")
@click.pass_context
def main(ctx: click.Context, verbose: bool, quiet: bool, config_file: Optional[str]) -> None:
    """AgentGuard — automated red-teaming for AI agent applications."""
    ctx.ensure_object(dict)
    setup_logging(verbose=verbose, quiet=quiet)
    cfg = AgentGuardConfig.load(config_path=config_file)
    set_config(cfg)
    ctx.obj["config"] = cfg


@main.command()
@click.argument("project_path", type=click.Path(exists=True, file_okay=False))
@click.option("--manifest-out", default=None,
              help="Where to write the generated manifest.yaml (default: <project_path>/manifest.yaml)")
@click.option("--no-llm", is_flag=True, help="Skip LLM synthesis, use AST-only heuristic verdicts.")
def init(project_path: str, manifest_out: str | None, no_llm: bool) -> None:
    """Statically scan PROJECT_PATH and write a capability manifest.

    Never executes the target — pure static analysis. Safe to run against
    any project before deciding whether to run `agentguard test` against it.
    """
    out_path = Path(manifest_out) if manifest_out else Path(project_path) / "manifest.yaml"
    click.echo(f"Scanning {project_path} ...")
    manifest = synthesize(project_path, use_llm=not no_llm)
    manifest.to_yaml(out_path)

    click.echo(f"Wrote {out_path}")
    click.echo(f"  tools: {[t.name for t in manifest.tools]} "
               f"(destructive: {[t.name for t in manifest.tools if t.destructive]})")
    click.echo(f"  rag: {manifest.rag.get('present')}  memory: {manifest.memory.get('present')}")
    click.echo(f"  attacker categories this manifest routes to: {manifest.routing()}")


@main.command()
@click.argument("project_path", type=click.Path(exists=True, file_okay=False))
@click.option("--target-url", required=True, help="URL of the already-running target (see agentguard.adapter.serve()).")
@click.option("--manifest", "manifest_path", default=None,
              help="Path to an existing manifest.yaml (default: <project_path>/manifest.yaml, generated if missing).")
@click.option("--findings-out", default="findings.json", help="Where to write findings.json.")
@click.option("--report-out", default="report.md", help="Where to write report.md.")
@click.option("--canary", "canaries", multiple=True, help="Known canary string(s) to check for in target responses. Repeatable.")
@click.option("--max-probes", default=None, type=int, help="Max probes per attacker category (default: from config).")
@click.option("--attacker-model", default=None, help="Override LLM model used by attacker agents.")
@click.option("--reporter-model", default=None, help="Override LLM model used by reporter agents.")
def test(project_path: str, target_url: str, manifest_path: str | None,
         findings_out: str, report_out: str, canaries: tuple[str, ...],
         max_probes: Optional[int], attacker_model: Optional[str],
         reporter_model: Optional[str]) -> None:
    """Run the full pipeline against a live target: manifest -> attack -> report.

    The target must already be running and reachable at --target-url (start
    it separately with `uvicorn <your_app>:app`, where your_app used
    @expose/@watch from agentguard.adapter). This command never starts a
    target process itself.
    """
    get_event_bus().subscribe(JSONLFileSink("trace.jsonl"))
    manifest_file = Path(manifest_path) if manifest_path else Path(project_path) / "manifest.yaml"
    if manifest_file.exists():
        click.echo(f"Loading manifest from {manifest_file}")
        manifest = Manifest.from_yaml(manifest_file)
    else:
        click.echo(f"No manifest found at {manifest_file}, generating one first...")
        manifest = synthesize(project_path)
        manifest.to_yaml(manifest_file)
        click.echo(f"Wrote {manifest_file}")

    click.echo(f"Routing to attacker categories: {manifest.routing()}")

    target = Target(target_url)
    try:
        health = target.health()
    except Exception as exc:
        raise click.ClickException(f"Could not connect to target at {target_url}: {exc}")

    if not health.get("entrypoint_registered"):
        raise click.ClickException(
            f"Target at {target_url} has no @expose entrypoint registered — check it's the right process."
        )

    probes = max_probes if max_probes is not None else get_config().max_probes
    profile = TargetProfile(
        tools=[tool.name for tool in manifest.tools],
        has_rag=bool(manifest.rag.get("present")),
        has_memory=bool(manifest.memory.get("present")),
    )

    click.echo(f"Attacking {target_url} ...")
    sink = None
    try:
        sink = run_attack_suite_sync(
            target,
            manifest,
            canaries=list(canaries),
            max_probes=probes,
            model=attacker_model,
            budget=None,
            profile=profile,
        )
    finally:
        if sink is not None:
            findings_data = {
                "target": sink.target_desc,
                "manifest_summary": sink.manifest_summary,
                "attempts": sink.session_state.get("findings", [a.model_dump(mode="json") for a in sink.attempts]),
            }
            Path(findings_out).write_text(json.dumps(findings_data, indent=2), encoding="utf-8")
            click.echo(f"Wrote {findings_out}")

    if getattr(sink, "_budget", None) is not None:
        logger.info("Budget usage: %s", sink._budget.usage_report())

    scorecard = compute_scorecard(findings_data)
    click.echo(f"Scorecard: {scorecard['total_successes']}/{scorecard['total_attempts']} "
               f"attacks succeeded ({scorecard['success_rate']:.0%})")
    for cat, row in scorecard["by_category"].items():
        click.echo(f"  {cat}: {row['succeeded']}/{row['attempted']}")

    click.echo("Generating report (offline, no further contact with the target)...")
    generate_report(
        findings_out,
        report_out,
        manifest_path=str(manifest_file),
        model=reporter_model,
        project_path=project_path,
    )
    click.echo(f"Wrote {report_out}")


if __name__ == "__main__":
    main()
