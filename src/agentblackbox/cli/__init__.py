"""CLI entry point — placeholder for Phase 3."""

import typer

app = typer.Typer(
    name="abb",
    help="AgentBlackBox — The flight recorder for AI agents.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Show version."""
    from agentblackbox import __version__
    typer.echo(f"AgentBlackBox v{__version__}")

