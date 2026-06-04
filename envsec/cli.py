"""CLI entry point for envsec."""

from __future__ import annotations

import sys

import click
from rich.console import Console
from rich.table import Table

from envsec.scanner import EnvironmentScanner
from envsec.report import render_terminal_report, render_json_report


console = Console()


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx: click.Context) -> None:
    """Audit your development environment for security misconfigurations."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(scan)


@main.command()
@click.option(
    "--format", "-f",
    type=click.Choice(["terminal", "json", "markdown"]),
    default="terminal",
    help="Output format.",
)
@click.option("--strict", is_flag=True, help="Exit with code 1 if any HIGH severity issues found.")
@click.option("--skip", multiple=True, help="Skip specific check modules (e.g. --skip ssh --skip git).")
def scan(format: str, strict: bool, skip: tuple[str, ...]) -> None:
    """Run all security checks against the current environment."""
    scanner = EnvironmentScanner(skip_modules=set(skip))
    report = scanner.run_all()

    if format == "json":
        click.echo(render_json_report(report))
    elif format == "markdown":
        click.echo(report.to_markdown())
    else:
        render_terminal_report(report, console)

    if strict and report.has_high_severity():
        sys.exit(1)


@main.command()
def version() -> None:
    """Print the envsec version."""
    from envsec import __version__
    click.echo(f"envsec {__version__}")


@main.command()
def checks() -> None:
    """List all available check modules."""
    from envsec.checks import REGISTRY
    table = Table(title="Available Checks")
    table.add_column("Module", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Checks", justify="right", style="green")

    for module_name, module_info in REGISTRY.items():
        table.add_row(
            module_name,
            module_info["description"],
            str(module_info["check_count"]),
        )

    console.print(table)


if __name__ == "__main__":
    main()
