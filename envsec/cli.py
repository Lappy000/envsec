"""CLI entry point for envsec."""

from __future__ import annotations

import json
import sys
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from envsec.scanner import EnvironmentScanner
from envsec.report import ScanReport, render_terminal_report, render_json_report


console = Console()


@click.group(invoke_without_command=True)
@click.option(
    "--format", "-f",
    type=click.Choice(["terminal", "json", "markdown"]),
    default="terminal",
    help="Output format.",
)
@click.option("--strict", is_flag=True, help="Exit with code 1 if any HIGH severity issues found.")
@click.option("--skip", multiple=True, help="Skip specific check modules (e.g. --skip ssh --skip git).")
@click.pass_context
def main(ctx: click.Context, format: str, strict: bool, skip: tuple[str, ...]) -> None:
    """Audit your development environment for security misconfigurations."""
    ctx.ensure_object(dict)
    ctx.obj["format"] = format
    ctx.obj["strict"] = strict
    ctx.obj["skip"] = set(skip)

    if ctx.invoked_subcommand is None:
        ctx.invoke(scan)


@main.command()
@click.pass_context
def scan(ctx: click.Context) -> None:
    """Run all security checks against the current environment."""
    fmt = ctx.obj.get("format", "terminal")
    strict = ctx.obj.get("strict", False)
    skip_modules = ctx.obj.get("skip", set())

    scanner = EnvironmentScanner(skip_modules=skip_modules)
    report = scanner.run_all()

    if fmt == "json":
        click.echo(render_json_report(report))
    elif fmt == "markdown":
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
