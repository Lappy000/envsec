"""Data models and rendering for scan reports."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    INFO = "INFO"

    @property
    def color(self) -> str:
        return {
            Severity.LOW: "yellow",
            Severity.MEDIUM: "dark_orange",
            Severity.HIGH: "red",
            Severity.INFO: "blue",
        }[self]

    @property
    def weight(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
        }[self]


@dataclass
class Finding:
    """A single security finding from a check."""
    check_id: str
    module: str
    title: str
    severity: Severity
    description: str
    remediation: Optional[str] = None

    def to_dict(self) -> dict:
        result = {
            "check_id": self.check_id,
            "module": self.module,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
        }
        if self.remediation:
            result["remediation"] = self.remediation
        return result


@dataclass
class ScanReport:
    """Aggregated results from all check modules."""
    findings: list[Finding] = field(default_factory=list)
    checks_run: int = 0
    checks_passed: int = 0
    modules_run: list[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def has_high_severity(self) -> bool:
        return any(f.severity == Severity.HIGH for f in self.findings)

    @property
    def score(self) -> int:
        """Compute a 0-100 security score. Starts at 100, deducted per finding."""
        if self.checks_run == 0:
            return 0
        deductions = sum(f.severity.weight * 5 for f in self.findings)
        return max(0, 100 - deductions)

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in sorted(self.findings, key=lambda x: x.severity.weight, reverse=True):
            sev = f.severity.value
            if sev not in result:
                result[sev] = []
            result[sev].append(f)
        return result

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "checks_run": self.checks_run,
            "checks_passed": self.checks_passed,
            "findings_count": len(self.findings),
            "modules_run": self.modules_run,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_markdown(self) -> str:
        lines = [
            "# envsec Scan Report",
            "",
            f"**Score:** {self.score}/100",
            f"**Checks run:** {self.checks_run}",
            f"**Checks passed:** {self.checks_passed}",
            f"**Issues found:** {len(self.findings)}",
            "",
        ]
        if not self.findings:
            lines.append("No issues found.")
            return "\n".join(lines)

        lines.append("## Findings")
        lines.append("")
        for f in sorted(self.findings, key=lambda x: x.severity.weight, reverse=True):
            lines.append(f"### [{f.severity.value}] {f.title}")
            lines.append(f"- **Module:** {f.module}")
            lines.append(f"- **Check:** {f.check_id}")
            lines.append(f"- {f.description}")
            if f.remediation:
                lines.append(f"- **Fix:** {f.remediation}")
            lines.append("")
        return "\n".join(lines)


def render_terminal_report(report: ScanReport, console: Console) -> None:
    """Render the scan report as a rich terminal output."""
    score = report.score
    if score >= 80:
        score_color = "green"
    elif score >= 50:
        score_color = "yellow"
    else:
        score_color = "red"

    header = Text()
    header.append("Security Score: ", style="bold")
    header.append(f"{score}/100", style=f"bold {score_color}")
    header.append(f"  |  Checks: {report.checks_run}")
    header.append(f"  |  Passed: {report.checks_passed}")
    header.append(f"  |  Issues: {len(report.findings)}")

    console.print(Panel(header, title="envsec", border_style="blue"))

    if not report.findings:
        console.print("[green]No issues found. Environment looks secure.[/green]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", width=8)
    table.add_column("Module", style="cyan", width=12)
    table.add_column("Check", width=24)
    table.add_column("Description")

    for f in sorted(report.findings, key=lambda x: x.severity.weight, reverse=True):
        sev_text = Text(f.severity.value, style=f"bold {f.severity.color}")
        table.add_row(sev_text, f.module, f.title, f.description)

    console.print(table)

    # Print remediations for HIGH findings
    high_findings = [f for f in report.findings if f.severity == Severity.HIGH and f.remediation]
    if high_findings:
        console.print()
        console.print("[bold red]Recommended fixes for HIGH severity issues:[/bold red]")
        for f in high_findings:
            console.print(f"  [cyan]{f.title}:[/cyan] {f.remediation}")


def render_json_report(report: ScanReport) -> str:
    """Serialize the report as formatted JSON."""
    return json.dumps(report.to_dict(), indent=2)
