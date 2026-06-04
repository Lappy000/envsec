"""Scanner orchestrator that runs all registered check modules."""

from __future__ import annotations

from envsec.checks import ALL_CHECKS
from envsec.report import ScanReport, Finding, Severity


class EnvironmentScanner:
    """Coordinates running check modules and collecting results."""

    def __init__(self, skip_modules: set[str] | None = None) -> None:
        self.skip_modules = skip_modules or set()

    def run_all(self) -> ScanReport:
        """Execute all registered checks and aggregate into a report."""
        report = ScanReport()

        for module_name, check_fns in ALL_CHECKS.items():
            if module_name in self.skip_modules:
                continue

            report.modules_run.append(module_name)

            for check_fn in check_fns:
                report.checks_run += 1
                try:
                    findings = check_fn()
                    if not findings:
                        report.checks_passed += 1
                    else:
                        for f in findings:
                            report.add_finding(f)
                except Exception as exc:
                    report.add_finding(Finding(
                        check_id=f"{module_name}-error",
                        module=module_name,
                        title=f"Check failed: {check_fn.__name__}",
                        severity=Severity.INFO,
                        description=f"Check raised an exception: {exc}",
                    ))

        return report

    def run_module(self, module_name: str) -> ScanReport:
        """Execute checks from a single module."""
        report = ScanReport()

        if module_name not in ALL_CHECKS:
            return report

        report.modules_run.append(module_name)
        for check_fn in ALL_CHECKS[module_name]:
            report.checks_run += 1
            try:
                findings = check_fn()
                if not findings:
                    report.checks_passed += 1
                else:
                    for f in findings:
                        report.add_finding(f)
            except Exception as exc:
                report.add_finding(Finding(
                    check_id=f"{module_name}-error",
                    module=module_name,
                    title=f"Check failed: {check_fn.__name__}",
                    severity=Severity.INFO,
                    description=f"Check raised an exception: {exc}",
                ))

        return report
