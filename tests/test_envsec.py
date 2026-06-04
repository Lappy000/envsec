"""Basic tests for the envsec scanner and report models."""

from __future__ import annotations

from envsec.report import Finding, ScanReport, Severity
from envsec.scanner import EnvironmentScanner
from envsec.checks import ALL_CHECKS, REGISTRY


def test_severity_weights_ordered():
    assert Severity.INFO.weight < Severity.LOW.weight
    assert Severity.LOW.weight < Severity.MEDIUM.weight
    assert Severity.MEDIUM.weight < Severity.HIGH.weight


def test_empty_report_score_zero():
    report = ScanReport()
    assert report.score == 0


def test_report_score_deducts_per_finding():
    report = ScanReport()
    report.checks_run = 5
    report.add_finding(Finding(
        check_id="t-1",
        module="test",
        title="example",
        severity=Severity.HIGH,
        description="d",
    ))
    # HIGH weight 3 * 5 = 15 deducted
    assert report.score == 85


def test_report_detects_high_severity():
    report = ScanReport()
    assert not report.has_high_severity()
    report.add_finding(Finding(
        check_id="t-2", module="test", title="x",
        severity=Severity.HIGH, description="d",
    ))
    assert report.has_high_severity()


def test_finding_to_dict_roundtrip():
    f = Finding(
        check_id="t-3", module="test", title="x",
        severity=Severity.MEDIUM, description="d", remediation="fix it",
    )
    d = f.to_dict()
    assert d["severity"] == "MEDIUM"
    assert d["remediation"] == "fix it"


def test_markdown_export_contains_score():
    report = ScanReport()
    report.checks_run = 3
    md = report.to_markdown()
    assert "envsec Scan Report" in md
    assert "Score:" in md


def test_scanner_runs_without_error():
    scanner = EnvironmentScanner()
    report = scanner.run_all()
    assert report.checks_run > 0
    assert isinstance(report.score, int)
    assert 0 <= report.score <= 100


def test_scanner_skip_module():
    scanner = EnvironmentScanner(skip_modules={"network", "tools", "env", "git", "ssh"})
    report = scanner.run_all()
    assert report.checks_run == 0
    assert report.modules_run == []


def test_registry_matches_dispatcher():
    # Every module in the dispatcher should be registered
    for module_name in ALL_CHECKS:
        assert module_name in REGISTRY
