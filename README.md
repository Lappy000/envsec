# envsec

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

CLI tool that audits your local development environment for security misconfigurations, exposed secrets, and hardening opportunities.

## What it checks

| Module    | Checks |
|-----------|--------|
| `ssh`     | `.ssh/` permissions, key file permissions, client config hardening |
| `git`     | Commit signing, credential storage, plaintext `.git-credentials` |
| `env`     | `.env` file exposure, secrets in shell history, global gitignore |
| `network` | Databases/services bound to 0.0.0.0, Docker socket permissions |
| `tools`   | Availability of common dev tools (git, python, node, docker, ssh) |

## Install

```bash
pip install -e .
```

Or just run directly:

```bash
python -m envsec.cli scan
```

## Usage

```bash
# Full scan with terminal output
envsec scan

# JSON output for CI integration
envsec scan --format json

# Markdown report
envsec scan --format markdown

# Skip specific modules
envsec scan --skip network --skip tools

# Strict mode: exit 1 on HIGH severity findings
envsec scan --strict

# List available check modules
envsec checks

# Print version
envsec version
```

## Output formats

**Terminal** (default) — colored table with severity indicators and a security score.

**JSON** — machine-readable output for piping into other tools or CI checks:

```json
{
  "score": 75,
  "checks_run": 11,
  "checks_passed": 8,
  "findings_count": 3,
  "findings": [...]
}
```

**Markdown** — suitable for saving as a report or pasting into issues.

## CI Integration

Add to your CI pipeline to enforce environment hygiene:

```yaml
# GitHub Actions example
- name: Environment security audit
  run: |
    pip install envsec
    envsec scan --strict --format json
```

## Adding custom checks

Each check module is a collection of functions that return `list[Finding]`. To add a new check:

1. Add your check function to `envsec/checks.py`
2. Register the module with `register_module()`
3. Add the function to the `ALL_CHECKS` dispatcher dict

```python
def check_my_thing() -> list[Finding]:
    findings = []
    # ... your logic ...
    if problem_detected:
        findings.append(Finding(
            check_id="custom-001",
            module="custom",
            title="Something is wrong",
            severity=Severity.MEDIUM,
            description="Detailed explanation.",
            remediation="How to fix it.",
        ))
    return findings
```

## Requirements

- Python 3.9+
- click
- rich

## Development

Run the test suite:

```bash
pip install pytest
pytest
```

## License

MIT
