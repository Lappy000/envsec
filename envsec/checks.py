"""Check module registry and individual security checks."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import platform
from pathlib import Path
from typing import Callable, Generator

from envsec.report import Finding, Severity


# --- Registry ---

REGISTRY: dict[str, dict] = {}


def register_module(name: str, description: str, check_count: int) -> None:
    REGISTRY[name] = {"description": description, "check_count": check_count}


# --- Utility ---

def _run_cmd(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", "command timed out"


def _home() -> Path:
    return Path.home()


def _is_windows() -> bool:
    return platform.system() == "Windows"


# --- SSH Checks ---

def check_ssh_dir_permissions() -> list[Finding]:
    """Verify .ssh directory and key file permissions."""
    findings: list[Finding] = []
    ssh_dir = _home() / ".ssh"

    if not ssh_dir.exists():
        findings.append(Finding(
            check_id="ssh-001",
            module="ssh",
            title="No .ssh directory",
            severity=Severity.INFO,
            description="No ~/.ssh directory found. SSH not configured.",
        ))
        return findings

    if not _is_windows():
        ssh_stat = ssh_dir.stat()
        mode = oct(ssh_stat.st_mode)[-3:]
        if mode != "700":
            findings.append(Finding(
                check_id="ssh-002",
                module="ssh",
                title="Weak .ssh dir permissions",
                severity=Severity.HIGH,
                description=f"~/.ssh has permissions {mode}, expected 700.",
                remediation="chmod 700 ~/.ssh",
            ))

    # Check for private keys with weak permissions
    key_files = ["id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"]
    for key_name in key_files:
        key_path = ssh_dir / key_name
        if key_path.exists() and not _is_windows():
            key_mode = oct(key_path.stat().st_mode)[-3:]
            if key_mode != "600":
                findings.append(Finding(
                    check_id="ssh-003",
                    module="ssh",
                    title=f"Weak permissions on {key_name}",
                    severity=Severity.HIGH,
                    description=f"~/.ssh/{key_name} has permissions {key_mode}, expected 600.",
                    remediation=f"chmod 600 ~/.ssh/{key_name}",
                ))

    return findings


def check_ssh_config_hardening() -> list[Finding]:
    """Check SSH client config for security best practices."""
    findings: list[Finding] = []
    ssh_config = _home() / ".ssh" / "config"

    if not ssh_config.exists():
        findings.append(Finding(
            check_id="ssh-004",
            module="ssh",
            title="No SSH client config",
            severity=Severity.LOW,
            description="No ~/.ssh/config found. Consider adding hardening options.",
            remediation="Create ~/.ssh/config with HashKnownHosts and ServerAliveInterval settings.",
        ))
        return findings

    try:
        content = ssh_config.read_text(errors="replace")
    except PermissionError:
        return findings

    if "HashKnownHosts yes" not in content:
        findings.append(Finding(
            check_id="ssh-005",
            module="ssh",
            title="Known hosts not hashed",
            severity=Severity.LOW,
            description="SSH config does not set HashKnownHosts yes.",
            remediation="Add 'HashKnownHosts yes' to ~/.ssh/config.",
        ))

    return findings


def check_ssh_authorized_keys() -> list[Finding]:
    """Check for overly permissive authorized_keys."""
    findings: list[Finding] = []
    auth_keys = _home() / ".ssh" / "authorized_keys"

    if auth_keys.exists() and not _is_windows():
        ak_mode = oct(auth_keys.stat().st_mode)[-3:]
        if ak_mode not in ("600", "644"):
            findings.append(Finding(
                check_id="ssh-006",
                module="ssh",
                title="Weak authorized_keys permissions",
                severity=Severity.MEDIUM,
                description=f"authorized_keys has permissions {ak_mode}.",
                remediation="chmod 600 ~/.ssh/authorized_keys",
            ))

    return findings


register_module("ssh", "SSH configuration and key permission checks", 3)

# --- Git Checks ---

def check_git_config() -> list[Finding]:
    """Verify git global configuration for security."""
    findings: list[Finding] = []

    rc, name, _ = _run_cmd(["git", "config", "--global", "user.name"])
    if rc != 0 or not name:
        findings.append(Finding(
            check_id="git-001",
            module="git",
            title="No global git user.name",
            severity=Severity.LOW,
            description="Git user.name is not configured globally.",
            remediation="git config --global user.name 'Your Name'",
        ))

    rc, email, _ = _run_cmd(["git", "config", "--global", "user.email"])
    if rc != 0 or not email:
        findings.append(Finding(
            check_id="git-002",
            module="git",
            title="No global git user.email",
            severity=Severity.LOW,
            description="Git user.email is not configured globally.",
            remediation="git config --global user.email 'you@example.com'",
        ))

    # Check for commit signing
    rc, gpg_sign, _ = _run_cmd(["git", "config", "--global", "commit.gpgsign"])
    if rc != 0 or gpg_sign.lower() != "true":
        findings.append(Finding(
            check_id="git-003",
            module="git",
            title="Commits not signed",
            severity=Severity.MEDIUM,
            description="Git commit signing is not enabled globally.",
            remediation="git config --global commit.gpgsign true",
        ))

    return findings


def check_git_credential_storage() -> list[Finding]:
    """Check how git stores credentials."""
    findings: list[Finding] = []

    rc, helper, _ = _run_cmd(["git", "config", "--global", "credential.helper"])
    if rc == 0 and helper == "store":
        findings.append(Finding(
            check_id="git-004",
            module="git",
            title="Git credentials stored in plaintext",
            severity=Severity.HIGH,
            description="credential.helper is 'store', which saves passwords in plaintext at ~/.git-credentials.",
            remediation="Use 'credential.helper cache' or a system keychain (e.g. manager-core).",
        ))

    git_creds = _home() / ".git-credentials"
    if git_creds.exists():
        findings.append(Finding(
            check_id="git-005",
            module="git",
            title="Plaintext .git-credentials file exists",
            severity=Severity.HIGH,
            description="~/.git-credentials contains plaintext credentials.",
            remediation="Remove the file and switch to credential.helper cache or manager-core.",
        ))

    return findings


register_module("git", "Git configuration and credential checks", 2)

# --- Env / Dotfile Checks ---

SECRET_PATTERNS = [
    (re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*\S+", re.IGNORECASE), "API key"),
    (re.compile(r"(?:secret[_-]?key|secretkey)\s*[:=]\s*\S+", re.IGNORECASE), "Secret key"),
    (re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*\S+", re.IGNORECASE), "Password"),
    (re.compile(r"(?:token|auth_token|access_token)\s*[:=]\s*\S+", re.IGNORECASE), "Token"),
    (re.compile(r"(?:aws_access_key_id)\s*[:=]\s*[A-Z0-9]{16,}", re.IGNORECASE), "AWS access key"),
    (re.compile(r"(?:aws_secret_access_key)\s*[:=]\s*\S{20,}", re.IGNORECASE), "AWS secret key"),
    (re.compile(r"ghp_[A-Za-z0-9_]{36,}", re.IGNORECASE), "GitHub personal access token"),
    (re.compile(r"sk-[A-Za-z0-9]{32,}", re.IGNORECASE), "OpenAI/Stripe secret key"),
    (re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE), "AWS access key ID"),
]


def check_env_files() -> list[Finding]:
    """Scan for .env files in the home directory tree (shallow)."""
    findings: list[Finding] = []
    home = _home()

    # Check common locations for .env files
    common_dirs = [home, home / "projects", home / "code", home / "dev", home / "Desktop"]
    for d in common_dirs:
        if not d.exists():
            continue
        env_file = d / ".env"
        if env_file.is_file():
            findings.append(Finding(
                check_id="env-001",
                module="env",
                title=f".env file at {env_file}",
                severity=Severity.MEDIUM,
                description=f"Found .env file at {env_file}. Verify it's not tracked by git.",
                remediation="Add .env to your global .gitignore.",
            ))

    return findings


def check_shell_history_secrets() -> list[Finding]:
    """Scan shell history files for accidentally pasted secrets."""
    findings: list[Finding] = []
    home = _home()

    history_files = [
        home / ".bash_history",
        home / ".zsh_history",
        home / ".history",
        home / ".python_history",
    ]

    # On Windows, also check PSReadLine history
    if _is_windows():
        ps_history = home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
        history_files.append(ps_history)

    for hist_file in history_files:
        if not hist_file.is_file():
            continue

        try:
            content = hist_file.read_text(errors="replace")
        except PermissionError:
            continue

        lines = content.splitlines()
        # Only scan last 5000 lines for performance
        recent_lines = lines[-5000:] if len(lines) > 5000 else lines
        secret_count = 0

        for line in recent_lines:
            for pattern, label in SECRET_PATTERNS:
                if pattern.search(line):
                    secret_count += 1
                    break  # one match per line is enough

        if secret_count > 0:
            findings.append(Finding(
                check_id="env-002",
                module="env",
                title=f"Secrets in {hist_file.name}",
                severity=Severity.HIGH,
                description=f"Found {secret_count} potential secret(s) in {hist_file.name}.",
                remediation=f"Review and clean {hist_file}. Consider HISTIGNORE patterns.",
            ))

    return findings


def check_global_gitignore() -> list[Finding]:
    """Check if a global .gitignore is configured to exclude sensitive files."""
    findings: list[Finding] = []

    rc, gitignore_path, _ = _run_cmd(["git", "config", "--global", "core.excludesfile"])
    if rc != 0 or not gitignore_path:
        findings.append(Finding(
            check_id="env-003",
            module="env",
            title="No global .gitignore",
            severity=Severity.MEDIUM,
            description="No global gitignore configured. .env and key files might be accidentally committed.",
            remediation="git config --global core.excludesfile ~/.gitignore_global",
        ))
        return findings

    gitignore = Path(gitignore_path).expanduser()
    if not gitignore.exists():
        findings.append(Finding(
            check_id="env-004",
            module="env",
            title="Global .gitignore file missing",
            severity=Severity.LOW,
            description=f"core.excludesfile points to {gitignore_path} but file does not exist.",
            remediation=f"Create {gitignore_path} with entries like .env, *.pem, id_rsa.",
        ))
    else:
        content = gitignore.read_text(errors="replace")
        if ".env" not in content:
            findings.append(Finding(
                check_id="env-005",
                module="env",
                title=".env not in global gitignore",
                severity=Severity.LOW,
                description="Global gitignore does not include .env pattern.",
                remediation=f"Add '.env' to {gitignore_path}.",
            ))

    return findings


register_module("env", "Environment files, shell history, and dotfile checks", 3)

# --- Network / Ports Checks ---

def check_common_ports() -> list[Finding]:
    """Check for services listening on commonly exposed ports."""
    findings: list[Finding] = []

    dangerous_ports = {
        "3306": "MySQL",
        "5432": "PostgreSQL",
        "6379": "Redis",
        "27017": "MongoDB",
        "9200": "Elasticsearch",
        "11211": "Memcached",
        "2375": "Docker (unencrypted)",
    }

    if _is_windows():
        rc, output, _ = _run_cmd(["netstat", "-an"], timeout=15)
    else:
        rc, output, _ = _run_cmd(["ss", "-tlnp"], timeout=15)

    if rc != 0:
        return findings

    for port, service in dangerous_ports.items():
        # Match lines with the port listening on all interfaces
        patterns = [f"0.0.0.0:{port}", f"[::]:{port}", f"*:{port}"]
        for p in patterns:
            if p in output:
                findings.append(Finding(
                    check_id=f"net-{port}",
                    module="network",
                    title=f"{service} exposed on all interfaces",
                    severity=Severity.HIGH,
                    description=f"{service} (port {port}) is listening on 0.0.0.0 / all interfaces.",
                    remediation=f"Bind {service} to 127.0.0.1 only, or use firewall rules.",
                ))
                break

    return findings


def check_docker_socket() -> list[Finding]:
    """Check if Docker socket is accessible and potentially exposed."""
    findings: list[Finding] = []

    docker_sock = Path("/var/run/docker.sock")
    if docker_sock.exists() and not _is_windows():
        sock_stat = docker_sock.stat()
        mode = oct(sock_stat.st_mode)[-3:]
        if mode in ("666", "777"):
            findings.append(Finding(
                check_id="net-docker",
                module="network",
                title="Docker socket world-accessible",
                severity=Severity.HIGH,
                description=f"Docker socket has permissions {mode}. Any local user can control Docker.",
                remediation="Set socket permissions to 660 and use the docker group.",
            ))

    return findings


register_module("network", "Network exposure and service binding checks", 2)

# --- Tool Version Checks ---

TOOLS_TO_CHECK = [
    ("git", ["git", "--version"]),
    ("python", ["python3", "--version"]),
    ("node", ["node", "--version"]),
    ("npm", ["npm", "--version"]),
    ("docker", ["docker", "--version"]),
    ("ssh", ["ssh", "-V"]),
]


def check_tool_availability() -> list[Finding]:
    """Verify that common dev tools are installed and reachable."""
    findings: list[Finding] = []

    for tool_name, cmd in TOOLS_TO_CHECK:
        rc, stdout, stderr = _run_cmd(cmd)
        version_out = stdout or stderr
        if rc < 0:
            findings.append(Finding(
                check_id=f"tools-{tool_name}",
                module="tools",
                title=f"{tool_name} not found",
                severity=Severity.INFO,
                description=f"{tool_name} is not installed or not in PATH.",
            ))

    return findings


register_module("tools", "Developer tool availability and version checks", 1)


# --- Check Dispatcher ---

ALL_CHECKS: dict[str, list[Callable[[], list[Finding]]]] = {
    "ssh": [check_ssh_dir_permissions, check_ssh_config_hardening, check_ssh_authorized_keys],
    "git": [check_git_config, check_git_credential_storage],
    "env": [check_env_files, check_shell_history_secrets, check_global_gitignore],
    "network": [check_common_ports, check_docker_socket],
    "tools": [check_tool_availability],
}
