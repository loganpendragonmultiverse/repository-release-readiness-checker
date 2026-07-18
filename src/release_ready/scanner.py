from __future__ import annotations

import re
import subprocess
from pathlib import Path
from urllib.parse import unquote

from .model import Audit, Finding, Severity

IGNORED_DIRECTORIES = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor", "dist", "build", "coverage", "__pycache__"}
REQUIRED_FILES = {
    "README.md": Severity.ERROR,
    "LICENSE": Severity.ERROR,
    "CONTRIBUTING.md": Severity.WARNING,
    "SECURITY.md": Severity.WARNING,
    "CHANGELOG.md": Severity.WARNING,
}
SENSITIVE_FILENAMES = {".env", "id_rsa", "id_ed25519", "credentials.json", "service-account.json"}
SECRET_PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-token": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
}
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def audit_repository(target: Path) -> Audit:
    root = target.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Not a directory: {root}")

    files = tuple(_iter_files(root))
    findings: list[Finding] = []
    findings.extend(_check_required_files(root))
    findings.extend(_check_sensitive_files(root, files))
    findings.extend(_check_secret_signatures(root, files))
    findings.extend(_check_markdown_links(root, files))
    findings.extend(_check_repository_metadata(root))
    findings.extend(_check_tests_and_automation(root, files))
    findings.sort(key=lambda item: (_severity_rank(item.severity), item.path or "", item.line or 0, item.rule))
    return Audit(root, tuple(findings), len(files))


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and not any(part in IGNORED_DIRECTORIES for part in path.relative_to(root).parts):
            yield path


def _check_required_files(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    present = {path.name.casefold(): path for path in root.iterdir() if path.is_file()}
    for name, severity in REQUIRED_FILES.items():
        path = present.get(name.casefold())
        if path:
            findings.append(Finding(f"file-{name.casefold()}", Severity.PASS, f"{name} is present.", name))
        else:
            findings.append(Finding(f"file-{name.casefold()}", severity, f"{name} is missing."))
    return findings


def _check_sensitive_files(root: Path, files: tuple[Path, ...]) -> list[Finding]:
    tracked = _tracked_files(root)
    findings: list[Finding] = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        if path.name.casefold() in SENSITIVE_FILENAMES or path.suffix.casefold() in {".pem", ".p12", ".pfx"}:
            severity = Severity.ERROR if not tracked or relative in tracked else Severity.ERROR
            findings.append(Finding("sensitive-file", severity, "Potentially sensitive file is present; confirm it contains no credentials and should be published.", relative))
    return findings


def _check_secret_signatures(root: Path, files: tuple[Path, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        if path.stat().st_size > 1_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            for name, pattern in SECRET_PATTERNS.items():
                if pattern.search(line):
                    findings.append(Finding(name, Severity.ERROR, f"Content resembles a {name.replace('-', ' ')}. Rotate it if real and remove it from history.", path.relative_to(root).as_posix(), line_number))
    return findings


def _check_markdown_links(root: Path, files: tuple[Path, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        if path.suffix.casefold() not in {".md", ".markdown"}:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for line_number, line in enumerate(lines, 1):
            for raw_target in MARKDOWN_LINK.findall(line):
                target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
                if not target or target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                local = (path.parent / unquote(target.split("#", 1)[0])).resolve()
                try:
                    local.relative_to(root)
                except ValueError:
                    findings.append(Finding("link-outside-repository", Severity.WARNING, "Local Markdown link points outside the repository.", path.relative_to(root).as_posix(), line_number))
                else:
                    if not local.exists():
                        findings.append(Finding("broken-local-link", Severity.ERROR, f"Local Markdown link does not exist: {target}", path.relative_to(root).as_posix(), line_number))
    return findings


def _check_repository_metadata(root: Path) -> list[Finding]:
    gitignore = root / ".gitignore"
    findings = []
    if gitignore.is_file():
        text = gitignore.read_text(encoding="utf-8", errors="replace")
        if ".env" in text:
            findings.append(Finding("gitignore-env", Severity.PASS, ".gitignore excludes environment files.", ".gitignore"))
        else:
            findings.append(Finding("gitignore-env", Severity.WARNING, ".gitignore does not explicitly exclude .env files.", ".gitignore"))
    else:
        findings.append(Finding("gitignore", Severity.WARNING, ".gitignore is missing."))
    return findings


def _check_tests_and_automation(root: Path, files: tuple[Path, ...]) -> list[Finding]:
    relative = {path.relative_to(root).as_posix().casefold() for path in files}
    has_tests = any(path.startswith(("tests/", "test/", "spec/")) or "/tests/" in path for path in relative)
    has_ci = any(path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")) for path in relative)
    return [
        Finding("tests", Severity.PASS if has_tests else Severity.ERROR, "Test files were found." if has_tests else "No test files were found."),
        Finding("continuous-integration", Severity.PASS if has_ci else Severity.WARNING, "GitHub Actions workflow found." if has_ci else "No GitHub Actions workflow was found."),
    ]


def _tracked_files(root: Path) -> set[str]:
    try:
        result = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if result.returncode != 0:
        return set()
    return {item.decode("utf-8", errors="surrogateescape") for item in result.stdout.split(b"\0") if item}


def _severity_rank(severity: Severity) -> int:
    return {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2, Severity.PASS: 3}[severity]
