from pathlib import Path

from release_ready.model import Severity
from release_ready.reporters import render_html, render_json
from release_ready.scanner import audit_repository


def make_repository(tmp_path: Path) -> Path:
    for name in ("README.md", "LICENSE", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", ".gitignore"):
        (tmp_path / name).write_text("# File\n\n.env\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_example.py").write_text("def test_example(): assert True\n", encoding="utf-8")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: CI\n", encoding="utf-8")
    return tmp_path


def test_complete_repository_passes_core_checks(tmp_path: Path) -> None:
    audit = audit_repository(make_repository(tmp_path))
    errors = [item for item in audit.findings if item.severity is Severity.ERROR]
    assert errors == []
    assert audit.score == 100


def test_missing_files_and_broken_links_are_reported(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("[Missing](docs/missing.md)\n", encoding="utf-8")
    audit = audit_repository(tmp_path)
    rules = {item.rule for item in audit.findings if item.severity is Severity.ERROR}
    assert "file-license" in rules
    assert "broken-local-link" in rules
    assert "tests" in rules


def test_secret_signatures_include_location(tmp_path: Path) -> None:
    make_repository(tmp_path)
    fake_token = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456"
    (tmp_path / "config.txt").write_text(f"token={fake_token}\n", encoding="utf-8")
    finding = next(item for item in audit_repository(tmp_path).findings if item.rule == "github-token")
    assert finding.path == "config.txt"
    assert finding.line == 1


def test_reports_are_portable(tmp_path: Path) -> None:
    audit = audit_repository(make_repository(tmp_path))
    assert '"score": 100' in render_json(audit)
    assert "<!doctype html>" in render_html(audit)
