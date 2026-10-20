import json
import subprocess
from pathlib import Path

import pytest

from release_ready.baselines import compare, load_baseline, snapshot, write_baseline
from release_ready.cli import main
from release_ready.reporters import render_html, render_json, render_text
from release_ready.scanner import audit_repository


def test_audit_never_invokes_git_or_repository_commands(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("target command execution attempted")

    monkeypatch.setattr(subprocess, "run", forbidden)
    (tmp_path / ".env").write_text("synthetic marker")
    audit = audit_repository(tmp_path)
    assert any(f.rule == "sensitive-file" for f in audit.findings)


def test_empty_markdown_links_and_secret_targets_are_safe(tmp_path):
    token = "ghp_" + "syntheticvalueabcdefghij1234567890"
    source = tmp_path / "README.md"
    source.write_text("[empty]( )\n[private](" + token + ")\n")
    old = audit_repository(tmp_path)
    rendered = render_json(old) + render_html(old) + render_text(old)
    assert token not in rendered
    assert any(f.rule == "github-token" for f in old.findings)
    source.write_text("[empty]( )\n[private](another-missing-target)\n")
    comparison = compare(audit_repository(tmp_path), tuple(snapshot(old)["findings"]))
    assert any(f["rule"] == "broken-local-link" for f in comparison.new)
    assert any(f["rule"] == "broken-local-link" for f in comparison.resolved)


@pytest.mark.parametrize("replacement", [b"x" * 1_000_001, b"\xff"], ids=["oversized-content", "non-utf8"])
def test_skipped_content_cannot_falsely_resolve_or_replace_baseline(tmp_path, replacement):
    source = tmp_path / "config.txt"
    source.write_text("ghp_" + "syntheticvalueabcdefghij1234567890")
    baseline = tmp_path.parent / (tmp_path.name + "-baseline.json")
    write_baseline(baseline, audit_repository(tmp_path))
    source.write_bytes(replacement)
    current = audit_repository(tmp_path)
    assert current.uninspected_paths == ("config.txt",)
    comparison = compare(current, load_baseline(baseline))
    assert not comparison.resolved
    assert any(f["rule"] == "github-token" for f in comparison.unverified)
    output = tmp_path.parent / (tmp_path.name + "-new.json")
    with pytest.raises(ValueError, match="incomplete"):
        write_baseline(output, current)
    assert not output.exists()
    assert main([str(tmp_path), "--baseline", str(baseline), "--new-only", "--fail-on", "never"]) == 2
    assert json.loads(render_json(current))["content_inspection_complete"] is False


@pytest.mark.parametrize("pattern,passed", [("# .env", False), (".environment", False), (".env\n!.env", False), (".env*\n!.env.example", True)])
def test_ignore_evidence_respects_comments_and_negation(tmp_path, pattern, passed):
    (tmp_path / ".gitignore").write_text(pattern)
    audit = audit_repository(tmp_path)
    result = next(f for f in audit.findings if f.rule == "gitignore-env")
    assert (result.severity.value == "pass") is passed


@pytest.mark.parametrize("kind", ["file", "root", "directory"])
def test_symlinks_are_not_inspected(tmp_path, kind):
    source = tmp_path / "repo"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("synthetic content")
    try:
        if kind == "file":
            (source / "linked.txt").symlink_to(outside / "secret.txt")
        elif kind == "directory":
            (source / "linked").symlink_to(outside, target_is_directory=True)
        else:
            root = tmp_path / "linked"
            root.symlink_to(source, target_is_directory=True)
            source = root
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="symlink"):
        audit_repository(source)


def test_dangling_output_and_baseline_symlinks_are_refused(tmp_path):
    target = tmp_path / "absent"
    output = tmp_path / "output.json"
    try:
        output.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    # Keep synthetic output link outside the audited root.
    root = tmp_path / "repo"
    root.mkdir()
    assert main([str(root), "--output", str(output), "--overwrite"]) == 2
    assert main([str(root), "--write-baseline", str(output)]) == 2
    assert output.is_symlink() and not target.exists()


def test_existing_and_competing_reports_are_preserved(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    output = tmp_path / "report.json"
    output.write_text("keep")
    args = [str(root), "--format", "json", "--output", str(output), "--fail-on", "never"]
    assert main(args) == 2
    assert output.read_text() == "keep"
    assert main(args + ["--overwrite"]) == 0
    assert "findings" in json.loads(output.read_text())
    raced = tmp_path / "raced.json"
    original = Path.open

    def racing(path, mode="r", *args, **kwargs):
        if path == raced and mode == "x":
            with original(path, "w", encoding="utf-8") as handle:
                handle.write("other writer")
        return original(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", racing)
    assert main([str(root), "--output", str(raced), "--fail-on", "never"]) == 2
    assert raced.read_text() == "other writer"
