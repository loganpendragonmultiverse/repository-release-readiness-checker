import json

import pytest

from release_ready.baselines import compare, load_baseline, snapshot, write_baseline
from release_ready.cli import main
from release_ready.model import Audit, Finding, Severity
from release_ready.reporters import render_comparison


def audit(root, *findings):
    return Audit(root, tuple(findings), 1)


def test_relocation_and_order_preserve_identities(tmp_path):
    one = Finding(
        "broken-local-link", Severity.ERROR, "Missing: private-target", "README.md", 4
    )
    two = Finding("tests", Severity.ERROR, "No tests")
    first = audit(tmp_path / "one", one, two)
    second = audit(tmp_path / "elsewhere", two, one)
    path = tmp_path / "baseline.json"
    write_baseline(path, first)
    result = compare(second, load_baseline(path))
    assert len(result.unchanged) == 2
    assert not result.new and not result.resolved
    assert "private-target" not in path.read_text()
    assert str(tmp_path) not in path.read_text()


def test_changed_evidence_location_severity_and_resolution(tmp_path):
    old = Finding("tests", Severity.ERROR, "Missing tests", "test.py", 1)
    fresh = Finding("tests", Severity.WARNING, "Missing tests", "test.py", 1)
    result = compare(
        audit(tmp_path, fresh), tuple(snapshot(audit(tmp_path, old))["findings"])
    )
    assert len(result.new) == len(result.resolved) == 1
    assert not result.unchanged
    for changed in [
        Finding("tests", Severity.ERROR, "Different evidence", "test.py", 1),
        Finding("tests", Severity.ERROR, "Missing tests", "test.py", 2),
    ]:
        assert (
            len(
                compare(
                    audit(tmp_path, changed),
                    (snapshot(audit(tmp_path, old))["findings"][0],),
                ).new
            )
            == 1
        )
    assert not snapshot(audit(tmp_path, Finding("tests", Severity.PASS, "Present")))[
        "findings"
    ]


@pytest.mark.parametrize(
    "data",
    [
        [],
        {},
        {"schema_version": True, "findings": []},
        {"schema_version": 2, "findings": []},
        {"schema_version": 1, "findings": {}},
        {"schema_version": 1, "findings": [{}]},
    ],
)
def test_rejects_malformed_baselines(tmp_path, data):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        load_baseline(path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("path", "/private/file"),
        ("path", "../file"),
        ("path", "C:\\private"),
        ("line", True),
        ("line", 0),
        ("severity", "pass"),
        ("rule", "<script>"),
        ("id", "a" * 64),
        ("evidence_sha256", "not-a-hash"),
    ],
)
def test_rejects_invalid_records(tmp_path, field, value):
    data = snapshot(
        audit(tmp_path, Finding("tests", Severity.ERROR, "Missing", "a.py", 1))
    )
    data["findings"][0][field] = value
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        load_baseline(path)


def test_rejects_duplicates_encoding_and_oversize(tmp_path):
    path = tmp_path / "bad.json"
    for content in [
        b'{"schema_version":1,"schema_version":1,"findings":[]}',
        b"\xff",
        b" " * 1_000_001,
    ]:
        path.write_bytes(content)
        with pytest.raises(ValueError):
            load_baseline(path)
    data = snapshot(audit(tmp_path, Finding("tests", Severity.ERROR, "Missing")))
    data["findings"] *= 2
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        load_baseline(path)


def test_cli_defaults_and_new_only_thresholds(tmp_path, capsys):
    target = tmp_path / "repo"
    target.mkdir()
    baseline = tmp_path / "baseline.json"
    assert main([str(target), "--write-baseline", str(baseline)]) == 1
    assert main([str(target), "--baseline", str(baseline)]) == 1
    assert main([str(target), "--baseline", str(baseline), "--new-only"]) == 0
    (target / "README.md").write_text("[broken](absent.md)")
    assert main([str(target), "--baseline", str(baseline), "--new-only"]) == 1
    assert (
        main(
            [
                str(target),
                "--baseline",
                str(baseline),
                "--new-only",
                "--fail-on",
                "never",
            ]
        )
        == 0
    )


def test_cli_protects_inputs_and_handles_output_errors(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    assert (
        main([str(tmp_path), "--write-baseline", str(baseline), "--fail-on", "never"])
        == 0
    )
    before = baseline.read_bytes()
    assert main([str(tmp_path), "--write-baseline", str(baseline)]) == 2
    assert (
        main([str(tmp_path), "--baseline", str(baseline), "--output", str(baseline)])
        == 2
    )
    assert main([str(tmp_path), "--new-only"]) == 2
    assert main([str(tmp_path), "--output", str(tmp_path / "missing" / "report")]) == 2
    assert baseline.read_bytes() == before


def test_comparison_formats_and_warning_failure(tmp_path):
    finding = Finding("tests", Severity.WARNING, "<unsafe>", "a<b.py", 1)
    current = audit(tmp_path, finding)
    result = compare(current, ())
    report = json.loads(render_comparison(current, result, "json"))
    assert len(report["comparison"]["new"]) == 1
    assert "New: 1" in render_comparison(current, result, "text")
    rendered = render_comparison(current, result, "html")
    assert "a&lt;b.py" in rendered and "<unsafe>" not in rendered
    target = tmp_path / "repo"
    target.mkdir()
    for name in ("README.md", "LICENSE"):
        (target / name).write_text("ok")
    (target / "tests").mkdir()
    (target / "tests" / "test_ok.py").write_text("pass")
    baseline = tmp_path / "empty.json"
    baseline.write_text('{"schema_version":1,"findings":[]}')
    args = [str(target), "--baseline", str(baseline), "--new-only"]
    assert main(args) == 0
    assert main(args + ["--fail-on", "warning"]) == 1


def test_baseline_write_refuses_nonportable_names_without_creating_output(tmp_path):
    output = tmp_path / "baseline.json"
    current = audit(tmp_path, Finding("tests", Severity.WARNING, "Review", "bad:path"))
    with pytest.raises(ValueError):
        write_baseline(output, current)
    assert not output.exists()
