"""Portable, value-free finding baselines; never execute the audited repository."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .model import Audit, Finding, Severity

MAX_BASELINE_BYTES = 1_000_000
_KEYS = {"id", "rule", "severity", "path", "line", "evidence_sha256"}


def _identity(record: dict[str, object]) -> str:
    payload = {key: value for key, value in record.items() if key != "id"}
    return hashlib.sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def _record(finding: Finding) -> dict[str, object]:
    record: dict[str, object] = {
        "rule": finding.rule,
        "severity": finding.severity.value,
        "path": finding.path,
        "line": finding.line,
        "evidence_sha256": hashlib.sha256(finding.message.encode("utf-8")).hexdigest(),
    }
    record["id"] = _identity(record)
    return record


def snapshot(audit: Audit) -> dict[str, object]:
    records = {
        _identity(record): record
        for finding in audit.findings
        if finding.severity is not Severity.PASS
        for record in [_record(finding)]
    }
    return {"schema_version": 1, "findings": [records[key] for key in sorted(records)]}


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate baseline field")
        result[key] = value
    return result


def load_baseline(path: Path) -> tuple[dict[str, object], ...]:
    if path.stat().st_size > MAX_BASELINE_BYTES:
        raise ValueError("Baseline exceeds 1 MB")
    try:
        data = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Baseline must contain valid UTF-8 JSON") from exc
    return _validate(data)


def _validate(data: object) -> tuple[dict[str, object], ...]:
    if not isinstance(data, dict) or set(data) != {"schema_version", "findings"}:
        raise ValueError("Invalid baseline envelope")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Unsupported baseline schema version")
    if not isinstance(data["findings"], list):
        raise ValueError("Baseline findings must be a list")
    seen: set[str] = set()
    for record in data["findings"]:
        if not isinstance(record, dict) or set(record) != _KEYS:
            raise ValueError("Invalid baseline finding fields")
        if not isinstance(record["rule"], str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9.-]{0,127}", record["rule"]
        ):
            raise ValueError("Invalid baseline rule")
        if not isinstance(record["severity"], str) or record["severity"] not in {
            "error",
            "warning",
            "info",
        }:
            raise ValueError("Invalid baseline severity")
        location = record["path"]
        if location is not None:
            if not isinstance(location, str) or not location or len(location) > 4096:
                raise ValueError("Invalid baseline path")
            if (
                PurePosixPath(location).is_absolute()
                or any(part in {".", ".."} for part in location.split("/"))
                or "\\" in location
                or ":" in location
                or any(ord(char) < 32 for char in location)
            ):
                raise ValueError("Baseline paths must be repository-relative")
        if record["line"] is not None and (
            type(record["line"]) is not int or record["line"] < 1
        ):
            raise ValueError("Invalid baseline line")
        for key in ("id", "evidence_sha256"):
            if not isinstance(record[key], str) or not re.fullmatch(
                r"[0-9a-f]{64}", record[key]
            ):
                raise ValueError("Invalid baseline fingerprint")
        if record["id"] != _identity(record) or record["id"] in seen:
            raise ValueError("Mismatched or duplicate baseline identity")
        seen.add(record["id"])
    return tuple(data["findings"])


@dataclass(frozen=True)
class Comparison:
    new: tuple[dict[str, object], ...]
    unchanged: tuple[dict[str, object], ...]
    resolved: tuple[dict[str, object], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "new": list(self.new),
            "unchanged": list(self.unchanged),
            "resolved": list(self.resolved),
        }

    def new_findings(self, audit: Audit) -> tuple[Finding, ...]:
        identities = {record["id"] for record in self.new}
        return tuple(
            finding
            for finding in audit.findings
            if _record(finding)["id"] in identities
        )


def compare(audit: Audit, previous: tuple[dict[str, object], ...]) -> Comparison:
    current = {record["id"]: record for record in snapshot(audit)["findings"]}
    old = {record["id"]: record for record in previous}
    return Comparison(
        tuple(current[key] for key in sorted(current.keys() - old.keys())),
        tuple(current[key] for key in sorted(current.keys() & old.keys())),
        tuple(old[key] for key in sorted(old.keys() - current.keys())),
    )


def write_baseline(path: Path, audit: Audit) -> None:
    payload = snapshot(audit)
    _validate(payload)
    content = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if len(content.encode("utf-8")) > MAX_BASELINE_BYTES:
        raise ValueError("Baseline exceeds 1 MB")
    with path.open("x", encoding="utf-8") as handle:
        handle.write(content)
