from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path


class Severity(StrEnum):
    PASS = "pass"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Finding:
    rule: str
    severity: Severity
    message: str
    path: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Audit:
    target: Path
    findings: tuple[Finding, ...]
    files_scanned: int

    @property
    def score(self) -> int:
        deductions = {Severity.ERROR: 14, Severity.WARNING: 5, Severity.INFO: 0, Severity.PASS: 0}
        return max(0, 100 - sum(deductions[item.severity] for item in self.findings))

    @property
    def errors(self) -> int:
        return sum(item.severity is Severity.ERROR for item in self.findings)

    @property
    def warnings(self) -> int:
        return sum(item.severity is Severity.WARNING for item in self.findings)

    def to_dict(self) -> dict[str, object]:
        return {
            "target": str(self.target),
            "score": self.score,
            "files_scanned": self.files_scanned,
            "summary": {"errors": self.errors, "warnings": self.warnings},
            "findings": [item.to_dict() for item in self.findings],
        }
