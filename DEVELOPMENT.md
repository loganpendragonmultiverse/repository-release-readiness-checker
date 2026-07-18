# Development handoff

Version 1.0 is a conservative, read-only Python CLI. It must not execute commands found in the target repository or print matched secret values. New rules need deterministic fixtures, a clear severity rationale, and documentation of false-positive boundaries.

Validation baseline: `python -m pytest` and `python -m build` on supported Python versions.
