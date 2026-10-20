# Development handoff

Version 1.2.0 is a conservative, read-only Python CLI. It must not execute commands found in the target repository or print matched secret values. New rules need deterministic fixtures, a clear severity rationale, and documentation of false-positive boundaries.

Validation baseline: `python -m pytest` and `python -m build` on supported Python versions.

## 1.2.0

Supports portable, value-free finding baselines and new/unchanged/resolved reports with opt-in new-only failure thresholds.

Run the existing project gates before review. The tag-triggered Release artifacts workflow tests and builds wheel/source distributions from the exact tag; publishing those verified assets remains a maintainer action.

The v1.2.0 audit removes unnecessary Git execution, which could honor executable
repository fsmonitor settings. Keep all target code/configuration inert. Content
inspection skips must remain visible and must not create false resolved baseline
findings or successful new-only policy decisions.
