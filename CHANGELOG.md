# Changelog

## 1.2.0 - 2026-10-20

- Wrap long paths in standalone HTML tables on narrow and wide screens.

- Remove Git command execution from repository inspection.
- Surface bounded/non-text inspection skips and keep unmatched baseline findings unverified; refuse incomplete baseline snapshots/new-only success.
- Refuse source symlinks, handle empty local links and avoid copying raw link targets into diagnostics.
- Match basic .env ignore comments/negation and create reports exclusively unless regular-report overwrite is explicit.

## 1.1.0 - 2026-10-15

- Add portable, value-free finding baselines and new/unchanged/resolved reports with opt-in new-only failure thresholds.
- Preserve default CLI policy and source safety boundaries; add regression tests and documented limits.

## 1.0.0 - 2026-07-18

- Added read-only repository scanning and severity-ranked findings.
- Added community-file, test, CI, local-link, sensitive-file, and secret-signature checks.
- Added terminal, JSON, and portable HTML reports.
- Added configurable failure thresholds for CI use.
