# 1.1.0 release candidate

This branch is a review candidate. Do not merge, tag, publish a GitHub release,
change the public catalog, or update the Open Source Engine until the maintainer
approves the final tested source and publication scope.

Before approval:
- Verify the PR head and clean source tree; review code, security boundaries,
  regression tests, README, development guide, package metadata and changelog.
- Require all existing protected PR CI and CodeQL checks, including Windows,
  macOS and Linux. Container checks alone do not establish cross-platform acceptance.
- Build wheel/source distributions from that exact head. Keep checksums and the
  command/test receipts with the review. Candidate builds are not published assets.

After separate merge/release approval:
- Review the resulting merged commit and require successful main checks.
- Mark the changelog release date in an approved change, then approve the exact
  release commit and v1.1.0 tag. Do not reuse candidate hashes after source changes.
- Build and verify distributions from the exact tag; attach only those verified
  artifacts to the release. Do not publish automatically from this PR.
- Reconcile the curated release register and only this project's catalog entry
  through the canonical Forge release process, verify live links/version/hashes,
  then update only its Open Source Engine record.
- Retain unpublished source and candidate artifacts until accounted for.

## Project checks

    python -m pip install -e . pytest build
    python -m pytest
    python -m build

The existing CI matrix is Python 3.10/3.13 on Ubuntu, Windows and macOS.
The baseline format is version 1. Baseline identities are location-sensitive;
they do not imply that unchanged findings are approved. Default failure behavior
must remain unchanged without --new-only. Baseline-mode outputs must be new files.
