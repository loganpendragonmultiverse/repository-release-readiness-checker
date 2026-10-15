# 1.1.0 release verification

The maintainer authorized release after protected checks and independent review.
The implementation passed 26 tests and cross-platform CI; release-finalization
documents and the exact version tag must also pass their applicable checks.

The tag-triggered Release artifacts workflow tests and builds distributions,
checks package and runtime versions against the tag, and uploads the wheel,
source distribution and SHA256SUMS. Download and verify those artifacts before
attaching them to the GitHub release. Do not reuse earlier candidate artifacts.

After publication, reconcile only this project in the release register and Forge
catalog. Run the canonical renderer, release/SEO verifiers, organization watch
audit and live verifiers before updating its Open Source Engine record.
