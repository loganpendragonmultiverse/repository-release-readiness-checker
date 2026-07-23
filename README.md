# Repository Release Readiness Checker

A read-only command-line audit for the awkward moment between “the code works on my machine” and “this repository is ready for strangers.” It checks the public surface of a software project, reports evidence, and leaves every file untouched.

## What it checks

- Core community and release documents
- Local links in Markdown documentation
- Common sensitive filenames and recognizable secret signatures
- `.gitignore` coverage for environment files
- Test presence and GitHub Actions configuration
- A concise readiness score with error, warning, information, and pass findings

This is a release checklist, not a security certification. It deliberately avoids running untrusted project commands during a scan.

## Install from source

Python 3.10 or newer is required.

```bash
python -m venv .venv
python -m pip install -e .
```

## Three-minute usage

Audit the current repository:

```bash
release-ready .
```

Create a portable HTML report:

```bash
release-ready . --format html --output release-readiness.html
```

Use JSON in another tool without failing a pipeline:

```bash
release-ready . --format json --output release-readiness.json --fail-on never
```

The command exits `1` when the configured failure threshold is reached and `2` when the target or report cannot be processed.

## Privacy and safety

Scanning is local. The tool does not upload source code or contact external services. It reads text files up to 1 MB for known secret signatures and never prints a detected secret value.

## Limitations

- It does not prove that documentation claims are true or that a project is secure.
- Remote HTTP links are not requested in v1.0.
- Generated and dependency directories are skipped using a conservative built-in list.
- Secret detection is intentionally narrow to reduce accidental disclosure and false confidence.

## Development

```bash
python -m pip install -e . pytest
python -m pytest
python -m build
```

See [CONTRIBUTING.md](https://github.com/loganpendragonmultiverse/.github/blob/main/CONTRIBUTING.md) before proposing a change. Bug reports and focused pull requests are welcome.

## Project status

**Feature complete for v1.0.** Security and correctness fixes are welcome; broader checks should remain evidence-based and read-only.

Released under the [MIT License](LICENSE).

## More open-source projects

This project is part of the [Logan Pendragon Forge open-source collection](https://www.loganpendragonforge.com/open-source/). Browse the catalog for other released tools, source repositories, live demos, and downloads.
