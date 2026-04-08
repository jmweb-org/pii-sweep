# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-10

### Added
- Docker image and a published container entry point.
- Continuous integration across Python 3.10, 3.11 and 3.12.
- Expanded documentation, including scope and limitations.

## [0.1.0] - 2026-04-06

### Added
- `scan` command: detect PII per column in CSV, Parquet and JSON Lines files,
  with a confidence per finding and a `--check` CI gate.
- Detectors for credit cards (Luhn), IBAN (mod-97), US SSN, email, phone and
  IPv4, grouped by severity.
- `--threshold`, `--sample` and `--fail-on` to tune sensitivity and gating.

[0.2.0]: https://github.com/jmweb-org/pii-sweep/releases/tag/v0.2.0
[0.1.0]: https://github.com/jmweb-org/pii-sweep/releases/tag/v0.1.0
