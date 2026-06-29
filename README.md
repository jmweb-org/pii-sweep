# pii-sweep

[![CI](https://github.com/jmweb-org/pii-sweep/actions/workflows/ci.yml/badge.svg)](https://github.com/jmweb-org/pii-sweep/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pii-sweep.svg)](https://pypi.org/project/pii-sweep/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Scan dataset files for personally identifiable information, with a confidence
per column and a CI gate, before the data leaves your hands.

Before a dataset is shared, copied to a notebook, or pushed to a bucket, it is
worth knowing whether a column quietly holds emails, card numbers or national
IDs. `pii-sweep` samples each column, runs a set of detectors, and reports which
columns look like PII and how strongly.

```console
$ pii-sweep scan customers.parquet
severity  column        type         confidence
high      card_number   credit_card  100%
high      tax_id        ssn          98%
medium    contact       email        91%
```

## Install

```console
$ pip install pii-sweep                 # from PyPI, once released
$ pip install git+https://github.com/jmweb-org/pii-sweep   # latest, available now
```

Reads CSV, Parquet and JSON Lines through polars.

## Usage

```console
$ pii-sweep scan data.csv                 # human-readable table
$ pii-sweep scan data.parquet --json      # machine-readable findings
$ pii-sweep scan data.csv --show-samples  # include one masked example per finding
$ pii-sweep scan data.csv --sample 5000   # cap values scanned per column
$ pii-sweep scan data.csv --threshold 0.3 # flag at a lower match fraction
$ pii-sweep scan data.csv --check         # exit non-zero if PII is found
```

### In CI

Stop a dataset with PII from being committed or published:

```yaml
- run: pii-sweep scan data/export.parquet --check --fail-on medium
```

## What it detects

| Type | Severity | How |
| --- | --- | --- |
| `credit_card` | high | 13-19 digits passing the Luhn checksum |
| `iban` | high | Country format plus the mod-97 checksum |
| `ssn` | high | US social-security format with valid ranges |
| `email` | medium | Standard address pattern |
| `phone` | medium | International or grouped number, 9-15 digits |
| `ipv4` | low | Dotted-quad address |

Detectors with a checksum (cards, IBAN) are strict, so a column of random
13-digit numbers is not flagged as cards. The **confidence** is the fraction of
sampled non-null values a detector matched; `--threshold` sets how high that
must be to flag a column. Use `--show-samples` when you want one masked example
per finding for review; raw values are not printed.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Scanned; nothing at or above the fail severity (or `--check` not set) |
| 1 | `--check` found PII at or above `--fail-on` |
| 2 | The file was missing or in an unsupported format |

## Scope

`pii-sweep` finds structured PII with clear patterns. It does not detect free-text
names or addresses, and a clean report is not a compliance guarantee. Treat it
as a fast guardrail, not a substitute for review.

## License

MIT. See [LICENSE](LICENSE).
