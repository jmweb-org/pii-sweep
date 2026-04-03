from __future__ import annotations

from pii_sweep.detectors import Severity
from pii_sweep.scan import has_pii, scan_column, scan_values


def test_scan_values_reports_confidence():
    emails = ["a@x.com", "b@y.com", "c@z.com", "not-email"]
    conf = scan_values(emails)
    assert conf["email"] == 0.75


def test_scan_values_ignores_nulls_and_blanks():
    conf = scan_values(["a@x.com", None, "  ", "b@y.com"])
    assert conf["email"] == 1.0


def test_scan_values_empty_column():
    assert scan_values([None, None]) == {}


def test_scan_column_threshold():
    values = ["a@x.com", "b@y.com", "plain", "text"]
    # email confidence is 0.5 here
    assert scan_column("c", values, threshold=0.6) == []
    flagged = scan_column("c", values, threshold=0.5)
    assert flagged and flagged[0].detector == "email"


def test_scan_column_sets_severity_and_sampled():
    values = ["4242 4242 4242 4242", "4111 1111 1111 1111"]
    findings = scan_column("card", values, threshold=0.5)
    assert findings[0].severity is Severity.HIGH
    assert findings[0].sampled == 2


def test_scan_column_respects_sample():
    values = ["a@x.com"] * 100
    findings = scan_column("c", values, sample=10)
    assert findings[0].sampled == 10


def test_has_pii_threshold():
    values = ["8.8.8.8", "1.1.1.1"]  # ipv4 is low severity
    findings = scan_column("ip", values, threshold=0.5)
    assert has_pii(findings, Severity.LOW) is True
    assert has_pii(findings, Severity.HIGH) is False
