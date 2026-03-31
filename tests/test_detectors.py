from __future__ import annotations

from pii_sweep.detectors import (
    is_credit_card,
    is_email,
    is_iban,
    is_ipv4,
    is_phone,
    is_ssn,
    luhn_ok,
)


def test_email():
    assert is_email("alice@example.com")
    assert is_email("a.b+tag@sub.domain.co")
    assert not is_email("not-an-email")
    assert not is_email("missing@tld")


def test_ipv4():
    assert is_ipv4("192.168.0.1")
    assert is_ipv4("8.8.8.8")
    assert not is_ipv4("999.1.1.1")
    assert not is_ipv4("1.2.3")


def test_ssn():
    assert is_ssn("123-45-6789")
    assert not is_ssn("000-45-6789")  # invalid area
    assert not is_ssn("123456789")  # no dashes


def test_phone():
    assert is_phone("+1 (415) 555-2671")
    assert is_phone("+34 646 042 452")
    assert not is_phone("12")
    assert not is_phone("hello world")


def test_luhn():
    assert luhn_ok("4242424242424242")
    assert not luhn_ok("4242424242424241")


def test_credit_card_requires_luhn():
    assert is_credit_card("4242 4242 4242 4242")
    assert is_credit_card("4111-1111-1111-1111")
    assert not is_credit_card("4242 4242 4242 4241")  # fails Luhn
    assert not is_credit_card("1234")  # too short


def test_iban_checksum():
    assert is_iban("GB82 WEST 1234 5698 7654 32")
    assert not is_iban("GB00 WEST 1234 5698 7654 32")  # bad checksum
    assert not is_iban("notaniban")
