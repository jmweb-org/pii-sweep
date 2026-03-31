"""Pure PII detectors.

Each detector takes a single string and decides whether it looks like one kind
of personally identifiable information. Detectors are deliberately strict where
a checksum exists (credit cards, IBAN) to keep false positives down, and are
grouped by how sensitive a hit is. Everything here is pure and unit-tested.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


_EMAIL = re.compile(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$", re.IGNORECASE)
_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_SSN = re.compile(r"^(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}$")
_PHONE = re.compile(r"^\+?\d[\d\s().-]{7,}\d$")
_IBAN = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")
_CARD_CHARS = re.compile(r"^[\d\s-]{13,25}$")


def is_email(text: str) -> bool:
    return bool(_EMAIL.match(text.strip()))


def is_ipv4(text: str) -> bool:
    return bool(_IPV4.match(text.strip()))


def is_ssn(text: str) -> bool:
    return bool(_SSN.match(text.strip()))


def is_phone(text: str) -> bool:
    value = text.strip()
    if not _PHONE.match(value):
        return False
    digits = re.sub(r"\D", "", value)
    return 9 <= len(digits) <= 15


def luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        d = ord(char) - 48
        if index % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def is_credit_card(text: str) -> bool:
    value = text.strip()
    if not _CARD_CHARS.match(value):
        return False
    digits = re.sub(r"\D", "", value)
    return 13 <= len(digits) <= 19 and luhn_ok(digits)


def iban_ok(value: str) -> bool:
    rearranged = value[4:] + value[:4]
    converted = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(converted) % 97 == 1
    except ValueError:
        return False


def is_iban(text: str) -> bool:
    value = text.strip().replace(" ", "").upper()
    return bool(_IBAN.match(value)) and iban_ok(value)


@dataclass(frozen=True, slots=True)
class Detector:
    name: str
    severity: Severity
    predicate: object  # Callable[[str], bool]

    def matches(self, text: str) -> bool:
        return bool(self.predicate(text))


DETECTORS: tuple[Detector, ...] = (
    Detector("credit_card", Severity.HIGH, is_credit_card),
    Detector("iban", Severity.HIGH, is_iban),
    Detector("ssn", Severity.HIGH, is_ssn),
    Detector("email", Severity.MEDIUM, is_email),
    Detector("phone", Severity.MEDIUM, is_phone),
    Detector("ipv4", Severity.LOW, is_ipv4),
)


def detectors_by_name() -> dict[str, Detector]:
    return {d.name: d for d in DETECTORS}
