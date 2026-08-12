"""Scan columns and datasets for PII using the pure detectors.

A column is scanned by sampling its non-null values and asking each detector
how often it fires. The fraction of values a detector matches is its
confidence for that column; the highest-severity detector above a threshold
decides whether the column is flagged.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from pii_sweep.detectors import DETECTORS, Detector, Severity


@dataclass(frozen=True, slots=True)
class ColumnFinding:
    column: str
    detector: str
    severity: Severity
    confidence: float
    sampled: int
    masked_sample: str | None = None

    @property
    def sort_key(self) -> tuple[int, float, str]:
        order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
        return (order[self.severity], -self.confidence, self.column)


def _mask_sample(value: str) -> str:
    text = value.strip()
    if "@" in text:
        local, domain = text.split("@", 1)
        suffix = ""
        if "." in domain:
            suffix = "." + domain.rsplit(".", 1)[1]
        first = local[:1] or "*"
        return f"{first}***@***{suffix}"

    digits = re.sub(r"\D", "", text)
    if len(digits) >= 4:
        return f"***{digits[-4:]}"

    if len(text) <= 2:
        return "***"
    return f"{text[0]}***{text[-1]}"


def _first_masked_match(
    values: Sequence[str | None], detector: Detector, sample: int | None
) -> str | None:
    present = [v for v in values if v is not None and str(v).strip() != ""]
    if sample is not None and len(present) > sample:
        present = present[:sample]
    for value in present:
        text = str(value)
        if detector.matches(text):
            return _mask_sample(text)
    return None


def scan_values(
    values: Sequence[str | None],
    detectors: Sequence[Detector] = DETECTORS,
    *,
    sample: int | None = None,
) -> dict[str, float]:
    """Return per-detector confidence (match fraction) over non-null values."""

    present = [v for v in values if v is not None and str(v).strip() != ""]
    if sample is not None and len(present) > sample:
        present = present[:sample]
    if not present:
        return {}
    counts = dict.fromkeys((d.name for d in detectors), 0)
    for value in present:
        text = str(value)
        for detector in detectors:
            if detector.matches(text):
                counts[detector.name] += 1
    return {name: hits / len(present) for name, hits in counts.items() if hits}


def scan_column(
    column: str,
    values: Sequence[str | None],
    *,
    threshold: float = 0.5,
    sample: int | None = None,
    detectors: Sequence[Detector] = DETECTORS,
) -> list[ColumnFinding]:
    present = [v for v in values if v is not None and str(v).strip() != ""]
    sampled = min(len(present), sample) if sample is not None else len(present)
    confidences = scan_values(values, detectors, sample=sample)
    by_name = {d.name: d for d in detectors}
    findings = [
        ColumnFinding(
            column,
            name,
            by_name[name].severity,
            conf,
            sampled,
            _first_masked_match(values, by_name[name], sample),
        )
        for name, conf in confidences.items()
        if conf >= threshold
    ]
    findings.sort(key=lambda f: f.sort_key)
    return findings


def has_pii(findings: Sequence[ColumnFinding], min_severity: Severity = Severity.LOW) -> bool:
    order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
    limit = order[min_severity]
    return any(order[f.severity] <= limit for f in findings)
