"""Read tabular files and scan every column for PII."""

from __future__ import annotations

from pathlib import Path

import polars as pl

from pii_sweep.detectors import DETECTORS, Detector
from pii_sweep.scan import ColumnFinding, scan_column


def read_frame(path: str | Path) -> pl.DataFrame:
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return pl.read_csv(path, infer_schema_length=0)
    if suffix in {".parquet", ".pq"}:
        return pl.read_parquet(path)
    if suffix in {".jsonl", ".ndjson"}:
        return pl.read_ndjson(path)
    if suffix == ".json":
        return pl.read_json(path)
    raise ValueError(f"unsupported file type: {path.suffix or '(none)'}")


def scan_frame(
    frame: pl.DataFrame,
    *,
    threshold: float = 0.5,
    sample: int | None = None,
    detectors: tuple[Detector, ...] = DETECTORS,
) -> list[ColumnFinding]:
    findings: list[ColumnFinding] = []
    for name in frame.columns:
        values = [None if v is None else str(v) for v in frame.get_column(name).to_list()]
        findings.extend(
            scan_column(name, values, threshold=threshold, sample=sample, detectors=detectors)
        )
    findings.sort(key=lambda f: f.sort_key)
    return findings


def scan_file(
    path: str | Path,
    *,
    threshold: float = 0.5,
    sample: int | None = None,
) -> list[ColumnFinding]:
    return scan_frame(read_frame(path), threshold=threshold, sample=sample)
