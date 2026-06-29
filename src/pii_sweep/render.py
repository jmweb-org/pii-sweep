"""Render PII findings for the terminal and as JSON."""

from __future__ import annotations

from rich.console import Group
from rich.table import Table
from rich.text import Text

from pii_sweep.detectors import Severity
from pii_sweep.scan import ColumnFinding

_STYLE = {Severity.HIGH: "bold red", Severity.MEDIUM: "yellow", Severity.LOW: "dim"}


def findings_to_json(findings: list[ColumnFinding], *, show_samples: bool = False) -> list[dict]:
    rows = [
        {
            "column": f.column,
            "detector": f.detector,
            "severity": f.severity.value,
            "confidence": round(f.confidence, 4),
            "sampled": f.sampled,
        }
        for f in findings
    ]
    if show_samples:
        for row, finding in zip(rows, findings, strict=True):
            row["masked_sample"] = finding.masked_sample
    return rows


def render_table(findings: list[ColumnFinding], *, show_samples: bool = False) -> Group:
    if not findings:
        return Group(Text("no PII detected", style="green"))
    table = Table(box=None, pad_edge=False)
    table.add_column("severity")
    table.add_column("column", style="cyan")
    table.add_column("type")
    table.add_column("confidence", justify="right")
    if show_samples:
        table.add_column("sample")
    for f in findings:
        row = [
            Text(f.severity.value, style=_STYLE[f.severity]),
            f.column,
            f.detector,
            f"{f.confidence:.0%}",
        ]
        if show_samples:
            row.append(f.masked_sample or "")
        table.add_row(*row)
    return Group(table)
