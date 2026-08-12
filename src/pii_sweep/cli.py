"""Command-line interface for pii-sweep."""

from __future__ import annotations

import json
import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console

from pii_sweep import __version__
from pii_sweep.dataset import scan_file
from pii_sweep.detectors import Severity
from pii_sweep.render import findings_to_json, render_table
from pii_sweep.scan import has_pii

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Scan dataset files for personally identifiable information.",
)
_out = Console()
_err = Console(stderr=True)

EXIT_OK = 0
EXIT_PII_FOUND = 1
EXIT_BAD_INPUT = 2


class FailOn(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


_FAIL_SEVERITY = {
    FailOn.high: Severity.HIGH,
    FailOn.medium: Severity.MEDIUM,
    FailOn.low: Severity.LOW,
}


def _version_callback(value: bool) -> None:
    if value:
        _out.print(f"pii-sweep {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """pii-sweep command-line interface."""


@app.command("scan")
def scan(
    dataset: Path = typer.Argument(..., help="Dataset file (CSV, Parquet, JSONL)."),
    threshold: float = typer.Option(
        0.5, "--threshold", help="Min match fraction to flag a column."
    ),
    sample: int = typer.Option(0, "--sample", help="Sample at most N values per column (0 = all)."),
    as_json: bool = typer.Option(False, "--json", help="Emit findings as JSON."),
    show_samples: bool = typer.Option(
        False,
        "--show-samples",
        help="Show one masked sample value for each finding.",
    ),
    check: bool = typer.Option(False, "--check", help="Exit non-zero if PII is found."),
    fail_on: FailOn = typer.Option(
        FailOn.low, "--fail-on", help="Lowest severity that --check treats as PII."
    ),
) -> None:
    """Scan a dataset for PII and report flagged columns."""

    try:
        findings = scan_file(dataset, threshold=threshold, sample=sample or None)
    except (OSError, ValueError) as exc:
        _err.print(f"pii-sweep: {exc}")
        raise typer.Exit(EXIT_BAD_INPUT) from exc

    if as_json:
        _out.print_json(json.dumps(findings_to_json(findings, show_samples=show_samples)))
    else:
        _out.print(render_table(findings, show_samples=show_samples))

    if check and has_pii(findings, _FAIL_SEVERITY[fail_on]):
        raise typer.Exit(EXIT_PII_FOUND)


def entrypoint() -> None:
    try:
        app()
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print("pii-sweep: interrupted", file=sys.stderr)
        raise SystemExit(130) from None
