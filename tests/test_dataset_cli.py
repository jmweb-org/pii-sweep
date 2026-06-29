from __future__ import annotations

import json

import polars as pl
import pytest
from typer.testing import CliRunner

from pii_sweep import __version__
from pii_sweep import cli as cli_module
from pii_sweep.dataset import read_frame, scan_file

runner = CliRunner()


def _csv(tmp_path, name, frame):
    path = tmp_path / name
    frame.write_csv(path)
    return path


def test_read_unsupported_extension(tmp_path):
    path = tmp_path / "data.txt"
    path.write_text("nope")
    with pytest.raises(ValueError):
        read_frame(path)


def test_scan_file_flags_pii_columns(tmp_path):
    frame = pl.DataFrame(
        {
            "email": ["a@x.com", "b@y.com", "c@z.com"],
            "city": ["Madrid", "Paris", "Berlin"],
        }
    )
    path = _csv(tmp_path, "people.csv", frame)
    findings = scan_file(path)
    cols = {f.column for f in findings}
    assert "email" in cols
    assert "city" not in cols


def test_version():
    result = runner.invoke(cli_module.app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_scan_json(tmp_path):
    frame = pl.DataFrame({"email": ["a@x.com", "b@y.com"]})
    path = _csv(tmp_path, "d.csv", frame)
    result = runner.invoke(cli_module.app, ["scan", str(path), "--json"])
    assert result.exit_code == 0
    findings = json.loads(result.stdout)
    assert findings[0]["detector"] == "email"
    assert "masked_sample" not in findings[0]


def test_scan_json_can_include_masked_samples(tmp_path):
    frame = pl.DataFrame({"email": ["alice@example.com", "bob@example.com"]})
    path = _csv(tmp_path, "d.csv", frame)
    result = runner.invoke(cli_module.app, ["scan", str(path), "--json", "--show-samples"])
    assert result.exit_code == 0
    findings = json.loads(result.stdout)
    assert findings[0]["masked_sample"] == "a***@***.com"
    assert "alice@example.com" not in result.stdout


def test_scan_table_can_include_masked_samples(tmp_path):
    frame = pl.DataFrame({"email": ["alice@example.com", "bob@example.com"]})
    path = _csv(tmp_path, "d.csv", frame)
    result = runner.invoke(cli_module.app, ["scan", str(path), "--show-samples"])
    assert result.exit_code == 0
    assert "a***@***.com" in result.stdout
    assert "alice@example.com" not in result.stdout


def test_scan_clean_dataset_reports_none(tmp_path):
    frame = pl.DataFrame({"city": ["Madrid", "Paris"]})
    path = _csv(tmp_path, "clean.csv", frame)
    result = runner.invoke(cli_module.app, ["scan", str(path)])
    assert result.exit_code == 0
    assert "no PII detected" in result.stdout


def test_scan_check_fails_on_pii(tmp_path):
    frame = pl.DataFrame({"email": ["a@x.com", "b@y.com"]})
    path = _csv(tmp_path, "d.csv", frame)
    result = runner.invoke(cli_module.app, ["scan", str(path), "--check"])
    assert result.exit_code == cli_module.EXIT_PII_FOUND


def test_scan_check_fail_on_high_ignores_low(tmp_path):
    frame = pl.DataFrame({"ip": ["8.8.8.8", "1.1.1.1"]})
    path = _csv(tmp_path, "ips.csv", frame)
    result = runner.invoke(cli_module.app, ["scan", str(path), "--check", "--fail-on", "high"])
    assert result.exit_code == 0


def test_scan_missing_file_is_bad_input(tmp_path):
    result = runner.invoke(cli_module.app, ["scan", str(tmp_path / "missing.csv")])
    assert result.exit_code == cli_module.EXIT_BAD_INPUT
