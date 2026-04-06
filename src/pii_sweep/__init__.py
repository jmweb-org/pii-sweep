"""pii-sweep: scan dataset files for personally identifiable information."""

from pii_sweep.dataset import scan_file, scan_frame
from pii_sweep.detectors import DETECTORS, Detector, Severity
from pii_sweep.scan import ColumnFinding, has_pii, scan_column, scan_values

__version__ = "0.1.0"

__all__ = [
    "DETECTORS",
    "ColumnFinding",
    "Detector",
    "Severity",
    "__version__",
    "has_pii",
    "scan_column",
    "scan_file",
    "scan_frame",
    "scan_values",
]
