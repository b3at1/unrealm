"""
scanner.py – Orchestrates all detectors and produces a ScanReport.
"""
from __future__ import annotations

import platform

from unrealm.findings import ScanReport
from unrealm.detectors import network


def run_scan(verbose: bool = False) -> ScanReport:
    """
    Detect the current platform, run the matching detectors, add network
    checks, and return the completed ScanReport.
    """
    system = platform.system()
    report = ScanReport(platform=system)

    # ── Platform-specific detectors ───────────────────────────────────────────
    if system == "Linux":
        from unrealm.detectors import linux as plat_detector
        plat_detector.scan(report)
    elif system == "Darwin":
        from unrealm.detectors import macos as plat_detector
        plat_detector.scan(report)
    elif system == "Windows":
        from unrealm.detectors import windows as plat_detector
        plat_detector.scan(report)
    else:
        # Best-effort on unknown Unix-like systems: run Linux checks
        from unrealm.detectors import linux as plat_detector
        plat_detector.scan(report)

    # ── Cross-platform network checks (always run) ────────────────────────────
    network.scan(report)

    return report
