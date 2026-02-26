"""
findings.py – Shared data structures for unrealm detection results.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class Severity(enum.Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single detected artifact or indicator of compromise."""

    category: str           # e.g. "process", "file", "service", "network", "registry"
    severity: Severity
    title: str
    detail: str
    path: Optional[str] = None       # Filesystem path, registry key, or similar locator
    extra: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        loc = f" [{self.path}]" if self.path else ""
        return f"[{self.severity.value}] {self.category.upper()} – {self.title}{loc}: {self.detail}"


@dataclass
class ScanReport:
    """Top-level container for all findings from a scan run."""

    platform: str
    findings: List[Finding] = field(default_factory=list)

    # ------------------------------------------------------------------ helpers
    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def has_detections(self) -> bool:
        return bool(self.findings)

    def by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def by_category(self, category: str) -> List[Finding]:
        return [f for f in self.findings if f.category == category]

    def count(self) -> int:
        return len(self.findings)
