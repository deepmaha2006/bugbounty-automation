"""
Data models shared across the framework.

These classes normalize the output of every scanner into one consistent
shape so the UI, report generator and storage layer never have to care
about where a finding came from.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    """A single vulnerability finding.

    ``confidence`` holds the classification tier produced by
    :func:`core.finding.classify_finding` (confirmed | possible | info).
    ``verified`` mirrors it (True only for confirmed) and ``evidence_kind``
    records how the evidence was obtained (observed | inspection | heuristic).
    """

    severity: str = "Info"          # Critical | High | Medium | Low | Info
    type: str = "Unknown"
    description: str = ""
    evidence: str = ""
    url: str = ""
    remediation: str = ""
    scan_type: str = ""
    confidence: str = "confirmed"   # confirmed | possible | info
    evidence_kind: str = "observed"
    verified: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any], scan_type: str = "") -> "Finding":
        # Classification enforces the confidence tiers + severity caps, so a
        # heuristic can never enter the report as a High/Critical confirmed
        # vulnerability regardless of what a scanner claimed.
        from core.finding import classify_finding
        classified = classify_finding(raw, scanner_key=scan_type)
        return cls(
            severity=str(classified.get("severity", "Info")),
            type=str(classified.get("type", "Unknown")),
            description=str(classified.get("description", "")),
            evidence=str(classified.get("evidence", "")),
            url=str(classified.get("url", "")),
            remediation=str(classified.get("remediation", "")),
            scan_type=scan_type or str(classified.get("scan_type", "")),
            confidence=str(classified.get("confidence", "confirmed")),
            evidence_kind=str(classified.get("evidence_kind", "observed")),
            verified=bool(classified.get("verified", True)),
        )


@dataclass
class ScanResult:
    """Normalized result of running one scanner against one target."""

    scanner_key: str
    scanner_name: str
    target: str
    findings: List[Finding] = field(default_factory=list)
    status: str = "pending"         # pending | running | done | error
    error: str = ""
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return 0.0

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "Critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "High")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "Medium")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner": self.scanner_name,
            "target": self.target,
            "status": self.status,
            "error": self.error,
            "vulnerabilities": [f.to_dict() for f in self.findings],
            "total_findings": self.finding_count,
            "duration": round(self.duration, 2),
        }


class ScanReport:
    """Aggregated report object produced after a full scan run."""

    def __init__(self, target: str, results: List[ScanResult],
                 started_at: datetime, finished_at: datetime,
                 selected_keys: List[str]):
        self.target = target
        self.results = results
        self.started_at = started_at
        self.finished_at = finished_at
        self.selected_keys = selected_keys

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.finished_at - self.started_at).total_seconds())

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for r in self.results:
            for f in r.findings:
                counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def total_findings(self) -> int:
        return sum(r.finding_count for r in self.results)

    def security_score(self, weights: Optional[Dict[str, int]] = None) -> int:
        """Aggregate 0-100 security score from severity weights."""
        from config.settings import SEVERITY_WEIGHTS
        w = weights or SEVERITY_WEIGHTS
        score = 100
        for sev, count in self.severity_counts.items():
            score += count * w.get(sev, 0)
        return max(0, min(100, score))

    def grade(self, score: int) -> tuple:
        """Return (grade, color, label) for a given score."""
        if score >= 80:
            return "A", "#10b981", "Low Risk"
        if score >= 60:
            return "B", "#f59e0b", "Medium Risk"
        if score >= 40:
            return "C", "#f97316", "High Risk"
        return "F", "#ef4444", "Critical Risk"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.started_at.isoformat(),
            "duration": str(round(self.duration_seconds, 1)) + "s",
            "scans_selected": self.selected_keys,
            "security_score": self.security_score(),
            "severity_counts": self.severity_counts,
            "results": {r.scanner_key: r.to_dict() for r in self.results},
        }
