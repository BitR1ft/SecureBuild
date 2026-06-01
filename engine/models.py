"""SecureBuild CI/CD Security Gate - Data Models"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    """Represents a single security finding detected by a gate."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    gate: str = ""
    file: str = ""
    line: int = 0
    message: str = ""
    cvss_score: float = 0.0
    severity: str = "info"
    fix_suggestion: str = ""
    fix_diff: str = ""
    cwe_id: str = ""
    rule_id: str = ""
    finding_type: str = "vulnerability"
    confidence: str = "medium"


    VALID_SEVERITIES: List[str] = field(
        default_factory=lambda: ["critical", "high", "medium", "low", "info"],
        repr=False,
        compare=False,
    )
    VALID_FINDING_TYPES: List[str] = field(
        default_factory=lambda: [
            "vulnerability",
            "misconfiguration",
            "secret",
            "dependency",
            "compliance",
        ],
        repr=False,
        compare=False,
    )
    VALID_CONFIDENCES: List[str] = field(
        default_factory=lambda: ["high", "medium", "low"],
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if self.severity not in self.VALID_SEVERITIES:
            self.severity = "info"
        if self.finding_type not in self.VALID_FINDING_TYPES:
            self.finding_type = "vulnerability"
        if self.confidence not in self.VALID_CONFIDENCES:
            self.confidence = "medium"
        self.cvss_score = max(0.0, min(10.0, float(self.cvss_score)))
        self.line = max(0, int(self.line))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "gate": self.gate,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "fix_suggestion": self.fix_suggestion,
            "fix_diff": self.fix_diff,
            "cwe_id": self.cwe_id,
            "rule_id": self.rule_id,
            "finding_type": self.finding_type,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Finding:
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            gate=data.get("gate", ""),
            file=data.get("file", ""),
            line=data.get("line", 0),
            message=data.get("message", ""),
            cvss_score=data.get("cvss_score", 0.0),
            severity=data.get("severity", "info"),
            fix_suggestion=data.get("fix_suggestion", ""),
            fix_diff=data.get("fix_diff", ""),
            cwe_id=data.get("cwe_id", ""),
            rule_id=data.get("rule_id", ""),
            finding_type=data.get("finding_type", "vulnerability"),
            confidence=data.get("confidence", "medium"),
        )


@dataclass
class GateResult:
    """Represents the result of running a single security gate."""

    gate_name: str = ""
    status: str = "pass"
    findings: List[Finding] = field(default_factory=list)
    duration_ms: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    VALID_STATUSES: List[str] = field(
        default_factory=lambda: ["pass", "fail", "error"],
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if self.status not in self.VALID_STATUSES:
            self.status = "error"
        self.duration_ms = max(0, int(self.duration_ms))
        self.files_scanned = max(0, int(self.files_scanned))
        self.files_skipped = max(0, int(self.files_skipped))

    @property
    def findings_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def has_critical_or_high(self) -> bool:
        return self.critical_count > 0 or self.high_count > 0

    @property
    def highest_severity(self) -> str:
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        if not self.findings:
            return "info"
        return max(
            self.findings, key=lambda f: severity_order.get(f.severity, 0)
        ).severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gate_name": self.gate_name,
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "findings_count": self.findings_count,
            "duration_ms": self.duration_ms,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GateResult:
        findings_data = data.get("findings", [])
        findings = [Finding.from_dict(f) if isinstance(f, dict) else f for f in findings_data]
        return cls(
            gate_name=data.get("gate_name", ""),
            status=data.get("status", "pass"),
            findings=findings,
            duration_ms=data.get("duration_ms", 0),
            files_scanned=data.get("files_scanned", 0),
            files_skipped=data.get("files_skipped", 0),
            metadata=data.get("metadata", {}),
        )


@dataclass
class RiskScore:
    """Represents the computed risk score for a pipeline run."""

    overall: float = 0.0
    by_gate: Dict[str, float] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)
    recommendation: str = ""
    trend: str = "new"
    percentile: float = 0.0

    VALID_TRENDS: List[str] = field(
        default_factory=lambda: ["improving", "stable", "degrading", "new"],
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        self.overall = max(0.0, min(100.0, float(self.overall)))
        if self.trend not in self.VALID_TRENDS:
            self.trend = "new"
        self.percentile = max(0.0, min(100.0, float(self.percentile)))

    @property
    def risk_level(self) -> str:
        if self.overall >= 80:
            return "critical"
        elif self.overall >= 60:
            return "high"
        elif self.overall >= 40:
            return "medium"
        elif self.overall >= 20:
            return "low"
        return "minimal"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall": self.overall,
            "by_gate": self.by_gate,
            "by_severity": self.by_severity,
            "recommendation": self.recommendation,
            "trend": self.trend,
            "percentile": self.percentile,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RiskScore:
        return cls(
            overall=data.get("overall", 0.0),
            by_gate=data.get("by_gate", {}),
            by_severity=data.get("by_severity", {}),
            recommendation=data.get("recommendation", ""),
            trend=data.get("trend", "new"),
            percentile=data.get("percentile", 0.0),
        )


@dataclass
class RunResult:
    """Represents the complete result of a SecureBuild pipeline run."""

    run_id: str = ""
    repo: str = ""
    branch: str = ""
    commit_hash: str = ""
    timestamp: str = ""
    overall_score: float = 0.0
    status: str = "pass"
    gate_results: List[GateResult] = field(default_factory=list)
    risk_score: Optional[RiskScore] = None
    duration_ms: int = 0

    VALID_STATUSES: List[str] = field(
        default_factory=lambda: ["pass", "fail", "error"],
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if self.status not in self.VALID_STATUSES:
            self.status = "error"
        self.overall_score = max(0.0, min(100.0, float(self.overall_score)))
        self.duration_ms = max(0, int(self.duration_ms))

    @property
    def total_findings(self) -> int:
        return sum(gr.findings_count for gr in self.gate_results)

    @property
    def total_critical(self) -> int:
        return sum(gr.critical_count for gr in self.gate_results)

    @property
    def total_high(self) -> int:
        return sum(gr.high_count for gr in self.gate_results)

    @property
    def failed_gates(self) -> List[str]:
        return [gr.gate_name for gr in self.gate_results if gr.status != "pass"]

    @property
    def all_findings(self) -> List[Finding]:
        findings: List[Finding] = []
        for gr in self.gate_results:
            findings.extend(gr.findings)
        return findings

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "repo": self.repo,
            "branch": self.branch,
            "commit_hash": self.commit_hash,
            "timestamp": self.timestamp,
            "overall_score": self.overall_score,
            "status": self.status,
            "gate_results": [gr.to_dict() for gr in self.gate_results],
            "risk_score": self.risk_score.to_dict() if self.risk_score else None,
            "duration_ms": self.duration_ms,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RunResult:
        gate_results_data = data.get("gate_results", [])
        gate_results = [
            GateResult.from_dict(gr) if isinstance(gr, dict) else gr
            for gr in gate_results_data
        ]
        risk_score_data = data.get("risk_score")
        risk_score = RiskScore.from_dict(risk_score_data) if risk_score_data else None
        return cls(
            run_id=data.get("run_id", ""),
            repo=data.get("repo", ""),
            branch=data.get("branch", ""),
            commit_hash=data.get("commit_hash", ""),
            timestamp=data.get("timestamp", ""),
            overall_score=data.get("overall_score", 0.0),
            status=data.get("status", "pass"),
            gate_results=gate_results,
            risk_score=risk_score,
            duration_ms=data.get("duration_ms", 0),
        )


@dataclass
class RemediationSuggestion:
    """Represents an actionable remediation suggestion for a finding."""

    finding_id: str = ""
    title: str = ""
    explanation: str = ""
    fix_code_before: str = ""
    fix_code_after: str = ""
    references: List[str] = field(default_factory=list)
    effort: str = "medium"
    quick_win: bool = False
    estimated_minutes: int = 30

    VALID_EFFORTS: List[str] = field(
        default_factory=lambda: ["low", "medium", "high"],
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if self.effort not in self.VALID_EFFORTS:
            self.effort = "medium"
        self.estimated_minutes = max(0, int(self.estimated_minutes))
        # Auto-detect quick_win if effort is low and quick_win is False
        if self.effort == "low" and self.estimated_minutes <= 15:
            self.quick_win = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "explanation": self.explanation,
            "fix_code_before": self.fix_code_before,
            "fix_code_after": self.fix_code_after,
            "references": self.references,
            "effort": self.effort,
            "quick_win": self.quick_win,
            "estimated_minutes": self.estimated_minutes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RemediationSuggestion:
        return cls(
            finding_id=data.get("finding_id", ""),
            title=data.get("title", ""),
            explanation=data.get("explanation", ""),
            fix_code_before=data.get("fix_code_before", ""),
            fix_code_after=data.get("fix_code_after", ""),
            references=data.get("references", []),
            effort=data.get("effort", "medium"),
            quick_win=data.get("quick_win", False),
            estimated_minutes=data.get("estimated_minutes", 30),
        )
