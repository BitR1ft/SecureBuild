"""SecureBuild CI/CD Security Gate - Risk Scorer Tests"""

from __future__ import annotations

import math
from typing import List
from unittest.mock import MagicMock

import pytest

from engine.models import Finding, GateResult, RiskScore, RunResult
from scoring.scorer import RiskScorer


def _make_finding(
    gate: str = "secrets",
    severity: str = "high",
    cvss_score: float = 7.5,
    finding_type: str = "secret",
) -> Finding:
    return Finding(
        gate=gate,
        file="app.py",
        line=1,
        message=f"{severity} finding in {gate}",
        cvss_score=cvss_score,
        severity=severity,
        rule_id=f"{gate}-test",
        cwe_id="CWE-798",
        finding_type=finding_type,
    )


def _make_run(findings_by_gate: dict) -> RunResult:
    gate_results = [
        GateResult(
            gate_name=gate,
            status="fail" if findings else "pass",
            findings=findings,
            duration_ms=100,
            files_scanned=5,
        )
        for gate, findings in findings_by_gate.items()
    ]
    return RunResult(
        run_id="20250101-test1234",
        repo="test/repo",
        branch="main",
        commit_hash="abc123",
        timestamp="2025-01-01T00:00:00Z",
        overall_score=0.0,
        status="fail",
        gate_results=gate_results,
        risk_score=None,
        duration_ms=500,
    )


class TestRiskScorerInit:
    def test_init_no_db(self):
        scorer = RiskScorer()
        assert scorer.db_manager is None

    def test_init_with_db(self):
        mock_db = MagicMock()
        scorer = RiskScorer(db_manager=mock_db)
        assert scorer.db_manager is mock_db


class TestCalculateScore:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_empty_run_returns_zero(self):
        run = _make_run({"secrets": [], "sast": []})
        score = self.scorer.calculate_score(run)
        assert score.overall == 0.0
        assert score.by_severity["critical"] == 0
        assert score.by_severity["high"] == 0

    def test_critical_findings_raise_score(self):
        run = _make_run({
            "secrets": [_make_finding("secrets", "critical", 9.8)],
        })
        score = self.scorer.calculate_score(run)
        assert score.overall > 0.0
        assert score.by_severity["critical"] == 1

    def test_multiple_severities_counted(self):
        run = _make_run({
            "secrets": [
                _make_finding("secrets", "critical", 9.1),
                _make_finding("secrets", "high", 7.5),
            ],
            "sast": [
                _make_finding("sast", "medium", 5.0, "vulnerability"),
            ],
        })
        score = self.scorer.calculate_score(run)
        assert score.by_severity["critical"] == 1
        assert score.by_severity["high"] == 1
        assert score.by_severity["medium"] == 1

    def test_score_clamped_to_100(self):
        findings = [_make_finding("secrets", "critical", 10.0) for _ in range(50)]
        run = _make_run({"secrets": findings})
        score = self.scorer.calculate_score(run)
        assert 0.0 <= score.overall <= 100.0

    def test_score_is_float(self):
        run = _make_run({"cve": [_make_finding("cve", "high", 7.5, "dependency")]})
        score = self.scorer.calculate_score(run)
        assert isinstance(score.overall, float)

    def test_gate_weights_applied(self):
        secrets_run = _make_run({"secrets": [_make_finding("secrets", "high", 7.5)]})
        license_run = _make_run({"license": [_make_finding("license", "high", 7.5, "compliance")]})

        secrets_score = self.scorer.calculate_score(secrets_run)
        license_score = self.scorer.calculate_score(license_run)
        assert secrets_score.overall >= license_score.overall

    def test_returns_risk_score_object(self):
        run = _make_run({"sast": [_make_finding("sast", "high", 7.0, "vulnerability")]})
        score = self.scorer.calculate_score(run)
        assert isinstance(score, RiskScore)
        assert hasattr(score, "overall")
        assert hasattr(score, "by_gate")
        assert hasattr(score, "by_severity")


class TestGetSeverityBreakdown:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_empty(self):
        result = self.scorer.get_severity_breakdown([])
        assert result == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def test_single_finding(self):
        f = _make_finding("secrets", "critical", 9.1)
        result = self.scorer.get_severity_breakdown([f])
        assert result["critical"] == 1
        assert result["high"] == 0

    def test_multiple_severities(self):
        findings = [
            _make_finding("secrets", "critical", 9.1),
            _make_finding("sast", "high", 7.5),
            _make_finding("sast", "high", 7.0),
            _make_finding("cve", "medium", 5.0),
        ]
        result = self.scorer.get_severity_breakdown(findings)
        assert result["critical"] == 1
        assert result["high"] == 2
        assert result["medium"] == 1


class TestIsBlocking:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_blocks_on_critical(self):
        assert self.scorer.is_blocking(30.0, {"critical_count": 1}) is True

    def test_blocks_on_five_highs(self):
        assert self.scorer.is_blocking(30.0, {"high_count": 5}) is True

    def test_no_block_below_threshold(self):
        assert self.scorer.is_blocking(20.0, {"critical_count": 0, "high_count": 0}) is False

    def test_warn_only_never_blocks(self):
        assert self.scorer.is_blocking(100.0, {"warn_only": True, "critical_count": 5}) is False

    def test_blocks_on_high_score(self):
        # Score > 7.0 on 0-10 scale should block
        assert self.scorer.is_blocking(8.0, {"score_scale": "0-10"}) is True


class TestGetTrend:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_no_history_returns_new(self):
        assert self.scorer.get_trend(5.0, []) == "new"

    def test_improving_trend(self):
        # Current score much lower than historical average
        historical = [7.0, 8.0, 9.0, 8.5, 7.5]
        result = self.scorer.get_trend(5.0, historical)
        assert result == "improving"

    def test_degrading_trend(self):
        # Current score much higher than historical average
        historical = [2.0, 3.0, 2.5, 3.5, 2.0]
        result = self.scorer.get_trend(7.0, historical)
        assert result == "degrading"

    def test_stable_trend(self):
        historical = [5.0, 5.0, 5.0, 5.0, 5.0]
        result = self.scorer.get_trend(5.2, historical)
        assert result == "stable"

    def test_critical_regression(self):
        historical = [2.0, 2.5, 2.0, 2.5, 2.0]
        result = self.scorer.get_trend(8.0, historical)
        assert result == "critical_regression"


class TestCalculateCvssBaseScore:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_network_critical_no_priv(self):
        score = self.scorer.calculate_cvss_base_score(
            av="Network", ac="Low", pr="None", ui="None",
            scope="Unchanged", c="High", i="High", a="High"
        )
        assert score == pytest.approx(9.8, abs=0.1)

    def test_local_low_impact(self):
        score = self.scorer.calculate_cvss_base_score(
            av="Local", ac="High", pr="High", ui="Required",
            scope="Unchanged", c="Low", i="None", a="None"
        )
        assert 0.0 <= score <= 10.0

    def test_no_impact_returns_zero(self):
        score = self.scorer.calculate_cvss_base_score(
            av="Network", ac="Low", pr="None", ui="None",
            scope="Unchanged", c="None", i="None", a="None"
        )
        assert score == 0.0


class TestSimulateFix:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_fixing_all_returns_zero(self):
        f = _make_finding("secrets", "critical", 9.1)
        run = _make_run({"secrets": [f]})
        result = self.scorer.simulate_fix(run, [f.id])
        assert result == 0.0

    def test_fixing_some_reduces_score(self):
        f1 = _make_finding("secrets", "critical", 9.1)
        f2 = _make_finding("sast", "high", 7.5, "vulnerability")
        run = _make_run({"secrets": [f1], "sast": [f2]})
        original = self.scorer.calculate_score(run).overall
        projected = self.scorer.simulate_fix(run, [f1.id])
        assert projected < original

    def test_no_findings_to_fix(self):
        run = _make_run({"secrets": []})
        result = self.scorer.simulate_fix(run, ["nonexistent-id"])
        assert result == 0.0
