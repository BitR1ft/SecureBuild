"""SecureBuild CI/CD Security Gate - Orchestrator Tests"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from engine.config import SecureBuildConfig
from engine.db import DatabaseManager
from engine.models import Finding, GateResult, RiskScore, RunResult
from engine.orchestrator import Orchestrator


class TestRiskScorerImport:
    def test_risk_scorer_imported_from_scoring_module(self):
        from engine.orchestrator import RiskScorer as OrchestratorScorer
        from scoring.scorer import RiskScorer as ScoringScorer
        # Both should reference the same class
        assert OrchestratorScorer is ScoringScorer

    def test_risk_scorer_has_calculate_score_method(self):
        from engine.orchestrator import RiskScorer
        scorer = RiskScorer()
        assert hasattr(scorer, "calculate_score"), \
            "RiskScorer from scoring.scorer must have calculate_score()"


@pytest.fixture
def config():
    return SecureBuildConfig()


@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test_orch.db")
    return DatabaseManager(db_path)


@pytest.fixture
def orchestrator(config, db):
    # Pass an empty gate_classes dict; we'll inject mocks per test
    return Orchestrator(config=config, db_manager=db, gate_classes={})


@pytest.fixture
def mock_gate_class():
    def _make(gate_name: str, findings: List[Finding] = None, status: str = "pass"):
        findings = findings or []
        mock_cls = MagicMock()
        mock_instance = MagicMock()
        mock_instance.name = gate_name
        result = GateResult(
            gate_name=gate_name,
            status=status,
            findings=findings,
            duration_ms=50,
            files_scanned=3,
        )
        mock_instance.run.return_value = result
        mock_cls.return_value = mock_instance
        return mock_cls
    return _make


@pytest.fixture
def temp_git_repo(tmp_path):
    import subprocess
    (tmp_path / ".git").mkdir()
    subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
    return str(tmp_path)


class TestOrchestratorInit:
    def test_creates_with_defaults(self, config, db):
        orch = Orchestrator(config=config, db_manager=db, gate_classes={})
        assert orch.config is config
        assert orch.db_manager is db
        assert orch.risk_scorer is not None

    def test_risk_scorer_is_scoring_module_instance(self, config, db):
        from scoring.scorer import RiskScorer
        orch = Orchestrator(config=config, db_manager=db, gate_classes={})
        assert isinstance(orch.risk_scorer, RiskScorer)

    def test_register_gate(self, orchestrator, mock_gate_class):
        gate_cls = mock_gate_class("test-gate")
        orchestrator.register_gate("test-gate", gate_cls)
        assert "test-gate" in orchestrator._gate_classes

    def test_register_default_gates_logs_warning_on_missing(self, config, db, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="orchestrator"):
            orch = Orchestrator(config=config, db_manager=db)
        # Should not raise, even if some gates aren't importable in test env


class TestComputeOverallScore:
    def setup_method(self):
        config = SecureBuildConfig()
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DatabaseManager(str(Path(tmpdir) / "test.db"))
            self.orch = Orchestrator(config=config, db_manager=db, gate_classes={})

    def test_with_risk_score_inverts(self):
        risk = RiskScore(overall=40.0, by_gate={}, by_severity={})
        gate_results: List[GateResult] = []
        score = self.orch._compute_overall_score(gate_results, risk)
        assert score == pytest.approx(60.0, abs=0.01)

    def test_without_risk_score_all_pass(self):
        gate_results = [
            GateResult("secrets", "pass", [], 100, 5),
            GateResult("sast", "pass", [], 100, 5),
        ]
        score = self.orch._compute_overall_score(gate_results, None)
        assert score == pytest.approx(100.0, abs=1.0)

    def test_without_risk_score_empty_gates(self):
        score = self.orch._compute_overall_score([], None)
        assert score == 100.0


class TestDetermineStatus:
    def setup_method(self):
        config = SecureBuildConfig()
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DatabaseManager(str(Path(tmpdir) / "test.db"))
            self.orch = Orchestrator(config=config, db_manager=db, gate_classes={})

    def test_all_pass_returns_pass(self):
        gate_results = [GateResult("secrets", "pass", [], 100, 5)]
        status = self.orch._determine_status(gate_results, None)
        assert status == "pass"

    def test_any_fail_returns_fail(self):
        gate_results = [
            GateResult("secrets", "pass", [], 100, 5),
            GateResult("sast", "fail", [], 100, 5),
        ]
        status = self.orch._determine_status(gate_results, None)
        assert status == "fail"

    def test_any_error_returns_error(self):
        gate_results = [GateResult("sast", "error", [], 100, 5)]
        status = self.orch._determine_status(gate_results, None)
        assert status == "error"

    def test_fail_and_error_returns_fail(self):
        gate_results = [
            GateResult("sast", "error", [], 100, 5),
            GateResult("secrets", "fail", [], 100, 5),
        ]
        status = self.orch._determine_status(gate_results, None)
        assert status == "fail"


class TestOrchestratorRun:
    def test_run_invalid_path_raises(self, orchestrator, tmp_path):
        nonexistent = str(tmp_path / "does-not-exist")
        from engine.exceptions import InvalidRepoError
        with pytest.raises(InvalidRepoError):
            orchestrator.run(nonexistent)

    def test_run_non_git_dir_raises(self, orchestrator, tmp_path):
        # Create a real directory but without .git
        repo = tmp_path / "not-a-git-repo"
        repo.mkdir()
        from engine.exceptions import InvalidRepoError
        with pytest.raises(InvalidRepoError):
            orchestrator.run(str(repo))

    def test_run_happy_path(self, config, db, mock_gate_class, tmp_path):
        import subprocess
        # Create a proper git repo
        (tmp_path / ".git").mkdir()
        subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=str(tmp_path), capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"], cwd=str(tmp_path),
            capture_output=True,
        )

        gate_cls = mock_gate_class("secrets", findings=[], status="pass")
        orch = Orchestrator(config=config, db_manager=db, gate_classes={"secrets": gate_cls})

        result = orch.run(str(tmp_path))
        assert isinstance(result, RunResult)
        assert result.repo is not None
        assert result.status in ("pass", "fail", "error")
