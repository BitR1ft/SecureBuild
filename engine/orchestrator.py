"""SecureBuild CI/CD Security Gate - Main Orchestrator"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Type

from engine.config import SecureBuildConfig
from engine.db import DatabaseManager
from engine.exceptions import GateExecutionError, InvalidRepoError, ScoringError
from engine.logger import get_logger
from engine.models import GateResult, RiskScore, RunResult
from engine.runner import GateRunner
from engine.utils import (
    generate_run_id,
    get_commit_hash,
    get_current_branch,
    get_repo_name,
    validate_repo_path,
)
from gates.base import BaseGate
from scoring.scorer import RiskScorer

logger = get_logger("orchestrator")


class Orchestrator:
    """Central controller for the SecureBuild pipeline."""

    def __init__(
        self,
        config: SecureBuildConfig,
        db_manager: DatabaseManager,
        gate_classes: Optional[Dict[str, Type[BaseGate]]] = None,
    ) -> None:
        self.config = config
        self.db_manager = db_manager
        self.risk_scorer = RiskScorer(db_manager=db_manager)
        self._gate_classes = gate_classes or {}
        self._register_default_gates()

    def _register_default_gates(self) -> None:
        gate_imports = {
            "secrets": ("gates.gate1_secrets", "SecretsGate"),
            "sast": ("gates.gate2_sast", "SASTGate"),
            "cve": ("gates.gate3_cve", "CVEGate"),
            "license": ("gates.gate4_license", "LicenseGate"),
            "iac": ("gates.gate5_iac", "IACGate"),
        }

        for gate_name, (module_name, class_name) in gate_imports.items():
            if gate_name in self._gate_classes:
                continue  # Already registered
            try:
                import importlib
                module = importlib.import_module(module_name)
                gate_class = getattr(module, class_name)
                self._gate_classes[gate_name] = gate_class
                logger.debug("Auto-registered gate: %s", gate_name)
            except (ImportError, AttributeError) as exc:
                logger.warning(
                    "Could not auto-register gate '%s': %s",
                    gate_name,
                    str(exc),
                )

    def register_gate(self, name: str, gate_class: Type[BaseGate]) -> None:
        self._gate_classes[name] = gate_class
        logger.info("Registered custom gate: %s", name)

    def run(
        self,
        repo_path: str,
        run_config: Optional[dict] = None,
    ) -> RunResult:
        start_time = time.monotonic()
        run_id = generate_run_id()

        logger.info(
            "Starting SecureBuild pipeline run: %s",
            run_id,
            extra={"run_id": run_id},
        )

        try:
            validated_path = validate_repo_path(repo_path)
            repo_path_str = str(validated_path)
        except InvalidRepoError:
            logger.error(
                "Invalid repository path: %s",
                repo_path,
                extra={"run_id": run_id},
            )
            raise

        repo_name = get_repo_name(repo_path_str)
        try:
            branch = get_current_branch(repo_path_str)
        except InvalidRepoError:
            branch = "unknown"
            logger.warning(
                "Could not determine branch, using 'unknown'",
                extra={"run_id": run_id},
            )

        try:
            commit_hash = get_commit_hash(repo_path_str)
        except InvalidRepoError:
            commit_hash = "unknown"
            logger.warning(
                "Could not determine commit hash, using 'unknown'",
                extra={"run_id": run_id},
            )

        timestamp = datetime.now(timezone.utc).isoformat()

        logger.info(
            "Scanning repo=%s branch=%s commit=%s",
            repo_name,
            branch,
            commit_hash[:8],
            extra={"run_id": run_id, "repo": repo_name},
        )

        # Apply run_config overrides if provided
        active_gates = self._gate_classes
        if run_config and "only_gates" in run_config:
            only = run_config["only_gates"]
            active_gates = {
                name: cls
                for name, cls in self._gate_classes.items()
                if name in only
            }

        runner = GateRunner(config=self.config, gate_classes=active_gates)
        gate_results = runner.run_all(repo_path_str)

        # Build a partial RunResult for scoring (score uses all_findings
        # and gate_results, so we need those before the final result).
        risk_score: Optional[RiskScore] = None
        try:
            _partial_result = RunResult(
                run_id=run_id,
                repo=repo_name,
                branch=branch,
                commit_hash=commit_hash,
                timestamp=timestamp,
                overall_score=0.0,
                status="pass",
                gate_results=gate_results,
                risk_score=None,
                duration_ms=0,
            )
            risk_score = self.risk_scorer.calculate_score(_partial_result)
            logger.info(
                "Risk score: %.2f (%s) - %s",
                risk_score.overall,
                risk_score.risk_level,
                risk_score.recommendation[:80],
                extra={"run_id": run_id, "repo": repo_name},
            )
        except ScoringError as exc:
            logger.error(
                "Risk scoring failed: %s",
                str(exc),
                extra={"run_id": run_id, "repo": repo_name},
            )

        overall_score = self._compute_overall_score(gate_results, risk_score)
        status = self._determine_status(gate_results, risk_score)

        duration_ms = int((time.monotonic() - start_time) * 1000)

        run_result = RunResult(
            run_id=run_id,
            repo=repo_name,
            branch=branch,
            commit_hash=commit_hash,
            timestamp=timestamp,
            overall_score=overall_score,
            status=status,
            gate_results=gate_results,
            risk_score=risk_score,
            duration_ms=duration_ms,
        )


        try:
            self.db_manager.save_run(run_result)
            logger.info(
                "Pipeline run saved to database",
                extra={"run_id": run_id, "repo": repo_name},
            )
        except Exception as exc:
            logger.error(
                "Failed to save run to database: %s",
                str(exc),
                extra={"run_id": run_id, "repo": repo_name},
            )

        self._trigger_report_generation(run_result)

        logger.info(
            "Pipeline run %s complete: status=%s score=%.1f duration=%dms",
            run_id,
            status,
            overall_score,
            duration_ms,
            extra={"run_id": run_id, "repo": repo_name},
        )

        return run_result

    def _compute_overall_score(
        self,
        gate_results: List[GateResult],
        risk_score: Optional[RiskScore],
    ) -> float:
        if risk_score is not None:
            # Invert: higher risk = lower security score
            return round(100.0 - risk_score.overall, 2)

        # Fallback: simple calculation based on gate pass/fail
        if not gate_results:
            return 100.0

        passed = sum(1 for gr in gate_results if gr.status == "pass")
        total = len(gate_results)
        base_score = (passed / total) * 100.0

        # Reduce for findings
        total_findings = sum(gr.findings_count for gr in gate_results)
        deduction = min(50.0, total_findings * 2.0)

        return round(max(0.0, base_score - deduction), 2)

    def _determine_status(
        self,
        gate_results: List[GateResult],
        risk_score: Optional[RiskScore],
    ) -> str:
        # If any gate errored, the overall status is error
        if any(gr.status == "error" for gr in gate_results):
            # But if there are also failures, report fail
            if any(gr.status == "fail" for gr in gate_results):
                return "fail"
            return "error"

        # If any gate explicitly failed, the pipeline fails
        if any(gr.status == "fail" for gr in gate_results):
            return "fail"

        # Check critical/high findings against config
        if self.config.fail_on_critical:
            for gr in gate_results:
                if gr.critical_count > 0:
                    return "fail"

        if self.config.fail_on_high:
            for gr in gate_results:
                if gr.high_count > 0:
                    return "fail"

        return "pass"

    def _trigger_report_generation(self, run_result: RunResult) -> None:
        try:
            from reporter import generate_report  # type: ignore

            output_dir = self.config.output_dir
            generate_report(run_result, output_dir=output_dir)
            logger.info(
                "Report generated for run %s",
                run_result.run_id,
                extra={"run_id": run_result.run_id},
            )
        except ImportError:
            logger.debug(
                "Reporter module not available; skipping report generation",
            )
        except Exception as exc:
            logger.warning(
                "Report generation failed: %s",
                str(exc),
                extra={"run_id": run_result.run_id},
            )
