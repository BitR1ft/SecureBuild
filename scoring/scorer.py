"""SecureBuild CI/CD Security Gate - Risk Scoring Engine"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from engine.db import DatabaseManager
from engine.exceptions import ScoringError
from engine.logger import get_logger
from engine.models import Finding, GateResult, RiskScore, RunResult

logger = get_logger("scorer")


class RiskScorer:
    """Computes weighted risk scores for SecureBuild pipeline runs."""

    # Higher weight = findings from this gate contribute more to risk.
    GATE_WEIGHTS: Dict[str, float] = {
        "secrets": 1.5,
        "sast": 1.3,
        "cve": 1.2,
        "dependencies": 1.2,
        "license": 0.8,
        "iac": 1.1,
        "compliance": 0.9,
    }

    # Default gate weight for unrecognised gate names
    DEFAULT_GATE_WEIGHT: float = 1.0

    SEVERITY_MULTIPLIERS: Dict[str, float] = {
        "critical": 2.0,
        "high": 1.5,
        "medium": 1.0,
        "low": 0.5,
        "info": 0.2,
    }

    # Default severity multiplier for unrecognised severity levels
    DEFAULT_SEVERITY_MULTIPLIER: float = 0.2

    # The algorithm computes on a 0-10 scale, then multiplies by
    # SCALE_FACTOR to produce the 0-100 value stored in RiskScore.overall.
    SCALE_FACTOR: float = 10.0

    def __init__(self, db_manager: Optional[DatabaseManager] = None) -> None:
        self.db_manager = db_manager


    def calculate_score(self, run_result: RunResult) -> RiskScore:
        try:
            all_findings = run_result.all_findings
            gate_results = run_result.gate_results

            total_weighted = 0.0
            total_weight = 0.0
            by_gate: Dict[str, float] = {}
            by_severity: Dict[str, int] = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }

            for finding in all_findings:
                gate_w = self.GATE_WEIGHTS.get(
                    finding.gate, self.DEFAULT_GATE_WEIGHT
                )
                sev_m = self.SEVERITY_MULTIPLIERS.get(
                    finding.severity, self.DEFAULT_SEVERITY_MULTIPLIER
                )
                weight = gate_w * sev_m
                contribution = finding.cvss_score * weight

                total_weighted += contribution
                total_weight += weight

                by_severity[finding.severity] = (
                    by_severity.get(finding.severity, 0) + 1
                )

            for gr in gate_results:
                gate_w = self.GATE_WEIGHTS.get(
                    gr.gate_name, self.DEFAULT_GATE_WEIGHT
                )
                gate_total = 0.0
                for finding in gr.findings:
                    sev_m = self.SEVERITY_MULTIPLIERS.get(
                        finding.severity, self.DEFAULT_SEVERITY_MULTIPLIER
                    )
                    gate_total += finding.cvss_score * gate_w * sev_m
                by_gate[gr.gate_name] = round(gate_total, 4)

            if total_weight > 0 and total_weighted > 0:
                raw_score = total_weighted / total_weight
            else:
                raw_score = 0.0

            # Clamp to 0-10
            normalised_score = max(0.0, min(10.0, raw_score))

            # Scale to 0-100 for RiskScore.overall
            overall = round(normalised_score * self.SCALE_FACTOR, 2)
            overall = max(0.0, min(100.0, overall))

            recommendation = self.generate_score_explanation(
                run_result,
                RiskScore(
                    overall=overall,
                    by_gate=by_gate,
                    by_severity=by_severity,
                ),
            )

            trend = "new"
            if self.db_manager:
                try:
                    historical = self._get_historical_scores(run_result.repo)
                    trend = self.get_trend(normalised_score, historical)
                except Exception:
                    trend = "new"

            percentile = 0.0
            if self.db_manager:
                try:
                    percentile = self.calculate_percentile(
                        normalised_score, self.db_manager
                    )
                except Exception:
                    percentile = 0.0

            risk_score = RiskScore(
                overall=overall,
                by_gate=by_gate,
                by_severity=by_severity,
                recommendation=recommendation,
                trend=trend,
                percentile=percentile,
            )

            logger.info(
                "Risk score computed: %.2f (0-100 scale) | "
                "critical=%d high=%d medium=%d low=%d info=%d",
                overall,
                by_severity.get("critical", 0),
                by_severity.get("high", 0),
                by_severity.get("medium", 0),
                by_severity.get("low", 0),
                by_severity.get("info", 0),
            )

            return risk_score

        except Exception as exc:
            if isinstance(exc, ScoringError):
                raise
            raise ScoringError(
                metric="overall",
                message=str(exc),
                original_error=exc,
            )

    def get_severity_breakdown(self, findings: List[Finding]) -> Dict[str, int]:
        breakdown: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for f in findings:
            if f.severity in breakdown:
                breakdown[f.severity] += 1
            else:
                breakdown[f.severity] = breakdown.get(f.severity, 0) + 1
        return breakdown

    def get_gate_breakdown(self, gate_results: List[GateResult]) -> Dict[str, float]:
        breakdown: Dict[str, float] = {}
        for gr in gate_results:
            gate_w = self.GATE_WEIGHTS.get(
                gr.gate_name, self.DEFAULT_GATE_WEIGHT
            )
            gate_total = 0.0
            for finding in gr.findings:
                sev_m = self.SEVERITY_MULTIPLIERS.get(
                    finding.severity, self.DEFAULT_SEVERITY_MULTIPLIER
                )
                gate_total += finding.cvss_score * gate_w * sev_m
            breakdown[gr.gate_name] = round(gate_total, 4)
        return breakdown

    def is_blocking(
        self,
        score: float,
        threshold_config: Optional[Dict[str, Any]] = None,
    ) -> bool:
        config = threshold_config or {}

        # If warn_only is enabled, never block
        if config.get("warn_only", False):
            logger.warning(
                "Block condition met but warn_only mode is active"
            )
            return False

        critical_count = config.get("critical_count", 0)
        high_count = config.get("high_count", 0)
        score_threshold = config.get("score_threshold", 7.0)

        # Determine the score scale
        scale = config.get("score_scale", None)
        if scale is None:
            # Auto-detect: if score > 20, assume 0-100 scale
            scale = "0-100" if score > 20 else "0-10"

        if scale == "0-100":
            normalised = score / self.SCALE_FACTOR
        else:
            normalised = score

        # Rule 1: Any critical finding blocks
        if critical_count > 0:
            logger.info(
                "Blocking: %d critical findings found", critical_count
            )
            return True

        # Rule 2: 5+ high findings block
        if high_count >= 5:
            logger.info(
                "Blocking: %d high findings (threshold: 5)", high_count
            )
            return True

        # Rule 3: Overall score exceeds threshold
        if normalised > score_threshold:
            logger.info(
                "Blocking: score %.2f exceeds threshold %.2f",
                normalised,
                score_threshold,
            )
            return True

        return False

    def get_trend(
        self,
        current_score: float,
        historical_scores: List[float],
    ) -> str:
        if not historical_scores:
            return "new"

        # Take the last 5 runs
        recent = historical_scores[-5:]
        if not recent:
            return "new"

        avg_historical = sum(recent) / len(recent)
        delta = current_score - avg_historical

        if delta > 2.0:
            return "critical_regression"
        elif delta > 0.5:
            return "degrading"
        elif delta < -0.5:
            return "improving"
        else:
            return "stable"

    def calculate_cvss_base_score(
        self,
        av: str,
        ac: str,
        pr: str,
        ui: str,
        scope: str,
        c: str,
        i: str,
        a: str,
    ) -> float:
        av_values = {"network": 0.85, "n": 0.85, "adjacent": 0.62, "a": 0.62,
                     "local": 0.55, "l": 0.55, "physical": 0.20, "p": 0.20}
        ac_values = {"low": 0.77, "l": 0.77, "high": 0.44, "h": 0.44}
        ui_values = {"none": 0.85, "n": 0.85, "required": 0.62, "r": 0.62}

        # PR values depend on Scope
        pr_values_unchanged = {"none": 0.85, "n": 0.85, "low": 0.68,
                               "l": 0.68, "high": 0.50, "h": 0.50}
        pr_values_changed = {"none": 0.85, "n": 0.85, "low": 0.62,
                             "l": 0.62, "high": 0.27, "h": 0.27}

        cia_values = {"high": 0.56, "h": 0.56, "low": 0.22, "l": 0.22,
                      "none": 0.0, "n": 0.0}

        scope_changed = scope.lower() in ("changed", "c")

        av_val = av_values.get(av.lower(), 0.85)
        ac_val = ac_values.get(ac.lower(), 0.77)
        ui_val = ui_values.get(ui.lower(), 0.85)

        if scope_changed:
            pr_val = pr_values_changed.get(pr.lower(), 0.85)
        else:
            pr_val = pr_values_unchanged.get(pr.lower(), 0.85)

        c_val = cia_values.get(c.lower(), 0.0)
        i_val = cia_values.get(i.lower(), 0.0)
        a_val = cia_values.get(a.lower(), 0.0)

        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

        iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

        if iss <= 0:
            return 0.0

        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        if impact <= 0:
            return 0.0

        if scope_changed:
            base_score = min(10.0, 1.08 * (impact + exploitability))
        else:
            base_score = min(10.0, impact + exploitability)

        # Roundup to one decimal place (per CVSS v3.1 spec):
        # "returns the smallest number, specified to one decimal place,
        #  that is equal to or higher than its input"
        return math.ceil(base_score * 10) / 10.0

    def generate_score_explanation(
        self,
        run_result: RunResult,
        score: RiskScore,
    ) -> str:
        all_findings = run_result.all_findings
        if not all_findings:
            return (
                "Score 0.0 (Minimal) — no security findings detected. "
                "The repository passes all security gates."
            )

        # Score is on 0-100 scale in RiskScore; convert to 0-10 for display
        score_10 = score.overall / self.SCALE_FACTOR
        level = self._score_to_level(score_10)

        sorted_findings = sorted(
            all_findings, key=lambda f: f.cvss_score, reverse=True
        )

        # Take top 3-5 findings that contribute the most
        top_n = min(5, len(sorted_findings))
        top_findings = sorted_findings[:top_n]

        # Group the top findings by type for concise description
        driver_parts: List[str] = []
        for f in top_findings:
            gate_label = f.gate.title() if f.gate else "Unknown"
            part = f"{f.message[:60]} ({gate_label} Gate, CVSS {f.cvss_score:.1f})"
            driver_parts.append(part)

        if len(all_findings) > top_n:
            remaining = len(all_findings) - top_n
            driver_parts.append(f"{remaining} additional findings")

        drivers_text = ", ".join(driver_parts)

        top_ids = [f.id for f in top_findings[:3]]
        projected = self.simulate_fix(run_result, top_ids)
        projected_level = self._score_to_level(projected / self.SCALE_FACTOR)

        explanation = (
            f"Score {score_10:.1f} ({level}) — driven primarily by "
            f"{drivers_text}. "
            f"Resolving the top {len(top_ids)} findings would reduce "
            f"score to approximately {projected / self.SCALE_FACTOR:.1f} "
            f"({projected_level})."
        )

        return explanation

    def simulate_fix(
        self,
        run_result: RunResult,
        finding_ids: List[str],
    ) -> float:
        ids_set = set(finding_ids)
        all_findings = run_result.all_findings

        # Filter out the "fixed" findings
        remaining = [f for f in all_findings if f.id not in ids_set]

        if not remaining:
            return 0.0

        # Recalculate with remaining findings
        total_weighted = 0.0
        total_weight = 0.0

        for finding in remaining:
            gate_w = self.GATE_WEIGHTS.get(
                finding.gate, self.DEFAULT_GATE_WEIGHT
            )
            sev_m = self.SEVERITY_MULTIPLIERS.get(
                finding.severity, self.DEFAULT_SEVERITY_MULTIPLIER
            )
            weight = gate_w * sev_m
            total_weighted += finding.cvss_score * weight
            total_weight += weight

        if total_weight > 0 and total_weighted > 0:
            raw_score = total_weighted / total_weight
        else:
            raw_score = 0.0

        normalised = max(0.0, min(10.0, raw_score))
        return round(normalised * self.SCALE_FACTOR, 2)

    def calculate_percentile(
        self,
        score: float,
        db_manager: DatabaseManager,
    ) -> float:
        try:
            recent_runs = db_manager.get_recent_runs(limit=1000)
            if not recent_runs:
                return 50.0

            # Convert DB scores (0-100) to 0-10 scale for comparison
            historical_scores: List[float] = []
            for run_data in recent_runs:
                db_score = run_data.get("overall_score", 0.0)
                # overall_score in DB is 0-100 (higher is better),
                # but risk score is inverted (higher = riskier)
                # We compare against risk_score.overall from metadata
                metadata = run_data.get("metadata", {})
                if isinstance(metadata, str):
                    import json
                    try:
                        metadata = json.loads(metadata)
                    except (json.JSONDecodeError, TypeError):
                        metadata = {}

                risk_overall = metadata.get("risk_score", {}).get("overall", None)
                if risk_overall is not None:
                    historical_scores.append(float(risk_overall) / self.SCALE_FACTOR)
                else:
                    # Fallback: invert the overall_score (100 - score = risk)
                    risk_approx = (100.0 - db_score) / self.SCALE_FACTOR
                    historical_scores.append(max(0.0, min(10.0, risk_approx)))

            if not historical_scores:
                return 50.0

            # Count how many historical scores are below the current one
            below = sum(1 for s in historical_scores if s < score)
            equal = sum(1 for s in historical_scores if s == score)
            total = len(historical_scores)

            # Use the standard percentile formula
            percentile = ((below + 0.5 * equal) / total) * 100.0
            return round(max(0.0, min(100.0, percentile)), 1)

        except Exception as exc:
            logger.warning(
                "Percentile calculation failed: %s", str(exc)
            )
            return 50.0

    def calculate_per_file_risk(self, findings: List[Finding]) -> Dict[str, float]:
        per_file: Dict[str, float] = {}
        for f in findings:
            if f.file:
                per_file[f.file] = per_file.get(f.file, 0.0) + f.cvss_score
        # Round for readability
        return {fp: round(score, 2) for fp, score in per_file.items()}


    def _score_to_level(self, score_10: float) -> str:
        if score_10 >= 9.0:
            return "Critical"
        elif score_10 >= 7.0:
            return "High"
        elif score_10 >= 4.0:
            return "Medium"
        elif score_10 >= 1.0:
            return "Low"
        else:
            return "Minimal"

    def _get_historical_scores(self, repo: str) -> List[float]:
        if not self.db_manager:
            return []

        try:
            runs = self.db_manager.get_runs_by_repo(repo, limit=20)
            scores: List[float] = []
            for run_data in runs:
                metadata = run_data.get("metadata", {})
                if isinstance(metadata, str):
                    import json
                    try:
                        metadata = json.loads(metadata)
                    except (json.JSONDecodeError, TypeError):
                        metadata = {}

                risk_overall = metadata.get("risk_score", {}).get("overall", None)
                if risk_overall is not None:
                    scores.append(float(risk_overall) / self.SCALE_FACTOR)
                else:
                    db_score = run_data.get("overall_score", 0.0)
                    risk_approx = (100.0 - db_score) / self.SCALE_FACTOR
                    scores.append(max(0.0, min(10.0, risk_approx)))

            return scores

        except Exception:
            return []
