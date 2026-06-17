"""SecureBuild CI/CD Security Gate - Report Renderer"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from engine.exceptions import ReportGenerationError
from engine.logger import get_logger
from engine.models import Finding, GateResult, RiskScore, RunResult

logger = get_logger("reporter")


SEVERITY_COLORS: Dict[str, str] = {
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#CA8A04",
    "low": "#16A34A",
    "info": "#2563EB",
}

# Grade labels based on overall score (0-100 scale, higher is better)
GRADE_THRESHOLDS: List[Dict[str, Any]] = [
    {"min": 90, "label": "Pass", "color": "#16A34A"},
    {"min": 70, "label": "Low Risk", "color": "#16A34A"},
    {"min": 50, "label": "Medium", "color": "#CA8A04"},
    {"min": 30, "label": "High", "color": "#EA580C"},
    {"min": 0, "label": "Critical", "color": "#DC2626"},
]


def cvss_color(score: float) -> str:
    if score >= 9.0:
        return "#DC2626"
    elif score >= 7.0:
        return "#EA580C"
    elif score >= 4.0:
        return "#CA8A04"
    elif score >= 0.1:
        return "#16A34A"
    return "#2563EB"


def severity_badge(severity: str) -> str:
    severity_lower = severity.lower()
    color = SEVERITY_COLORS.get(severity_lower, "#6B7280")
    bg_color = color + "1A"  # 10% opacity hex
    label = severity_lower.title()

    return (
        f'<span style="'
        f'display:inline-block; padding:2px 10px; border-radius:9999px; '
        f'font-size:12px; font-weight:600; '
        f'color:{color}; background:{bg_color}; '
        f'border:1px solid {color}40;'
        f'">{label}</span>'
    )


def format_cvss(score: float) -> str:
    return f"{float(score):.1f}"


def truncate_path(path: str, max_len: int = 60) -> str:
    if len(path) <= max_len:
        return path

    # Preserve the filename (after last separator)
    sep = "/" if "/" in path else "\\"
    parts = path.rsplit(sep, 1)
    filename = parts[-1] if len(parts) > 1 else path

    if len(filename) >= max_len - 3:
        return "..." + filename[: max_len - 3]

    # Show as much of the beginning and end as possible
    available = max_len - 3  # 3 for "..."
    head_len = available - len(filename) - 1  # 1 for separator
    if head_len < 3:
        return "..." + filename

    head = path[:head_len]
    return f"{head}...{sep}{filename}"


def format_duration(ms: int) -> str:
    if ms < 0:
        ms = 0

    total_seconds = ms // 1000
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60

    if hours > 0:
        return f"{hours}h {minutes}m"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    elif seconds > 0:
        return f"{seconds}s"
    else:
        ms_remaining = ms % 1000
        if ms_remaining > 0:
            return f"{ms_remaining}ms"
        return "0ms"


def get_grade(score: float) -> Dict[str, str]:
    for threshold in GRADE_THRESHOLDS:
        if score >= threshold["min"]:
            return {"label": threshold["label"], "color": threshold["color"]}
    return {"label": "Critical", "color": "#DC2626"}


class ReportRenderer:
    """Renders professional HTML security reports from RunResult data."""

    def __init__(self, template_dir: Optional[str] = None) -> None:
        if template_dir is None:
            template_dir = str(Path(__file__).resolve().parent / "templates")

        self.template_dir = template_dir

        # Ensure the template directory exists
        os.makedirs(self.template_dir, exist_ok=True)

        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

        # Register custom Jinja2 filters
        self.env.filters["cvss_color"] = cvss_color
        self.env.filters["severity_badge"] = severity_badge
        self.env.filters["format_cvss"] = format_cvss
        self.env.filters["truncate_path"] = truncate_path
        self.env.filters["format_duration"] = format_duration

        # Register grade helper as a global function in templates
        self.env.globals["get_grade"] = get_grade
        self.env.globals["severity_color"] = lambda s: SEVERITY_COLORS.get(
            s.lower(), "#6B7280"
        )

        logger.info("ReportRenderer initialized with template_dir=%s", template_dir)

    def render_report(
        self,
        run_result: RunResult,
        output_path: Optional[str] = None,
    ) -> str:
        try:
            template = self.env.get_template("report.html")

            # Build context with all necessary data
            context = self._build_context(run_result)

            # Generate executive summary
            context["executive_summary"] = self.render_executive_summary(run_result)

            # Render the template
            html_content = template.render(**context)

            # Write to file if output_path is provided
            if output_path:
                output_dir = os.path.dirname(os.path.abspath(output_path))
                os.makedirs(output_dir, exist_ok=True)
                with open(output_path, "w", encoding="utf-8") as fh:
                    fh.write(html_content)
                logger.info(
                    "Report written to %s (%d bytes)",
                    output_path,
                    len(html_content),
                )

            return html_content

        except ReportGenerationError:
            raise
        except Exception as exc:
            raise ReportGenerationError(
                report_type="html",
                run_id=run_result.run_id,
                message=f"Failed to render HTML report: {exc}",
                original_error=exc,
            )

    def render_executive_summary(self, run_result: RunResult) -> str:
        all_findings = run_result.all_findings
        total = len(all_findings)

        # If no findings, return a clean-pass summary
        if total == 0:
            return (
                f"Security scan of {run_result.repo or 'the repository'} "
                f"completed with no findings. The overall security score is "
                f"{run_result.overall_score:.1f}/100, indicating a clean bill "
                f"of health. All five security gates passed successfully with "
                f"no issues detected. No remediation action is required."
            )

        # Count by severity
        critical_count = sum(1 for f in all_findings if f.severity == "critical")
        high_count = sum(1 for f in all_findings if f.severity == "high")
        medium_count = sum(1 for f in all_findings if f.severity == "medium")
        low_count = sum(1 for f in all_findings if f.severity == "low")
        info_count = sum(1 for f in all_findings if f.severity == "info")

        # Risk score info
        risk_score = run_result.risk_score
        if risk_score:
            risk_value = risk_score.overall
            risk_level = risk_score.risk_level.title()
            trend = risk_score.trend.replace("_", " ").title()
        else:
            risk_value = 100.0 - run_result.overall_score
            risk_level = "Unknown"
            trend = "New"

        # Grade info
        grade = get_grade(run_result.overall_score)

        # Build summary sentences
        repo_label = run_result.repo or "the repository"
        branch_label = run_result.branch or "main"

        # Sentence 1: Overview
        sentence_1 = (
            f"A security scan of {repo_label} (branch: {branch_label}) "
            f"identified {total} finding{'s' if total != 1 else ''}, "
            f"resulting in an overall security score of "
            f"{run_result.overall_score:.1f}/100 ({grade['label']})."
        )

        # Sentence 2: Severity breakdown
        severity_parts: List[str] = []
        if critical_count > 0:
            severity_parts.append(f"{critical_count} critical")
        if high_count > 0:
            severity_parts.append(f"{high_count} high")
        if medium_count > 0:
            severity_parts.append(f"{medium_count} medium")
        if low_count > 0:
            severity_parts.append(f"{low_count} low")
        if info_count > 0:
            severity_parts.append(f"{info_count} informational")

        severity_text = ", ".join(severity_parts)
        sentence_2 = f"Findings by severity: {severity_text}."

        # Sentence 3: Risk assessment
        sentence_3 = (
            f"The risk assessment is {risk_level} "
            f"(risk score: {risk_value:.1f}/100) with a {trend.lower()} trend."
        )

        # Sentence 4: Top issues
        top_findings = sorted(all_findings, key=lambda f: f.cvss_score, reverse=True)[
            :3
        ]
        if top_findings:
            top_descriptions = []
            for f in top_findings:
                desc = f.message[:80].rstrip()
                if len(f.message) > 80:
                    desc += "..."
                top_descriptions.append(desc)
            top_text = "; ".join(top_descriptions)
            sentence_4 = f"Top issues include: {top_text}."
        else:
            sentence_4 = ""

        # Sentence 5: Estimated fix time
        from scoring.remediation import RemediationEngine

        remediation_engine = RemediationEngine()
        total_fix_minutes = remediation_engine.calculate_total_fix_time(all_findings)
        quick_wins = remediation_engine.identify_quick_wins(all_findings)

        if total_fix_minutes >= 60:
            fix_hours = total_fix_minutes // 60
            fix_mins = total_fix_minutes % 60
            fix_time_str = f"{fix_hours}h {fix_mins}m" if fix_mins else f"{fix_hours}h"
        else:
            fix_time_str = f"{total_fix_minutes}m"

        sentence_5 = (
            f"Estimated total remediation time is {fix_time_str}"
            f"{', with ' + str(len(quick_wins)) + ' quick wins available' if quick_wins else ''}."
        )

        # Combine non-empty sentences
        sentences = [s for s in [sentence_1, sentence_2, sentence_3, sentence_4, sentence_5] if s]
        return " ".join(sentences)


    def _build_context(self, run_result: RunResult) -> Dict[str, Any]:
        all_findings = run_result.all_findings

        # Severity counts
        severity_counts = {
            "critical": sum(1 for f in all_findings if f.severity == "critical"),
            "high": sum(1 for f in all_findings if f.severity == "high"),
            "medium": sum(1 for f in all_findings if f.severity == "medium"),
            "low": sum(1 for f in all_findings if f.severity == "low"),
            "info": sum(1 for f in all_findings if f.severity == "info"),
        }

        # Grade info
        grade = get_grade(run_result.overall_score)

        # Risk score info
        risk_score = run_result.risk_score
        risk_overall = risk_score.overall if risk_score else 0.0
        risk_level = risk_score.risk_level if risk_score else "unknown"
        risk_trend = risk_score.trend if risk_score else "new"
        risk_percentile = risk_score.percentile if risk_score else 0.0
        risk_recommendation = risk_score.recommendation if risk_score else ""

        # Gate score breakdown for bar chart
        gate_scores = {}
        if risk_score and risk_score.by_gate:
            gate_scores = risk_score.by_gate
        else:
            for gr in run_result.gate_results:
                gate_scores[gr.gate_name] = sum(f.cvss_score for f in gr.findings)

        # Remediation data
        from scoring.remediation import RemediationEngine

        remediation_engine = RemediationEngine()
        quick_wins = remediation_engine.identify_quick_wins(all_findings)
        priority_findings = remediation_engine.priority_sort(all_findings)
        total_fix_minutes = remediation_engine.calculate_total_fix_time(all_findings)

        # Generate remediation suggestions for each finding
        remediation_map: Dict[str, Dict[str, Any]] = {}
        for finding in all_findings:
            try:
                suggestion = remediation_engine.generate_remediation_for_finding(finding)
                remediation_map[finding.id] = {
                    "title": suggestion.title,
                    "explanation": suggestion.explanation,
                    "fix_code_before": suggestion.fix_code_before,
                    "fix_code_after": suggestion.fix_code_after,
                    "effort": suggestion.effort,
                    "quick_win": suggestion.quick_win,
                    "estimated_minutes": suggestion.estimated_minutes,
                    "references": suggestion.references,
                }
            except Exception:
                remediation_map[finding.id] = {
                    "title": f"Fix {finding.severity.title()} finding",
                    "explanation": finding.fix_suggestion or finding.message,
                    "fix_code_before": "",
                    "fix_code_after": "",
                    "effort": "medium",
                    "quick_win": False,
                    "estimated_minutes": 30,
                    "references": [],
                }

        # Quick win details
        quick_win_details: List[Dict[str, Any]] = []
        for f in quick_wins:
            fix_time = remediation_engine.calculate_estimated_fix_time(f)
            quick_win_details.append({
                "finding": f,
                "fix_time": fix_time,
                "remediation": remediation_map.get(f.id, {}),
            })

        # Priority fix list
        priority_fix_list: List[Dict[str, Any]] = []
        for f in priority_findings[:20]:  # Top 20 priority items
            fix_time = remediation_engine.calculate_estimated_fix_time(f)
            priority_fix_list.append({
                "finding": f,
                "fix_time": fix_time,
                "remediation": remediation_map.get(f.id, {}),
            })

        # Scan metadata
        scan_timestamp = run_result.timestamp or datetime.utcnow().isoformat()
        total_duration = run_result.duration_ms
        total_files_scanned = sum(gr.files_scanned for gr in run_result.gate_results)
        total_files_skipped = sum(gr.files_skipped for gr in run_result.gate_results)

        # Chart data for JavaScript (Chart.js)
        chart_severity_labels = ["Critical", "High", "Medium", "Low", "Info"]
        chart_severity_data = [
            severity_counts["critical"],
            severity_counts["high"],
            severity_counts["medium"],
            severity_counts["low"],
            severity_counts["info"],
        ]
        chart_severity_colors = [
            SEVERITY_COLORS["critical"],
            SEVERITY_COLORS["high"],
            SEVERITY_COLORS["medium"],
            SEVERITY_COLORS["low"],
            SEVERITY_COLORS["info"],
        ]

        chart_gate_labels = [gr.gate_name.title() for gr in run_result.gate_results]
        chart_gate_data = [
            len(gr.findings) for gr in run_result.gate_results
        ]
        chart_gate_colors = [
            "#1E40AF", "#2563EB", "#3B82F6", "#60A5FA", "#93C5FD"
        ]

        return {
            # Run metadata
            "run_result": run_result,
            "run_id": run_result.run_id,
            "repo": run_result.repo,
            "branch": run_result.branch,
            "commit_hash": run_result.commit_hash,
            "scan_timestamp": scan_timestamp,
            "overall_score": run_result.overall_score,
            "status": run_result.status,
            "duration_ms": run_result.duration_ms,
            # Grade
            "grade": grade,
            # Risk score
            "risk_score": risk_score,
            "risk_overall": risk_overall,
            "risk_level": risk_level,
            "risk_trend": risk_trend,
            "risk_percentile": risk_percentile,
            "risk_recommendation": risk_recommendation,
            # Findings summary
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "all_findings": all_findings,
            # Gate results
            "gate_results": run_result.gate_results,
            "gate_scores": gate_scores,
            "failed_gates": run_result.failed_gates,
            # Remediation
            "quick_wins": quick_wins,
            "quick_win_details": quick_win_details,
            "priority_fix_list": priority_fix_list,
            "total_fix_minutes": total_fix_minutes,
            "remediation_map": remediation_map,
            # Scan metadata
            "total_duration": total_duration,
            "total_files_scanned": total_files_scanned,
            "total_files_skipped": total_files_skipped,
            # Chart data
            "chart_severity_labels": chart_severity_labels,
            "chart_severity_data": chart_severity_data,
            "chart_severity_colors": chart_severity_colors,
            "chart_gate_labels": chart_gate_labels,
            "chart_gate_data": chart_gate_data,
            "chart_gate_colors": chart_gate_colors,
            # Colors
            "severity_colors": SEVERITY_COLORS,
            "primary_color": "#1E40AF",
            "bg_color": "#F8FAFC",
        }
