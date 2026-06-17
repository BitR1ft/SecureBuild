#!/usr/bin/env python3
"""SecureBuild CLI - CI/CD Security Gate Tool"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_PROJECT_ROOT = str(Path(__file__).resolve().parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


# Helpers shared across commands

def _load_config(config_path: Optional[str] = None) -> Any:
    from engine.config import SecureBuildConfig

    if config_path:
        return SecureBuildConfig.from_file(config_path)

    # Search for config in the current directory and project root
    for candidate in ("securebuild.yaml", "securebuild.yml"):
        if Path(candidate).exists():
            return SecureBuildConfig.from_file(candidate)

    return SecureBuildConfig()


def _get_db_manager(config: Any = None) -> Any:
    from engine.db import DatabaseManager

    if config is None:
        config = _load_config()

    db_path = os.environ.get(
        "DB_PATH",
        getattr(config, "database_path", "securebuild.db"),
    )
    _ensure_dir(str(Path(db_path).parent))
    return DatabaseManager(db_path=db_path)


def _ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


# ANSI colour helpers (no external dependency)

class _C:
    """Terminal colour constants — empty strings when not a TTY."""
    RST = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GRN = "\033[32m"
    YEL = "\033[33m"
    BLU = "\033[34m"
    MAG = "\033[35m"
    CYN = "\033[36m"

    @classmethod
    def disable(cls) -> None:
        cls.RST = cls.BOLD = cls.RED = cls.GRN = cls.YEL = ""
        cls.BLU = cls.MAG = cls.CYN = ""


# Disable colours when stdout is not a TTY
if not sys.stdout.isatty():
    _C.disable()


# Status / severity icons

_STATUS_ICON = {"pass": f"{_C.GRN}PASS{_C.RST}", "fail": f"{_C.RED}FAIL{_C.RST}", "error": f"{_C.YEL}ERROR{_C.RST}"}
_SEV_ICON = {
    "critical": f"{_C.RED}{_C.BOLD}CRITICAL{_C.RST}",
    "high": f"{_C.RED}HIGH{_C.RST}",
    "medium": f"{_C.YEL}MEDIUM{_C.RST}",
    "low": f"{_C.CYN}LOW{_C.RST}",
    "info": f"{_C.BLU}INFO{_C.RST}",
}


# Command: scan

def handle_scan(args: argparse.Namespace) -> None:
    from engine.config import SecureBuildConfig
    from engine.db import DatabaseManager
    from engine.exceptions import InvalidRepoError

    repo_path = str(Path(args.repo_path).resolve())
    if not Path(repo_path).exists():
        print(f"{_C.RED}Error: Repository path does not exist: {repo_path}{_C.RST}", file=sys.stderr)
        sys.exit(1)

    config = _load_config(args.config)

    # Apply CLI overrides
    if args.threshold is not None:
        # threshold on CLI overrides score threshold
        os.environ["SECUREBUILD_FAIL_ON_CRITICAL"] = "true"

    if args.verbose:
        from engine.logger import set_log_level
        set_log_level("DEBUG")

    if args.gates:
        # Gate CLI names match internal gate names directly
        only_gates = list(args.gates)
    else:
        only_gates = None

    output_dir = args.output_dir
    _ensure_dir(output_dir)

    db_path = os.environ.get("DB_PATH", getattr(config, "database_path", "data/securebuild.db"))
    _ensure_dir(str(Path(db_path).parent))
    db_manager = DatabaseManager(db_path=db_path)

    try:
        from engine.orchestrator import Orchestrator

        orchestrator = Orchestrator(config=config, db_manager=db_manager)

        run_config = {}
        if only_gates:
            run_config["only_gates"] = only_gates

        print(f"\n{_C.BOLD}SecureBuild Security Scan{_C.RST}")
        print(f"{'=' * 50}")
        print(f"  Repository : {repo_path}")
        print(f"  Output     : {output_dir}")
        print(f"  Format     : {args.format}")
        if args.dry_run:
            print(f"  Mode       : {_C.YEL}DRY RUN (non-blocking){_C.RST}")
        print()

        run_result = orchestrator.run(repo_path, run_config=run_config or None)

    except InvalidRepoError as exc:
        print(f"{_C.RED}Error: {exc}{_C.RST}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"{_C.RED}Error running scan: {exc}{_C.RST}", file=sys.stderr)
        sys.exit(1)

    _print_scan_summary(run_result)

    _generate_reports(run_result, output_dir, args.format)

    _generate_summary_md(run_result, output_dir)

    if args.dry_run:
        print(f"\n{_C.YEL}Dry-run mode: pipeline would be {'BLOCKED' if run_result.status == 'fail' else 'allowed'}{_C.RST}")
        sys.exit(0)

    if run_result.status == "fail":
        print(f"\n{_C.RED}{_C.BOLD}Pipeline BLOCKED: security gate failures detected{_C.RST}")
        sys.exit(1)
    elif run_result.status == "error":
        print(f"\n{_C.YEL}Pipeline completed with errors{_C.RST}")
        sys.exit(2)
    else:
        print(f"\n{_C.GRN}{_C.BOLD}Pipeline PASSED: all security gates clear{_C.RST}")
        sys.exit(0)


def _print_scan_summary(run_result: Any) -> None:
    print(f"\n{_C.BOLD}Scan Results Summary{_C.RST}")
    print(f"{'─' * 70}")
    print(f"  Run ID       : {run_result.run_id}")
    print(f"  Repository   : {run_result.repo}")
    print(f"  Branch       : {run_result.branch}")
    print(f"  Commit       : {run_result.commit_hash[:12] if run_result.commit_hash else 'unknown'}")
    print(f"  Timestamp    : {run_result.timestamp}")
    print(f"  Duration     : {run_result.duration_ms}ms")
    print(f"  Overall Score: {run_result.overall_score:.1f}/100")
    status_icon = _STATUS_ICON.get(run_result.status, run_result.status)
    print(f"  Status       : {status_icon}")
    print()

    # Gate results table
    if run_result.gate_results:
        print(f"  {'Gate':<20} {'Status':<10} {'Findings':<10} {'Critical':<10} {'High':<10} {'Duration':<10}")
        print(f"  {'─' * 70}")
        for gr in run_result.gate_results:
            gate_icon = _STATUS_ICON.get(gr.status, gr.status)
            print(
                f"  {gr.gate_name:<20} {gate_icon:<20} {gr.findings_count:<10} "
                f"{gr.critical_count:<10} {gr.high_count:<10} {gr.duration_ms}ms"
            )
        print()

    # Risk score details
    if run_result.risk_score:
        rs = run_result.risk_score
        print(f"  Risk Score   : {rs.overall:.2f}/100 ({rs.risk_level})")
        print(f"  Trend        : {rs.trend}")
        print(f"  Percentile   : {rs.percentile:.1f}")
        if rs.recommendation:
            print(f"  Recommendation: {rs.recommendation[:120]}")
        print()

    # Top findings
    if run_result.all_findings:
        print(f"  {_C.BOLD}Top Findings:{_C.RST}")
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            run_result.all_findings,
            key=lambda f: (severity_order.get(f.severity, 5), -f.cvss_score),
        )
        for i, finding in enumerate(sorted_findings[:15], 1):
            sev_icon = _SEV_ICON.get(finding.severity, finding.severity)
            location = f"{finding.file}:{finding.line}" if finding.file else "N/A"
            print(f"    {i:>2}. [{sev_icon}] {finding.message[:70]}")
            print(f"        Location: {location}  |  CVSS: {finding.cvss_score:.1f}  |  Gate: {finding.gate}")
            if finding.fix_suggestion:
                print(f"        Fix: {finding.fix_suggestion[:100]}")
        if len(run_result.all_findings) > 15:
            print(f"    ... and {len(run_result.all_findings) - 15} more findings")
        print()


def _generate_reports(run_result: Any, output_dir: str, fmt: str) -> None:
    formats = ["html", "json"] if fmt == "all" else [fmt]

    for report_format in formats:
        try:
            _generate_single_report(run_result, output_dir, report_format)
        except Exception as exc:
            print(f"{_C.YEL}Warning: Failed to generate {report_format} report: {exc}{_C.RST}", file=sys.stderr)


def _generate_single_report(run_result: Any, output_dir: str, fmt: str) -> None:
    run_id = run_result.run_id

    if fmt == "json":
        filepath = Path(output_dir) / f"securebuild-{run_id}.json"
        data = run_result.to_dict()
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"  JSON report : {filepath}")

    elif fmt == "html":
        filepath = Path(output_dir) / f"securebuild-{run_id}.html"
        html = _render_html_report(run_result)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"  HTML report : {filepath}")


def _render_html_report(run_result: Any) -> str:
    data = run_result.to_dict()
    risk_score = data.get("risk_score") or {}

    severity_counts = risk_score.get("by_severity", {}) if risk_score else {}
    total_findings = sum(severity_counts.values())

    # Build findings rows
    findings_rows = ""
    for f in data.get("gate_results", []):
        for finding in f.get("findings", []):
            sev = finding.get("severity", "info")
            color = {
                "critical": "#dc2626",
                "high": "#ea580c",
                "medium": "#ca8a04",
                "low": "#2563eb",
                "info": "#6b7280",
            }.get(sev, "#6b7280")
            findings_rows += f"""
            <tr>
                <td><span style="color:{color};font-weight:bold">{sev.upper()}</span></td>
                <td>{finding.get('gate', '')}</td>
                <td><code>{finding.get('file', '')}:{finding.get('line', 0)}</code></td>
                <td>{finding.get('message', '')}</td>
                <td>{finding.get('cvss_score', 0.0):.1f}</td>
                <td>{finding.get('cwe_id', '')}</td>
                <td>{finding.get('fix_suggestion', '')}</td>
            </tr>"""

    # Build gate summary rows
    gate_rows = ""
    for gr in data.get("gate_results", []):
        status_color = "#16a34a" if gr.get("status") == "pass" else "#dc2626"
        gate_rows += f"""
        <tr>
            <td>{gr.get('gate_name', '')}</td>
            <td style="color:{status_color};font-weight:bold">{gr.get('status', '').upper()}</td>
            <td>{gr.get('findings_count', 0)}</td>
            <td>{gr.get('duration_ms', 0)}ms</td>
            <td>{gr.get('files_scanned', 0)}</td>
        </tr>"""

    status = data.get("status", "unknown")
    status_color = "#16a34a" if status == "pass" else "#dc2626" if status == "fail" else "#ca8a04"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureBuild Report - {data.get('run_id', '')}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f9fafb; color: #1f2937; }}
  h1 {{ color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; }}
  h2 {{ color: #374151; margin-top: 30px; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 20px 0; }}
  .card {{ background: white; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }}
  .card .label {{ font-size: 0.85em; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }}
  .card .value {{ font-size: 1.5em; font-weight: 700; margin-top: 4px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 16px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }}
  th {{ background: #f3f4f6; text-align: left; padding: 12px; font-size: 0.85em; text-transform: uppercase; color: #6b7280; border-bottom: 2px solid #e5e7eb; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #f3f4f6; font-size: 0.9em; }}
  tr:hover {{ background: #f9fafb; }}
  code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }}
  .footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 0.8em; }}
</style>
</head>
<body>
<h1>SecureBuild Security Report</h1>

<div class="summary">
  <div class="card"><div class="label">Run ID</div><div class="value">{data.get('run_id', '')}</div></div>
  <div class="card"><div class="label">Status</div><div class="value" style="color:{status_color}">{status.upper()}</div></div>
  <div class="card"><div class="label">Overall Score</div><div class="value">{data.get('overall_score', 0):.1f}/100</div></div>
  <div class="card"><div class="label">Risk Level</div><div class="value">{risk_score.get('risk_level', 'N/A') if risk_score else 'N/A'}</div></div>
  <div class="card"><div class="label">Repository</div><div class="value" style="font-size:1em">{data.get('repo', '')}</div></div>
  <div class="card"><div class="label">Branch</div><div class="value" style="font-size:1em">{data.get('branch', '')}</div></div>
  <div class="card"><div class="label">Total Findings</div><div class="value">{total_findings}</div></div>
  <div class="card"><div class="label">Duration</div><div class="value">{data.get('duration_ms', 0)}ms</div></div>
</div>

<h2>Severity Breakdown</h2>
<div class="summary">
  <div class="card"><div class="label">Critical</div><div class="value" style="color:#dc2626">{severity_counts.get('critical', 0)}</div></div>
  <div class="card"><div class="label">High</div><div class="value" style="color:#ea580c">{severity_counts.get('high', 0)}</div></div>
  <div class="card"><div class="label">Medium</div><div class="value" style="color:#ca8a04">{severity_counts.get('medium', 0)}</div></div>
  <div class="card"><div class="label">Low</div><div class="value" style="color:#2563eb">{severity_counts.get('low', 0)}</div></div>
  <div class="card"><div class="label">Info</div><div class="value" style="color:#6b7280">{severity_counts.get('info', 0)}</div></div>
</div>

<h2>Gate Results</h2>
<table>
  <tr><th>Gate</th><th>Status</th><th>Findings</th><th>Duration</th><th>Files Scanned</th></tr>
  {gate_rows}
</table>

<h2>Findings Detail</h2>
<table>
  <tr><th>Severity</th><th>Gate</th><th>Location</th><th>Message</th><th>CVSS</th><th>CWE</th><th>Fix</th></tr>
  {findings_rows}
</table>

{"<p><strong>Recommendation:</strong> " + risk_score.get('recommendation', '') + "</p>" if risk_score and risk_score.get('recommendation') else ""}

<div class="footer">
  <p>Generated by SecureBuild CI/CD Security Gate on {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
  <p>Commit: {data.get('commit_hash', 'unknown')[:12]} | Run ID: {data.get('run_id', '')}</p>
</div>
</body>
</html>"""
    return html


def _generate_summary_md(run_result: Any, output_dir: str) -> None:
    data = run_result.to_dict()
    risk_score = data.get("risk_score") or {}
    severity_counts = risk_score.get("by_severity", {}) if risk_score else {}

    status = data.get("status", "unknown")
    status_emoji = "✅" if status == "pass" else "❌" if status == "fail" else "⚠️"

    lines = [
        f"## {status_emoji} SecureBuild Security Scan",
        "",
        f"**Status:** {status.upper()}  |  **Score:** {data.get('overall_score', 0):.1f}/100  |  **Run ID:** `{data.get('run_id', '')}`",
        "",
        f"| Repository | Branch | Commit | Duration |",
        f"|---|---|---|---|",
        f"| {data.get('repo', '')} | {data.get('branch', '')} | `{data.get('commit_hash', 'unknown')[:12]}` | {data.get('duration_ms', 0)}ms |",
        "",
        f"### Severity Breakdown",
        f"| Critical | High | Medium | Low | Info |",
        f"|---|---|---|---|---|",
        f"| {severity_counts.get('critical', 0)} | {severity_counts.get('high', 0)} | {severity_counts.get('medium', 0)} | {severity_counts.get('low', 0)} | {severity_counts.get('info', 0)} |",
        "",
    ]

    if risk_score and risk_score.get("recommendation"):
        lines.append(f"> **Recommendation:** {risk_score['recommendation']}")
        lines.append("")

    filepath = Path(output_dir) / "summary.md"
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# Command: init

def handle_init(args: argparse.Namespace) -> None:
    target = Path("securebuild.yaml")
    if target.exists():
        print(f"{_C.YEL}Warning: securebuild.yaml already exists. Overwrite? [y/N] ", end="")
        try:
            answer = input().strip().lower()
        except EOFError:
            answer = "n"
        if answer not in ("y", "yes"):
            print("Aborted.")
            return

    project_type = args.project_type
    language = args.language

    # Adjust defaults based on project type
    if project_type == "commercial":
        allowed_licenses = """      - MIT
      - Apache-2.0
      - BSD-2-Clause
      - BSD-3-Clause
      - ISC
      - PSF
      - Proprietary"""
        blocked_licenses = """      - AGPL-3.0
      - GPL-2.0
      - GPL-3.0"""
    else:
        allowed_licenses = """      - MIT
      - Apache-2.0
      - BSD-2-Clause
      - BSD-3-Clause
      - ISC
      - PSF
      - GPL-2.0
      - GPL-3.0
      - LGPL-2.1
      - LGPL-3.0
      - MPL-2.0"""
        blocked_licenses = """      - AGPL-3.0"""

    # Adjust language-specific gates
    lang_gates = ""
    if language in ("python", "both"):
        lang_gates += """
    # Python-specific patterns
    exclude_paths: ["migrations/**", "*/tests/**", "conftest.py"]"""
    if language in ("javascript", "both"):
        lang_gates += """
    # JavaScript/TypeScript patterns
    exclude_paths: ["*/tests/**", "*/__tests__/**", "*/test/**", "jest.config.*"]"""

    yaml_content = f"""# SecureBuild Configuration
# See docs/configuration.md for full documentation

project:
  name: ""  # Auto-detected from repo
  type: {project_type}  # open_source or commercial
  language: {language}  # python, javascript, or both

gates:
  secrets:
    enabled: true
    custom_patterns: []
    # - name: "Internal API Key"
    #   pattern: "INTERNAL_[A-Z0-9]{{32}}"
    exclude_paths: []
  sast:
    enabled: true
    incremental_scan: false{lang_gates}
  cve:
    enabled: true
    check_stale_days: 730
    check_licenses: true
    exclude_paths: []
  license:
    enabled: true
    allowed_licenses:
{allowed_licenses}
    blocked_licenses:
{blocked_licenses}
    exclude_paths: []
  iac:
    enabled: true
    check_docker: true
    check_compose: true
    check_k8s: true
    check_github_actions: true
    terraform_experimental: false
    exclude_paths: []

thresholds:
  block_on:
    critical: 1  # Block if ANY critical finding
    high: 5      # Block if 5+ high findings
    score: 7.0   # Block if overall score > 7.0
  warn_only: false  # Never block, always report

exclude_paths:
  - "node_modules/**"
  - "venv/**"
  - ".git/**"
  - "*.lock"
  - "*.min.js"
  - "*.min.css"
  - "__pycache__/**"
  - ".tox/**"

notifications:
  slack:
    enabled: false
    webhook_url: ""  # Set in .env or here
  email:
    enabled: false
    smtp_host: ""
    smtp_port: 587
    to_address: ""

github:
  post_pr_comments: true
  post_inline_comments: true
  update_commit_status: true
  job_summary: true

reporting:
  default_format: html
  include_charts: true
  include_code_snippets: true
  max_findings_per_gate: 100
"""

    with open(target, "w", encoding="utf-8") as f:
        f.write(yaml_content)

    print(f"{_C.GRN}Created securebuild.yaml{_C.RST}")
    print(f"  Project type : {project_type}")
    print(f"  Language     : {language}")
    print(f"\nEdit the file to customise gates, thresholds, and notifications.")


# Command: report

def handle_report(args: argparse.Namespace) -> None:
    db_manager = _get_db_manager()
    run_data = db_manager.get_run_by_id(args.run_id)

    if not run_data:
        print(f"{_C.RED}Error: Run ID '{args.run_id}' not found in database{_C.RST}", file=sys.stderr)
        sys.exit(1)

    # Reconstruct RunResult from stored data
    from engine.models import RunResult, GateResult, Finding, RiskScore

    gate_results = []
    for gr_data in run_data.get("gate_results", []):
        gate_results.append(GateResult(
            gate_name=gr_data.get("gate_name", ""),
            status=gr_data.get("status", "pass"),
            duration_ms=gr_data.get("duration_ms", 0),
            files_scanned=gr_data.get("metadata", {}).get("files_scanned", 0) if isinstance(gr_data.get("metadata"), dict) else 0,
        ))

    # Reconstruct findings from DB rows
    findings_list = []
    for f_data in run_data.get("findings", []):
        findings_list.append(Finding(
            gate=f_data.get("gate", ""),
            file=f_data.get("file", ""),
            line=f_data.get("line", 0),
            message=f_data.get("message", ""),
            cvss_score=f_data.get("cvss_score", 0.0),
            severity=f_data.get("severity", "info"),
            fix_suggestion=f_data.get("fix_suggestion", ""),
            cwe_id=f_data.get("cwe_id", ""),
            rule_id=f_data.get("rule_id", ""),
            finding_type=f_data.get("finding_type", "vulnerability"),
            confidence=f_data.get("confidence", "medium"),
        ))

    # Merge findings into gate results
    for gr in gate_results:
        gr.findings = [f for f in findings_list if f.gate == gr.gate_name]

    # Get risk score from metadata
    metadata = run_data.get("metadata", {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except (json.JSONDecodeError, TypeError):
            metadata = {}

    risk_score_data = metadata.get("risk_score")
    risk_score = RiskScore.from_dict(risk_score_data) if risk_score_data else None

    run_result = RunResult(
        run_id=run_data.get("id", ""),
        repo=run_data.get("repo", ""),
        branch=run_data.get("branch", ""),
        commit_hash=run_data.get("commit_hash", ""),
        timestamp=run_data.get("timestamp", ""),
        overall_score=run_data.get("overall_score", 0.0),
        status=run_data.get("status", "pass"),
        gate_results=gate_results,
        risk_score=risk_score,
        duration_ms=run_data.get("duration_ms", 0),
    )

    # Determine output path
    fmt = args.format
    output = args.output
    if output:
        output_dir = str(Path(output).parent)
        _ensure_dir(output_dir)
    else:
        output_dir = "reports"
        _ensure_dir(output_dir)

    # Generate report
    if fmt == "json":
        filepath = output or f"reports/securebuild-{args.run_id}.json"
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(run_result.to_dict(), f, indent=2, default=str)
        print(f"JSON report saved to: {filepath}")

    elif fmt == "html":
        filepath = output or f"reports/securebuild-{args.run_id}.html"
        html = _render_html_report(run_result)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"HTML report saved to: {filepath}")


# Command: dashboard

def handle_dashboard(args: argparse.Namespace) -> None:
    try:
        from flask import Flask, jsonify, render_template_string, request  # type: ignore
    except ImportError:
        print(
            f"{_C.RED}Error: Flask is not installed. Install it with: pip install flask{_C.RST}",
            file=sys.stderr,
        )
        sys.exit(1)

    db_manager = _get_db_manager()

    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

    DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureBuild Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; }
  .header { background: #1e293b; padding: 20px 40px; border-bottom: 1px solid #334155; display: flex; align-items: center; justify-content: space-between; }
  .header h1 { font-size: 1.5em; color: #38bdf8; }
  .header .stats { display: flex; gap: 24px; }
  .header .stat { text-align: center; }
  .header .stat .num { font-size: 1.8em; font-weight: 700; }
  .header .stat .lbl { font-size: 0.75em; color: #94a3b8; text-transform: uppercase; }
  .container { max-width: 1400px; margin: 0 auto; padding: 24px; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 16px; }
  .card h2 { color: #38bdf8; margin-bottom: 12px; font-size: 1.1em; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 10px 12px; color: #94a3b8; font-size: 0.8em; text-transform: uppercase; border-bottom: 1px solid #334155; }
  td { padding: 10px 12px; border-bottom: 1px solid #1e293b; font-size: 0.9em; }
  tr:hover { background: #334155; }
  .pass { color: #4ade80; font-weight: 600; }
  .fail { color: #f87171; font-weight: 600; }
  .error { color: #fbbf24; font-weight: 600; }
  .critical { color: #f87171; }
  .high { color: #fb923c; }
  .medium { color: #fbbf24; }
  .low { color: #38bdf8; }
  .info { color: #94a3b8; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; }
  .badge-pass { background: #064e3b; color: #4ade80; }
  .badge-fail { background: #7f1d1d; color: #f87171; }
  .badge-error { background: #78350f; color: #fbbf24; }
  .empty { text-align: center; padding: 40px; color: #64748b; }
</style>
</head>
<body>
<div class="header">
  <h1>SecureBuild Dashboard</h1>
  <div class="stats">
    <div class="stat"><div class="num" id="total-runs">-</div><div class="lbl">Total Runs</div></div>
    <div class="stat"><div class="num critical" id="critical-count">-</div><div class="lbl">Critical</div></div>
    <div class="stat"><div class="num high" id="high-count">-</div><div class="lbl">High</div></div>
    <div class="stat"><div class="num" id="avg-score">-</div><div class="lbl">Avg Score</div></div>
  </div>
</div>
<div class="container">
  <div class="card">
    <h2>Recent Scans</h2>
    <table>
      <thead><tr><th>Run ID</th><th>Repository</th><th>Branch</th><th>Score</th><th>Status</th><th>Findings</th><th>Timestamp</th><th>Duration</th></tr></thead>
      <tbody id="runs-table"></tbody>
    </table>
    <div class="empty" id="no-runs" style="display:none;">No scan runs found. Run `securebuild scan <repo>` to get started.</div>
  </div>
</div>
<script>
fetch('/api/v1/runs?limit=25')
  .then(r => r.json())
  .then(data => {
    document.getElementById('total-runs').textContent = data.total || 0;
    document.getElementById('critical-count').textContent = data.critical_count || 0;
    document.getElementById('high-count').textContent = data.high_count || 0;
    document.getElementById('avg-score').textContent = (data.avg_score || 0).toFixed(1);

    const tbody = document.getElementById('runs-table');
    const noRuns = document.getElementById('no-runs');
    if (!data.runs || data.runs.length === 0) {
      noRuns.style.display = 'block';
      return;
    }
    data.runs.forEach(run => {
      const statusClass = run.status === 'pass' ? 'badge-pass' : run.status === 'fail' ? 'badge-fail' : 'badge-error';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${run.id || ''}</code></td>
        <td>${run.repo || ''}</td>
        <td>${run.branch || ''}</td>
        <td>${(run.overall_score || 0).toFixed(1)}</td>
        <td><span class="badge ${statusClass}">${(run.status || '').toUpperCase()}</span></td>
        <td>${run.findings_count || 0}</td>
        <td>${run.timestamp || ''}</td>
        <td>${run.duration_ms || 0}ms</td>
      `;
      tbody.appendChild(tr);
    });
  })
  .catch(err => console.error('Failed to load runs:', err));
</script>
</body>
</html>"""

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/api/v1/health")
    def health():
        return jsonify({"status": "healthy", "version": "1.0.0"})

    @app.route("/api/v1/runs")
    def list_runs():
        limit = request.args.get("limit", 25, type=int)
        repo = request.args.get("repo")
        if repo:
            runs = db_manager.get_runs_by_repo(repo, limit=limit)
        else:
            runs = db_manager.get_recent_runs(limit=limit)

        # Enrich with findings count
        for run in runs:
            run_id = run.get("id")
            findings = db_manager.get_findings_by_severity("critical", run_id=run_id, limit=1000)
            run["findings_count"] = len(findings)

        return jsonify({
            "runs": runs,
            "total": db_manager.get_run_count(),
            "critical_count": db_manager.get_critical_count(),
            "avg_score": db_manager.get_avg_score(),
        })

    @app.route("/api/v1/runs/<run_id>")
    def get_run(run_id):
        run_data = db_manager.get_run_by_id(run_id)
        if not run_data:
            return jsonify({"error": "Run not found"}), 404
        return jsonify(run_data)

    host = args.host
    port = args.port
    debug = args.debug

    print(f"\n{_C.BOLD}SecureBuild Dashboard{_C.RST}")
    print(f"  Starting on http://{host}:{port}")
    print(f"  Debug mode: {'ON' if debug else 'OFF'}")
    print(f"  Database: {db_manager.db_path}")
    print()

    app.run(host=host, port=port, debug=debug)


# Command: history

def handle_history(args: argparse.Namespace) -> None:
    db_manager = _get_db_manager()

    if args.repo:
        runs = db_manager.get_runs_by_repo(args.repo, limit=args.limit)
    else:
        runs = db_manager.get_recent_runs(limit=args.limit)

    if not runs:
        print(f"\n{_C.YEL}No scan history found.{_C.RST}")
        print("  Run `securebuild scan <repo>` to start scanning.")
        return

    # Print header
    print(f"\n{_C.BOLD}SecureBuild Scan History{_C.RST}")
    print(f"{'─' * 100}")
    print(
        f"  {'Run ID':<18} {'Repository':<20} {'Branch':<14} "
        f"{'Score':<8} {'Status':<8} {'Timestamp':<22} {'Duration':<10}"
    )
    print(f"  {'─' * 96}")

    for run in runs:
        run_id = run.get("id", "")
        repo = run.get("repo", "")
        branch = run.get("branch", "")
        score = run.get("overall_score", 0.0)
        status = run.get("status", "unknown")
        timestamp = run.get("timestamp", "")
        duration = f"{run.get('duration_ms', 0)}ms"

        # Colour-code the status
        status_icon = _STATUS_ICON.get(status, status)
        score_color = _C.GRN if score >= 80 else _C.YEL if score >= 60 else _C.RED
        score_str = f"{score_color}{score:.1f}{_C.RST}"

        # Truncate long repo names
        if len(repo) > 18:
            repo = repo[:15] + "..."

        print(
            f"  {run_id:<18} {repo:<20} {branch:<14} "
            f"{score_str:<18} {status_icon:<18} {timestamp:<22} {duration:<10}"
        )

    print(f"  {'─' * 96}")
    total = db_manager.get_run_count()
    avg = db_manager.get_avg_score()
    critical = db_manager.get_critical_count()
    print(f"\n  Total runs: {total}  |  Average score: {avg:.1f}  |  Critical findings (30d): {critical}")

    if args.repo:
        repo_runs = db_manager.get_run_count(repo=args.repo)
        repo_avg = db_manager.get_avg_score(repo=args.repo)
        print(f"  Runs for '{args.repo}': {repo_runs}  |  Average score: {repo_avg:.1f}")

    print()


# Main entry point

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="securebuild",
        description="SecureBuild CI/CD Security Gate - Multi-gate security scanner",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    scan_parser = subparsers.add_parser("scan", help="Run security scan on a repository")
    scan_parser.add_argument("repo_path", help="Path to repository to scan")
    scan_parser.add_argument("--config", "-c", help="Path to securebuild.yaml config")
    scan_parser.add_argument("--output-dir", "-o", default="./reports", help="Output directory")
    scan_parser.add_argument(
        "--format", "-f",
        choices=["html", "json", "all"],
        default="all",
        help="Report format (html or json)",
    )
    scan_parser.add_argument("--threshold", "-t", type=float, help="Override score threshold")
    scan_parser.add_argument("--dry-run", action="store_true", help="Run without blocking pipeline")
    scan_parser.add_argument(
        "--gates", nargs="+",
        choices=["secrets", "sast", "cve", "license", "iac"],
        help="Gates to run (default: all enabled)",
    )
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    init_parser = subparsers.add_parser("init", help="Initialize securebuild.yaml config")
    init_parser.add_argument(
        "--project-type",
        choices=["commercial", "open_source"],
        default="open_source",
    )
    init_parser.add_argument(
        "--language",
        choices=["python", "javascript", "both"],
        default="python",
    )

    report_parser = subparsers.add_parser("report", help="Generate report for a previous run")
    report_parser.add_argument("run_id", help="Run ID to generate report for")
    report_parser.add_argument("--format", "-f", choices=["html", "json"], default="html")
    report_parser.add_argument("--output", "-o", help="Output file path")

    dashboard_parser = subparsers.add_parser("dashboard", help="Start web dashboard")
    dashboard_parser.add_argument("--host", default="0.0.0.0", help="Host to bind")
    dashboard_parser.add_argument("--port", type=int, default=5000, help="Port to bind")
    dashboard_parser.add_argument("--debug", action="store_true", help="Debug mode")

    history_parser = subparsers.add_parser("history", help="Show scan history")
    history_parser.add_argument("--repo", "-r", help="Filter by repo name")
    history_parser.add_argument("--limit", "-n", type=int, default=10, help="Number of results")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    dispatch = {
        "scan": handle_scan,
        "init": handle_init,
        "report": handle_report,
        "dashboard": handle_dashboard,
        "history": handle_history,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
