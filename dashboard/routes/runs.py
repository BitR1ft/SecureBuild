"""SecureBuild CI/CD Security Gate - Run History & Detail Routes"""

from flask import Blueprint, render_template, request, abort, current_app, jsonify, Response
from datetime import datetime, timezone, timedelta
import json

from engine.db import DatabaseManager

runs_bp = Blueprint('runs', __name__)


def _get_db():
    return DatabaseManager(current_app.config['DB_PATH'])


@runs_bp.route('/runs')
def run_history():
    db = _get_db()
    per_page = 20
    page = request.args.get('page', 1, type=int)
    offset = (page - 1) * per_page

    # Build filtered query
    conditions = []
    params = []

    repo_filter = request.args.get('repo', '')
    if repo_filter:
        conditions.append("repo LIKE ?")
        params.append(f"%{repo_filter}%")

    branch_filter = request.args.get('branch', '')
    if branch_filter:
        conditions.append("branch LIKE ?")
        params.append(f"%{branch_filter}%")

    date_from = request.args.get('date_from', '')
    if date_from:
        conditions.append("timestamp >= ?")
        params.append(f"{date_from}T00:00:00")

    date_to = request.args.get('date_to', '')
    if date_to:
        conditions.append("timestamp <= ?")
        params.append(f"{date_to}T23:59:59")

    status_filter = request.args.get('status', '')
    if status_filter:
        conditions.append("status = ?")
        params.append(status_filter)

    min_score = request.args.get('min_score', type=float)
    if min_score is not None:
        conditions.append("overall_score >= ?")
        params.append(min_score)

    max_score = request.args.get('max_score', type=float)
    if max_score is not None:
        conditions.append("overall_score <= ?")
        params.append(max_score)

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    with db._get_connection() as conn:
        # Get total count for pagination
        count_row = conn.execute(
            f"SELECT COUNT(*) FROM pipeline_runs {where_clause}",
            params
        ).fetchone()
        total_runs = count_row[0] if count_row else 0

        # Get paginated runs
        rows = conn.execute(
            f"""
            SELECT * FROM pipeline_runs
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
            """,
            params + [per_page, offset]
        ).fetchall()
        runs = [dict(r) for r in rows]

        # Get list of unique repos for filter dropdown
        repo_rows = conn.execute(
            "SELECT DISTINCT repo FROM pipeline_runs ORDER BY repo"
        ).fetchall()
        all_repos = [r['repo'] for r in repo_rows]

        # Get list of unique branches for filter dropdown
        branch_rows = conn.execute(
            "SELECT DISTINCT branch FROM pipeline_runs ORDER BY branch"
        ).fetchall()
        all_branches = [r['branch'] for r in branch_rows]

    total_pages = max(1, (total_runs + per_page - 1) // per_page)

    return render_template(
        'runs.html',
        runs=runs,
        page=page,
        total_pages=total_pages,
        total_runs=total_runs,
        per_page=per_page,
        all_repos=all_repos,
        all_branches=all_branches,
        repo_filter=repo_filter,
        branch_filter=branch_filter,
        date_from=date_from,
        date_to=date_to,
        status_filter=status_filter,
        min_score=min_score,
        max_score=max_score,
    )


@runs_bp.route('/runs/<run_id>')
def run_detail(run_id):
    db = _get_db()
    run_data = db.get_run_by_id(run_id)

    if not run_data:
        abort(404)

    # Organize findings by gate
    findings_by_gate = {}
    for finding in run_data.get('findings', []):
        gate = finding.get('gate', 'unknown')
        if gate not in findings_by_gate:
            findings_by_gate[gate] = []
        findings_by_gate[gate].append(finding)

    # Get severity counts for the run
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for finding in run_data.get('findings', []):
        sev = finding.get('severity', 'info')
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Compute score gauge value (0-100 to 0-10 scale for display)
    score_display = round(run_data.get('overall_score', 0) / 10, 1)

    return render_template(
        'run_detail.html',
        run=run_data,
        findings_by_gate=findings_by_gate,
        severity_counts=severity_counts,
        score_display=score_display,
    )


@runs_bp.route('/runs/<run_id>/report')
def run_report(run_id):
    db = _get_db()
    run_data = db.get_run_by_id(run_id)

    if not run_data:
        abort(404)

    findings_rows = ""
    for finding in run_data.get('findings', []):
        sev = finding.get('severity', 'info')
        color = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#ca8a04',
            'low': '#2563eb',
            'info': '#6b7280',
        }.get(sev, '#6b7280')
        file_loc = finding.get('file', '')
        line_no = finding.get('line', 0)
        location = f"{file_loc}:{line_no}" if file_loc else '—'
        cwe = finding.get('cwe_id', '') or '—'
        fix = finding.get('fix_suggestion', '') or '—'
        findings_rows += f"""
            <tr>
                <td><span style="color:{color};font-weight:bold;text-transform:uppercase">{sev}</span></td>
                <td>{finding.get('gate', '')}</td>
                <td><code style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:0.8em">{location}</code></td>
                <td>{finding.get('message', '')}</td>
                <td>{finding.get('cvss_score', 0.0):.1f}</td>
                <td>{cwe}</td>
                <td style="font-size:0.85em;color:#374151">{fix}</td>
            </tr>"""

    gate_rows = ""
    for gr in run_data.get('gate_results', []):
        status_color = '#16a34a' if gr.get('status') == 'pass' else '#dc2626'
        gate_rows += f"""
            <tr>
                <td>{gr.get('gate_name', '')}</td>
                <td style="color:{status_color};font-weight:bold">{gr.get('status', '').upper()}</td>
                <td>{gr.get('findings_count', 0)}</td>
                <td>{gr.get('duration_ms', 0)}ms</td>
                <td>{gr.get('files_scanned', 0)}</td>
            </tr>"""

    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for finding in run_data.get('findings', []):
        sev = finding.get('severity', 'info')
        if sev in severity_counts:
            severity_counts[sev] += 1
    total_findings = sum(severity_counts.values())

    status = run_data.get('status', 'unknown')
    score = run_data.get('overall_score', 0.0)
    status_color = '#16a34a' if status == 'pass' else '#dc2626' if status == 'fail' else '#ca8a04'
    score_color = '#16a34a' if score >= 80 else '#d97706' if score >= 50 else '#dc2626'
    ts = run_data.get('timestamp', '')[:19].replace('T', ' ') if run_data.get('timestamp') else 'N/A'
    repo = run_data.get('repo', '')
    branch = run_data.get('branch', '')
    commit = (run_data.get('commit_hash', '') or '')[:12] or 'unknown'
    duration = run_data.get('duration_ms', 0)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureBuild Report &mdash; {run_id[:16]}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: #f8fafc; color: #1e293b; line-height: 1.6; }}
  .page-header {{
    background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%);
    color: #fff; padding: 36px 48px; display: flex; align-items: center;
    justify-content: space-between; gap: 24px;
  }}
  .page-header .logo {{ display: flex; align-items: center; gap: 14px; }}
  .page-header .logo svg {{ width: 40px; height: 40px; flex-shrink: 0; }}
  .page-header .logo h1 {{ font-size: 1.6em; font-weight: 700; letter-spacing: -0.02em; }}
  .page-header .logo p {{ font-size: 0.85em; opacity: 0.75; margin-top: 2px; }}
  .status-pill {{
    display: inline-flex; align-items: center; gap: 6px;
    padding: 6px 18px; border-radius: 9999px; font-size: 0.95em;
    font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase;
    background: rgba(255,255,255,0.15); border: 1.5px solid rgba(255,255,255,0.3);
  }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}
  .summary-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px; margin-bottom: 32px;
  }}
  .metric {{
    background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
    padding: 20px 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.06);
  }}
  .metric .lbl {{
    font-size: 0.72em; font-weight: 600; color: #64748b;
    text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px;
  }}
  .metric .val {{ font-size: 1.6em; font-weight: 800; color: #0f172a; line-height: 1; }}
  .metric .val.score {{ color: {score_color}; }}
  .metric .val.status-val {{ color: {status_color}; }}
  .metric .sub {{ font-size: 0.8em; color: #94a3b8; margin-top: 4px; }}
  .sev-grid {{
    display: grid; grid-template-columns: repeat(5, 1fr);
    gap: 12px; margin-bottom: 32px;
  }}
  .sev-card {{
    background: #fff; border: 1px solid #e2e8f0; border-radius: 10px;
    padding: 16px 12px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.05);
  }}
  .sev-card .sev-num {{ font-size: 2em; font-weight: 800; line-height: 1; }}
  .sev-card .sev-lbl {{ font-size: 0.75em; font-weight: 600; text-transform: uppercase; margin-top: 4px; color: #64748b; }}
  .section {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
              padding: 0; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); overflow: hidden; }}
  .section-header {{
    padding: 16px 24px; border-bottom: 1px solid #f1f5f9;
    display: flex; align-items: center; justify-content: space-between;
    background: #f8fafc;
  }}
  .section-header h2 {{ font-size: 1em; font-weight: 700; color: #0f172a; }}
  .section-header .count {{ font-size: 0.8em; color: #64748b; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    text-align: left; padding: 11px 16px; color: #64748b;
    font-size: 0.72em; text-transform: uppercase; letter-spacing: 0.05em;
    border-bottom: 1.5px solid #e2e8f0; background: #f8fafc; font-weight: 700;
  }}
  td {{ padding: 10px 16px; border-bottom: 1px solid #f1f5f9; font-size: 0.88em; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f8fafc; }}
  .footer {{
    text-align: center; padding: 32px 16px; color: #94a3b8; font-size: 0.8em;
    border-top: 1px solid #e2e8f0; margin-top: 8px;
  }}
  @media print {{
    body {{ background: #fff; }}
    .page-header {{ background: #1e40af !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .section {{ break-inside: avoid; }}
  }}
  @media (max-width: 640px) {{
    .page-header {{ flex-direction: column; align-items: flex-start; padding: 24px; }}
    .sev-grid {{ grid-template-columns: repeat(3, 1fr); }}
    .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
    td, th {{ padding: 8px; font-size: 0.8em; }}
  }}
</style>
</head>
<body>

<div class="page-header">
  <div class="logo">
    <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M20 3L5 9v12c0 8.3 6.4 16 15 18C29.6 37 36 29.3 36 21V9L20 3z" fill="rgba(255,255,255,0.2)" stroke="rgba(255,255,255,0.8)" stroke-width="1.5"/>
      <path d="M14 20l4 4 8-8" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <div>
      <h1>SecureBuild</h1>
      <p>Security Scan Report &mdash; {ts}</p>
    </div>
  </div>
  <div class="status-pill"
       style="color:{'#bbf7d0' if status == 'pass' else '#fecaca' if status == 'fail' else '#fde68a'}">
    {'&#10003;' if status == 'pass' else '&#10007;' if status == 'fail' else '&#9888;'}&nbsp;{status.upper()}
  </div>
</div>

<div class="container">

  <!-- Summary Cards -->
  <div class="summary-grid">
    <div class="metric">
      <div class="lbl">Overall Score</div>
      <div class="val score">{score:.1f}<span style="font-size:0.5em;color:#94a3b8">/100</span></div>
    </div>
    <div class="metric">
      <div class="lbl">Status</div>
      <div class="val status-val">{status.upper()}</div>
    </div>
    <div class="metric">
      <div class="lbl">Repository</div>
      <div class="val" style="font-size:1em;word-break:break-all">{repo}</div>
      <div class="sub">{branch}</div>
    </div>
    <div class="metric">
      <div class="lbl">Commit</div>
      <div class="val" style="font-size:1em;font-family:monospace">{commit}</div>
    </div>
    <div class="metric">
      <div class="lbl">Total Findings</div>
      <div class="val" style="color:#dc2626" >{total_findings}</div>
    </div>
    <div class="metric">
      <div class="lbl">Duration</div>
      <div class="val" style="font-size:1.1em">{duration}ms</div>
    </div>
  </div>

  <!-- Severity Breakdown -->
  <div class="sev-grid">
    <div class="sev-card">
      <div class="sev-num" style="color:#dc2626">{severity_counts['critical']}</div>
      <div class="sev-lbl">Critical</div>
    </div>
    <div class="sev-card">
      <div class="sev-num" style="color:#ea580c">{severity_counts['high']}</div>
      <div class="sev-lbl">High</div>
    </div>
    <div class="sev-card">
      <div class="sev-num" style="color:#ca8a04">{severity_counts['medium']}</div>
      <div class="sev-lbl">Medium</div>
    </div>
    <div class="sev-card">
      <div class="sev-num" style="color:#2563eb">{severity_counts['low']}</div>
      <div class="sev-lbl">Low</div>
    </div>
    <div class="sev-card">
      <div class="sev-num" style="color:#6b7280">{severity_counts['info']}</div>
      <div class="sev-lbl">Info</div>
    </div>
  </div>

  <!-- Gate Results -->
  <div class="section">
    <div class="section-header">
      <h2>&#9638; Gate Results</h2>
      <span class="count">{len(run_data.get('gate_results', []))} gates</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Gate</th><th>Status</th><th>Findings</th><th>Duration</th><th>Files Scanned</th>
        </tr>
      </thead>
      <tbody>{gate_rows if gate_rows else '<tr><td colspan="5" style="text-align:center;color:#94a3b8;padding:24px">No gate results</td></tr>'}</tbody>
    </table>
  </div>

  <!-- Findings -->
  <div class="section">
    <div class="section-header">
      <h2>&#128027; Findings Detail</h2>
      <span class="count">{total_findings} total</span>
    </div>
    <div style="overflow-x:auto">
      <table>
        <thead>
          <tr>
            <th>Severity</th><th>Gate</th><th>Location</th>
            <th>Message</th><th>CVSS</th><th>CWE</th><th>Fix Suggestion</th>
          </tr>
        </thead>
        <tbody>{findings_rows if findings_rows else '<tr><td colspan="7" style="text-align:center;color:#94a3b8;padding:32px">&#10003; No findings detected &mdash; this run passed all security gates cleanly.</td></tr>'}</tbody>
      </table>
    </div>
  </div>

</div>

<div class="footer">
  Generated by <strong>SecureBuild CI/CD Security Gate</strong> &mdash;
  Run ID: <code>{run_id}</code> &mdash;
  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
</div>

</body>
</html>"""

    return Response(html, mimetype='text/html')


@runs_bp.route('/repos/<path:repo_name>')
def repo_summary(repo_name):
    db = _get_db()

    # Get recent runs for this repo
    runs = db.get_runs_by_repo(repo_name, limit=30, offset=0)

    if not runs:
        abort(404)

    # Get findings for recent runs
    run_ids = [r['id'] for r in runs]
    placeholders = ','.join(['?'] * len(run_ids))

    with db._get_connection() as conn:
        # Findings for these runs
        finding_rows = conn.execute(
            f"""
            SELECT * FROM findings
            WHERE run_id IN ({placeholders})
            ORDER BY cvss_score DESC
            """,
            run_ids
        ).fetchall()
        all_findings = [dict(r) for r in finding_rows]

        # Gate results for these runs
        gate_rows = conn.execute(
            f"""
            SELECT * FROM gate_results
            WHERE run_id IN ({placeholders})
            """,
            run_ids
        ).fetchall()
        gate_results = [dict(r) for r in gate_rows]

        # Top vulnerable files
        file_rows = conn.execute(
            f"""
            SELECT file,
                   COUNT(*) as finding_count,
                   MAX(cvss_score) as max_cvss,
                   GROUP_CONCAT(DISTINCT severity) as severities
            FROM findings
            WHERE run_id IN ({placeholders}) AND file != ''
            GROUP BY file
            ORDER BY finding_count DESC, max_cvss DESC
            LIMIT 10
            """,
            run_ids
        ).fetchall()
        vulnerable_files = [dict(r) for r in file_rows]

        # Finding type breakdown
        type_rows = conn.execute(
            f"""
            SELECT finding_type, COUNT(*) as count
            FROM findings
            WHERE run_id IN ({placeholders})
            GROUP BY finding_type
            ORDER BY count DESC
            """,
            run_ids
        ).fetchall()
        finding_types = [dict(r) for r in type_rows]

        # Severity breakdown
        sev_rows = conn.execute(
            f"""
            SELECT severity, COUNT(*) as count
            FROM findings
            WHERE run_id IN ({placeholders})
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                END
            """,
            run_ids
        ).fetchall()
        severity_breakdown = [dict(r) for r in sev_rows]

    # Compute gate pass rates
    gate_pass_rates = {}
    for gr in gate_results:
        gate_name = gr.get('gate_name', 'unknown')
        if gate_name not in gate_pass_rates:
            gate_pass_rates[gate_name] = {'pass': 0, 'fail': 0, 'error': 0, 'total': 0}
        status = gr.get('status', 'error')
        if status in gate_pass_rates[gate_name]:
            gate_pass_rates[gate_name][status] += 1
        gate_pass_rates[gate_name]['total'] += 1

    # Latest score and avg
    latest_score = runs[0].get('overall_score', 0) if runs else 0
    avg_score = db.get_avg_score(repo=repo_name, days=30)

    return render_template(
        'repo_summary.html',
        repo_name=repo_name,
        runs=runs,
        all_findings=all_findings,
        vulnerable_files=vulnerable_files,
        finding_types=finding_types,
        severity_breakdown=severity_breakdown,
        gate_pass_rates=gate_pass_rates,
        latest_score=latest_score,
        avg_score=avg_score,
        total_findings=len(all_findings),
    )
