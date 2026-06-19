"""SecureBuild CI/CD Security Gate - Home Dashboard Route"""

from flask import Blueprint, render_template, current_app
from datetime import datetime, timezone, timedelta

from engine.db import DatabaseManager

home_bp = Blueprint('home', __name__)


def _get_db():
    return DatabaseManager(current_app.config['DB_PATH'])


@home_bp.route('/')
def index():
    db = _get_db()

    # Calculate today's date range
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

    # Total runs today
    with db._get_connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM pipeline_runs WHERE timestamp >= ?",
            (today_start,),
        ).fetchone()
        runs_today = row[0] if row else 0

    # Total repos scanned (unique repos)
    with db._get_connection() as conn:
        row = conn.execute("SELECT COUNT(DISTINCT repo) FROM pipeline_runs").fetchone()
        total_repos = row[0] if row else 0

    # Average score (last 30 days)
    avg_score = db.get_avg_score(days=30)

    # Critical findings in last 7 days
    critical_count = db.get_critical_count(days=7)

    # Recent runs (last 10)
    recent_runs = db.get_recent_runs(limit=10)

    return render_template(
        'home.html',
        runs_today=runs_today,
        total_repos=total_repos,
        avg_score=avg_score,
        critical_count=critical_count,
        recent_runs=recent_runs,
    )
