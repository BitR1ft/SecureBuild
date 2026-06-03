"""SecureBuild CI/CD Security Gate - Database Manager"""

from __future__ import annotations

import hmac
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from engine.logger import get_logger
from engine.models import Finding, GateResult, RunResult

logger = get_logger("db")


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS pipeline_runs (
    id TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    branch TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    overall_score REAL NOT NULL DEFAULT 0.0,
    status TEXT NOT NULL DEFAULT 'pass',
    commit_hash TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS gate_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    gate_name TEXT NOT NULL,
    findings_count INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'info',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pass',
    metadata TEXT,
    FOREIGN KEY (run_id) REFERENCES pipeline_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    gate TEXT NOT NULL,
    file TEXT NOT NULL DEFAULT '',
    line INTEGER NOT NULL DEFAULT 0,
    message TEXT NOT NULL DEFAULT '',
    cvss_score REAL NOT NULL DEFAULT 0.0,
    severity TEXT NOT NULL DEFAULT 'info',
    fix_suggestion TEXT NOT NULL DEFAULT '',
    cwe_id TEXT NOT NULL DEFAULT '',
    rule_id TEXT NOT NULL DEFAULT '',
    finding_type TEXT NOT NULL DEFAULT 'vulnerability',
    confidence TEXT NOT NULL DEFAULT 'medium',
    fix_diff TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (run_id) REFERENCES pipeline_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    last_used TEXT,
    active INTEGER NOT NULL DEFAULT 1
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_repo ON pipeline_runs(repo);
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_timestamp ON pipeline_runs(timestamp);
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_status ON pipeline_runs(status);
CREATE INDEX IF NOT EXISTS idx_gate_results_run_id ON gate_results(run_id);
CREATE INDEX IF NOT EXISTS idx_gate_results_gate_name ON gate_results(gate_name);
CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_gate ON findings(gate);
CREATE INDEX IF NOT EXISTS idx_findings_cwe_id ON findings(cwe_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(active);
"""


class DatabaseManager:
    """Manages all database operations for SecureBuild."""

    def __init__(self, db_path: str = "securebuild.db") -> None:
        self.db_path = db_path
        self._initialized = False
        self._ensure_schema()


    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


    def _ensure_schema(self) -> None:
        if self._initialized:
            return

        # Ensure the parent directory exists
        db_dir = Path(self.db_path).parent
        if db_dir and db_dir != Path("."):
            db_dir.mkdir(parents=True, exist_ok=True)

        with self._get_connection() as conn:
            conn.executescript(_SCHEMA_SQL)

        self._initialized = True
        logger.info("Database schema initialized at %s", self.db_path)


    def save_run(self, run_result: RunResult) -> None:
        with self._get_connection() as conn:
            # Save the run
            metadata_json = json.dumps(run_result.to_dict(), default=str)
            conn.execute(
                """
                INSERT OR REPLACE INTO pipeline_runs
                    (id, repo, branch, timestamp, overall_score, status,
                     commit_hash, duration_ms, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_result.run_id,
                    run_result.repo,
                    run_result.branch,
                    run_result.timestamp,
                    run_result.overall_score,
                    run_result.status,
                    run_result.commit_hash,
                    run_result.duration_ms,
                    metadata_json,
                ),
            )

            # Save each gate result
            for gate_result in run_result.gate_results:
                self._save_gate_result(conn, run_result.run_id, gate_result)

            # Save each finding
            for finding in run_result.all_findings:
                self._save_finding(conn, run_result.run_id, finding)

        logger.info(
            "Saved run %s: %d gates, %d findings",
            run_result.run_id,
            len(run_result.gate_results),
            run_result.total_findings,
        )

    def save_gate_result(self, run_id: str, gate_result: GateResult) -> None:
        with self._get_connection() as conn:
            self._save_gate_result(conn, run_id, gate_result)

    def _save_gate_result(
        self, conn: sqlite3.Connection, run_id: str, gate_result: GateResult
    ) -> None:
        metadata_json = json.dumps(gate_result.metadata, default=str)
        conn.execute(
            """
            INSERT INTO gate_results
                (run_id, gate_name, findings_count, severity, duration_ms,
                 status, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                gate_result.gate_name,
                gate_result.findings_count,
                gate_result.highest_severity,
                gate_result.duration_ms,
                gate_result.status,
                metadata_json,
            ),
        )

    def save_finding(self, run_id: str, finding: Finding) -> None:
        with self._get_connection() as conn:
            self._save_finding(conn, run_id, finding)

    def _save_finding(
        self, conn: sqlite3.Connection, run_id: str, finding: Finding
    ) -> None:
        conn.execute(
            """
            INSERT INTO findings
                (run_id, gate, file, line, message, cvss_score, severity,
                 fix_suggestion, cwe_id, rule_id, finding_type, confidence,
                 fix_diff)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                finding.gate,
                finding.file,
                finding.line,
                finding.message,
                finding.cvss_score,
                finding.severity,
                finding.fix_suggestion,
                finding.cwe_id,
                finding.rule_id,
                finding.finding_type,
                finding.confidence,
                finding.fix_diff,
            ),
        )


    def get_run_by_id(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM pipeline_runs WHERE id = ?", (run_id,)
            ).fetchone()

            if not row:
                return None

            run_data = dict(row)

            # Parse metadata JSON
            if run_data.get("metadata"):
                try:
                    run_data["metadata"] = json.loads(run_data["metadata"])
                except (json.JSONDecodeError, TypeError) as exc:
                    logger.warning(
                        "Failed to parse metadata JSON for run %s: %s",
                        run_id, str(exc),
                    )

            # Load gate results
            gate_rows = conn.execute(
                "SELECT * FROM gate_results WHERE run_id = ?", (run_id,)
            ).fetchall()
            run_data["gate_results"] = [dict(r) for r in gate_rows]

            # Load findings
            finding_rows = conn.execute(
                "SELECT * FROM findings WHERE run_id = ?", (run_id,)
            ).fetchall()
            run_data["findings"] = [dict(r) for r in finding_rows]

            return run_data

    def get_runs_by_repo(
        self, repo: str, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM pipeline_runs
                WHERE repo = ?
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                """,
                (repo, limit, offset),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_recent_runs(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM pipeline_runs
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]


    def get_findings_by_severity(
        self,
        severity: str,
        run_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            if run_id:
                rows = conn.execute(
                    """
                    SELECT * FROM findings
                    WHERE severity = ? AND run_id = ?
                    ORDER BY cvss_score DESC
                    LIMIT ?
                    """,
                    (severity, run_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM findings
                    WHERE severity = ?
                    ORDER BY cvss_score DESC
                    LIMIT ?
                    """,
                    (severity, limit),
                ).fetchall()
            return [dict(r) for r in rows]


    def get_run_count(self, repo: Optional[str] = None) -> int:
        with self._get_connection() as conn:
            if repo:
                row = conn.execute(
                    "SELECT COUNT(*) FROM pipeline_runs WHERE repo = ?",
                    (repo,),
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) FROM pipeline_runs").fetchone()
            return row[0] if row else 0

    def get_avg_score(self, repo: Optional[str] = None, days: int = 30) -> float:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=days)
        ).isoformat()

        with self._get_connection() as conn:
            if repo:
                row = conn.execute(
                    """
                    SELECT AVG(overall_score) FROM pipeline_runs
                    WHERE repo = ? AND timestamp >= ?
                    """,
                    (repo, cutoff),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT AVG(overall_score) FROM pipeline_runs
                    WHERE timestamp >= ?
                    """,
                    (cutoff,),
                ).fetchone()
            return round(row[0], 2) if row and row[0] is not None else 0.0

    def get_critical_count(self, days: int = 30) -> int:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=days)
        ).isoformat()

        with self._get_connection() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) FROM findings f
                INNER JOIN pipeline_runs pr ON f.run_id = pr.id
                WHERE f.severity = 'critical' AND pr.timestamp >= ?
                """,
                (cutoff,),
            ).fetchone()
            return row[0] if row else 0


    def store_api_key(self, key_hash: str, name: str) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO api_keys (key_hash, name, created_at)
                VALUES (?, ?, ?)
                """,
                (key_hash, name, datetime.now(timezone.utc).isoformat()),
            )
            return cursor.lastrowid or 0

    def validate_api_key(self, key_hash: str) -> bool:
        with self._get_connection() as conn:
            # Retrieve all active hashes and compare in constant time
            rows = conn.execute(
                "SELECT id, key_hash FROM api_keys WHERE active = 1",
            ).fetchall()

            matched_id: int | None = None
            for row in rows:
                # hmac.compare_digest prevents timing attacks
                if hmac.compare_digest(key_hash, row["key_hash"]):
                    matched_id = row["id"]
                    break

            if matched_id is None:
                return False

            # Update last_used timestamp
            conn.execute(
                "UPDATE api_keys SET last_used = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), matched_id),
            )
            return True

    def get_all_api_keys(self) -> List[str]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT key_hash FROM api_keys WHERE active = 1",
            ).fetchall()
            return [row["key_hash"] for row in rows]

    def revoke_api_key(self, key_hash: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE api_keys SET active = 0 WHERE key_hash = ?",
                (key_hash,),
            )
            return cursor.rowcount > 0


    def cleanup_old_runs(self, days: int = 90) -> int:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=days)
        ).isoformat()

        with self._get_connection() as conn:
            # Delete findings first (due to FK constraints)
            conn.execute(
                """
                DELETE FROM findings
                WHERE run_id IN (
                    SELECT id FROM pipeline_runs WHERE timestamp < ?
                )
                """,
                (cutoff,),
            )
            # Delete gate results
            conn.execute(
                """
                DELETE FROM gate_results
                WHERE run_id IN (
                    SELECT id FROM pipeline_runs WHERE timestamp < ?
                )
                """,
                (cutoff,),
            )
            # Delete runs
            cursor = conn.execute(
                "DELETE FROM pipeline_runs WHERE timestamp < ?",
                (cutoff,),
            )
            deleted = cursor.rowcount
            logger.info("Cleaned up %d old runs (older than %d days)", deleted, days)
            return deleted
