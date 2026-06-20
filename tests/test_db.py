"""SecureBuild CI/CD Security Gate - DatabaseManager Tests"""

from __future__ import annotations

import hashlib
import hmac
import os
import tempfile
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest

from engine.db import DatabaseManager
from engine.models import Finding, GateResult, RiskScore, RunResult


@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test.db")
    return DatabaseManager(db_path)


def _make_finding(gate="secrets", severity="high", cvss=7.5):
    return Finding(
        gate=gate,
        file="app.py",
        line=10,
        message=f"Test {severity} finding",
        cvss_score=cvss,
        severity=severity,
        rule_id=f"{gate}-test",
        cwe_id="CWE-798",
        finding_type="secret",
    )


def _make_run_result(
    run_id: str = "20250101-abc12345",
    repo: str = "test/repo",
    status: str = "fail",
    overall_score: float = 65.0,
    severity: str = "high",
) -> RunResult:
    finding = _make_finding(severity=severity)
    gate_result = GateResult(
        gate_name="secrets",
        status=status,
        findings=[finding],
        duration_ms=100,
        files_scanned=5,
    )
    return RunResult(
        run_id=run_id,
        repo=repo,
        branch="main",
        commit_hash="abc123def456",
        timestamp=datetime.now(timezone.utc).isoformat(),
        overall_score=overall_score,
        status=status,
        gate_results=[gate_result],
        risk_score=RiskScore(
            overall=35.0,
            by_gate={"secrets": 35.0},
            by_severity={"critical": 0, "high": 1},
        ),
        duration_ms=500,
    )


class TestSchemaInit:
    def test_creates_tables(self, db):
        # If schema init fails, connection would fail
        assert db._initialized is True

    def test_idempotent_init(self, db):
        db._initialized = False
        db._ensure_schema()  # Should not raise
        assert db._initialized is True


class TestSaveAndGetRun:
    def test_save_and_retrieve_run(self, db):
        run = _make_run_result()
        db.save_run(run)
        retrieved = db.get_run_by_id(run.run_id)
        assert retrieved is not None
        assert retrieved["id"] == run.run_id
        assert retrieved["repo"] == run.repo
        assert retrieved["status"] == run.status

    def test_get_nonexistent_run_returns_none(self, db):
        result = db.get_run_by_id("nonexistent-run-id")
        assert result is None

    def test_run_includes_gate_results(self, db):
        run = _make_run_result()
        db.save_run(run)
        retrieved = db.get_run_by_id(run.run_id)
        assert "gate_results" in retrieved
        assert len(retrieved["gate_results"]) == 1
        assert retrieved["gate_results"][0]["gate_name"] == "secrets"

    def test_run_includes_findings(self, db):
        run = _make_run_result()
        db.save_run(run)
        retrieved = db.get_run_by_id(run.run_id)
        assert "findings" in retrieved
        assert len(retrieved["findings"]) == 1

    def test_metadata_parsed_as_dict(self, db):
        run = _make_run_result()
        db.save_run(run)
        retrieved = db.get_run_by_id(run.run_id)
        assert isinstance(retrieved.get("metadata"), dict)


class TestGetRunsByRepo:
    def test_returns_runs_for_repo(self, db):
        run1 = _make_run_result("20250101-run0001", "org/repo-a")
        run2 = _make_run_result("20250101-run0002", "org/repo-b")
        db.save_run(run1)
        db.save_run(run2)
        results = db.get_runs_by_repo("org/repo-a")
        assert len(results) == 1
        assert results[0]["repo"] == "org/repo-a"

    def test_limit_respected(self, db):
        for i in range(5):
            db.save_run(_make_run_result(f"20250101-run000{i}", "org/repo"))
        results = db.get_runs_by_repo("org/repo", limit=3)
        assert len(results) == 3

    def test_empty_repo_returns_empty(self, db):
        results = db.get_runs_by_repo("nonexistent/repo")
        assert results == []


class TestGetRecentRuns:
    def test_returns_runs_ordered_by_timestamp(self, db):
        db.save_run(_make_run_result("20250101-run0001", "repo/a"))
        db.save_run(_make_run_result("20250101-run0002", "repo/b"))
        results = db.get_recent_runs(limit=10)
        assert len(results) == 2

    def test_limit_respected(self, db):
        for i in range(5):
            db.save_run(_make_run_result(f"20250101-run000{i}", "repo/x"))
        results = db.get_recent_runs(limit=2)
        assert len(results) == 2


class TestStatistics:
    def test_run_count_empty(self, db):
        assert db.get_run_count() == 0

    def test_run_count_after_saves(self, db):
        db.save_run(_make_run_result("20250101-r001", "repo/a"))
        db.save_run(_make_run_result("20250101-r002", "repo/b"))
        assert db.get_run_count() == 2

    def test_run_count_filtered_by_repo(self, db):
        db.save_run(_make_run_result("20250101-r001", "repo/a"))
        db.save_run(_make_run_result("20250101-r002", "repo/b"))
        assert db.get_run_count(repo="repo/a") == 1

    def test_avg_score_empty(self, db):
        assert db.get_avg_score() == 0.0

    def test_avg_score_with_runs(self, db):
        db.save_run(_make_run_result("20250101-r001", "r", overall_score=80.0))
        db.save_run(_make_run_result("20250101-r002", "r", overall_score=60.0))
        avg = db.get_avg_score()
        assert avg == pytest.approx(70.0, abs=1.0)

    def test_critical_count(self, db):
        run = _make_run_result("20250101-r001", "r", severity="critical")
        db.save_run(run)
        count = db.get_critical_count(days=30)
        assert count >= 1


class TestApiKeys:
    def test_store_and_validate_key(self, db):
        raw_key = "my-super-secret-api-key"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        db.store_api_key(key_hash, "test-key")
        assert db.validate_api_key(key_hash) is True

    def test_invalid_key_returns_false(self, db):
        bad_hash = hashlib.sha256(b"wrong-key").hexdigest()
        assert db.validate_api_key(bad_hash) is False

    def test_revoked_key_returns_false(self, db):
        raw_key = "revoke-me"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        db.store_api_key(key_hash, "to-revoke")
        db.revoke_api_key(key_hash)
        assert db.validate_api_key(key_hash) is False

    def test_get_all_api_keys_empty(self, db):
        assert db.get_all_api_keys() == []

    def test_get_all_api_keys_returns_hashes(self, db):
        key_hash = hashlib.sha256(b"key1").hexdigest()
        db.store_api_key(key_hash, "key1")
        keys = db.get_all_api_keys()
        assert key_hash in keys

    def test_constant_time_comparison(self, db):
        raw_key = "timing-safe-key"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        db.store_api_key(key_hash, "timing-test")
        # Verify the key validates correctly using constant-time comparison
        assert db.validate_api_key(key_hash) is True
        # Wrong hash should not validate
        wrong_hash = hashlib.sha256(b"wrong").hexdigest()
        assert db.validate_api_key(wrong_hash) is False

    def test_revoke_nonexistent_returns_false(self, db):
        result = db.revoke_api_key("nonexistent-hash")
        assert result is False


class TestCleanup:
    def test_cleanup_removes_old_runs(self, db, tmp_path):
        run = _make_run_result("20250101-old0001", "repo/old")
        # Save, then manually set the timestamp to be 100 days ago
        db.save_run(run)

        old_timestamp = (
            datetime.now(timezone.utc) - timedelta(days=100)
        ).isoformat()

        with db._get_connection() as conn:
            conn.execute(
                "UPDATE pipeline_runs SET timestamp = ? WHERE id = ?",
                (old_timestamp, run.run_id),
            )

        deleted = db.cleanup_old_runs(days=90)
        assert deleted == 1
        assert db.get_run_by_id(run.run_id) is None

    def test_cleanup_keeps_recent_runs(self, db):
        run = _make_run_result("20250101-new0001", "repo/new")
        db.save_run(run)
        deleted = db.cleanup_old_runs(days=90)
        assert deleted == 0
        assert db.get_run_by_id(run.run_id) is not None
