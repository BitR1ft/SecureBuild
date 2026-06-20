"""SecureBuild CI/CD Security Gate - Pytest Configuration"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

from engine.config import SecureBuildConfig
from engine.db import DatabaseManager
from engine.models import Finding, GateResult, RunResult, RiskScore


@pytest.fixture
def vulnerable_repo_path() -> str:
    return str(Path(__file__).parent / "fixtures" / "vulnerable_repo")


@pytest.fixture
def fixed_repo_path() -> str:
    return str(Path(__file__).parent / "fixtures" / "demo_fixed_app")


@pytest.fixture
def temp_repo():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Initialize a git repo
        subprocess.run(
            ["git", "init"], cwd=tmpdir, capture_output=True
        )
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=tmpdir,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=tmpdir,
            capture_output=True,
        )
        yield tmpdir


@pytest.fixture
def mock_nvd_response() -> Dict[str, Any]:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-32681",
                    "descriptions": [
                        {"value": "Unintended leak of Proxy-Authorization header"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 7.5,
                                    "vectorString": (
                                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                                        "S:U/C:H/I:N/A:N"
                                    ),
                                }
                            }
                        ]
                    },
                }
            }
        ]
    }


@pytest.fixture
def sample_findings() -> List[Finding]:
    return [
        Finding(
            gate="secrets",
            file="app.py",
            line=12,
            message="AWS Access Key detected",
            cvss_score=9.1,
            severity="critical",
            rule_id="secrets-aws-access-key",
            cwe_id="CWE-798",
            finding_type="secret",
            confidence="high",
        ),
        Finding(
            gate="secrets",
            file="app.py",
            line=14,
            message="Hardcoded Password detected",
            cvss_score=7.5,
            severity="high",
            rule_id="secrets-password",
            cwe_id="CWE-798",
            finding_type="secret",
            confidence="high",
        ),
        Finding(
            gate="sast",
            file="app.py",
            line=22,
            message="SQL query with string formatting - potential SQL injection",
            cvss_score=8.1,
            severity="high",
            rule_id="sast-sql-injection",
            cwe_id="CWE-89",
            finding_type="vulnerability",
            confidence="high",
        ),
        Finding(
            gate="sast",
            file="app.py",
            line=29,
            message="subprocess call with shell=True - OS command injection risk",
            cvss_score=9.1,
            severity="critical",
            rule_id="sast-shell-true",
            cwe_id="CWE-78",
            finding_type="vulnerability",
            confidence="high",
        ),
        Finding(
            gate="sast",
            file="app.py",
            line=35,
            message="Use of eval() detected - potential code injection",
            cvss_score=9.8,
            severity="critical",
            rule_id="sast-eval-usage",
            cwe_id="CWE-95",
            finding_type="vulnerability",
            confidence="high",
        ),
        Finding(
            gate="cve",
            file="requirements.txt",
            line=0,
            message="CVE-2023-32681: Unintended leak in requests==2.18.0",
            cvss_score=7.5,
            severity="high",
            rule_id="cve-known-vulnerability",
            cwe_id="CWE-200",
            finding_type="dependency",
            confidence="high",
        ),
        Finding(
            gate="iac",
            file="Dockerfile",
            line=0,
            message="No USER instruction found",
            cvss_score=9.8,
            severity="critical",
            rule_id="docker-root-user",
            cwe_id="CWE-1032",
            finding_type="misconfiguration",
            confidence="high",
        ),
        Finding(
            gate="iac",
            file="docker-compose.yml",
            line=0,
            message="Service has privileged: true",
            cvss_score=9.8,
            severity="critical",
            rule_id="docker-privileged",
            cwe_id="CWE-1032",
            finding_type="misconfiguration",
            confidence="high",
        ),
    ]


@pytest.fixture
def sample_gate_result(sample_findings) -> GateResult:
    return GateResult(
        gate_name="secrets",
        status="fail",
        findings=sample_findings[:2],
        duration_ms=150,
        files_scanned=10,
        files_skipped=2,
    )


@pytest.fixture
def sample_run_result(sample_findings) -> RunResult:
    secrets_findings = [f for f in sample_findings if f.gate == "secrets"]
    sast_findings = [f for f in sample_findings if f.gate == "sast"]
    cve_findings = [f for f in sample_findings if f.gate == "cve"]
    iac_findings = [f for f in sample_findings if f.gate == "iac"]

    return RunResult(
        run_id="20250510-a3f2c1d4",
        repo="test/vulnerable-app",
        branch="main",
        commit_hash="abc123def456789012345678901234567890abcd",
        timestamp="2025-05-10T14:30:00Z",
        overall_score=35.0,
        status="fail",
        gate_results=[
            GateResult(
                gate_name="secrets",
                status="fail",
                findings=secrets_findings,
                duration_ms=150,
                files_scanned=10,
            ),
            GateResult(
                gate_name="sast",
                status="fail",
                findings=sast_findings,
                duration_ms=300,
                files_scanned=8,
            ),
            GateResult(
                gate_name="cve",
                status="fail",
                findings=cve_findings,
                duration_ms=100,
                files_scanned=2,
            ),
            GateResult(
                gate_name="iac",
                status="fail",
                findings=iac_findings,
                duration_ms=50,
                files_scanned=3,
            ),
        ],
        risk_score=RiskScore(
            overall=65.0,
            by_gate={"secrets": 70.0, "sast": 80.0, "cve": 40.0, "iac": 70.0},
            by_severity={"critical": 3, "high": 2},
            recommendation="Address critical and high findings before merging.",
            trend="new",
        ),
        duration_ms=600,
    )


@pytest.fixture
def db_manager():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        manager = DatabaseManager(db_path)
        yield manager


@pytest.fixture
def config() -> SecureBuildConfig:
    return SecureBuildConfig()
