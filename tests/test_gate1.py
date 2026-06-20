"""Tests for Gate 1: Secrets & Credential Scanner"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from engine.models import Finding, GateResult
from gates.gate1_secrets import SecretsGate


class TestSecretsGateInstantiation:
    """Test that the SecretsGate can be instantiated."""

    def test_can_instantiate_with_defaults(self):
        gate = SecretsGate()
        assert gate is not None
        assert gate.name == "secrets"

    def test_can_instantiate_with_config(self, config):
        gate = SecretsGate(config=config)
        assert gate.name == "secrets"

    def test_gate_description_is_set(self):
        gate = SecretsGate()
        assert gate.description
        assert "secret" in gate.description.lower()

    def test_severity_map_is_populated(self):
        gate = SecretsGate()
        severity_map = gate.get_severity_map()
        assert isinstance(severity_map, dict)
        assert len(severity_map) > 0


class TestSecretsGateAgainstVulnerableRepo:
    """Test SecretsGate against the vulnerable test fixture repo."""

    def test_finds_hardcoded_secrets(self, vulnerable_repo_path):
        gate = SecretsGate()
        result = gate.run(vulnerable_repo_path)
        assert isinstance(result, GateResult)
        assert result.gate_name == "secrets"
        assert result.findings_count > 0

    def test_finds_aws_access_key(self, vulnerable_repo_path):
        gate = SecretsGate()
        result = gate.run(vulnerable_repo_path)
        aws_findings = [
            f for f in result.findings
            if "aws" in f.rule_id.lower() or "AKIA" in f.message
        ]
        assert len(aws_findings) > 0

    def test_finds_hardcoded_password(self, vulnerable_repo_path):
        gate = SecretsGate()
        result = gate.run(vulnerable_repo_path)
        password_findings = [
            f for f in result.findings
            if "password" in f.rule_id.lower()
        ]
        assert len(password_findings) > 0

    def test_finds_private_key(self, vulnerable_repo_path):
        gate = SecretsGate()
        result = gate.run(vulnerable_repo_path)
        key_findings = [
            f for f in result.findings
            if "private" in f.rule_id.lower() or "PRIVATE KEY" in f.message
        ]
        assert len(key_findings) > 0

    def test_finds_env_credentials(self, vulnerable_repo_path):
        gate = SecretsGate()
        result = gate.run(vulnerable_repo_path)
        env_findings = [
            f for f in result.findings
            if ".env" in f.file
        ]
        assert len(env_findings) > 0

    def test_findings_have_correct_finding_type(self, vulnerable_repo_path):
        gate = SecretsGate()
        result = gate.run(vulnerable_repo_path)
        for finding in result.findings:
            assert finding.finding_type == "secret"

    def test_findings_have_severity_set(self, vulnerable_repo_path):
        gate = SecretsGate()
        result = gate.run(vulnerable_repo_path)
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for finding in result.findings:
            assert finding.severity in valid_severities


class TestSecretsGateAgainstFixedRepo:
    """Test SecretsGate against the fixed (secure) test fixture repo."""

    def test_fewer_findings_than_vulnerable(self, vulnerable_repo_path, fixed_repo_path):
        gate = SecretsGate()
        vuln_result = gate.run(vulnerable_repo_path)
        fixed_result = gate.run(fixed_repo_path)
        assert fixed_result.findings_count < vuln_result.findings_count

    def test_no_hardcoded_passwords(self, fixed_repo_path):
        gate = SecretsGate()
        result = gate.run(fixed_repo_path)
        password_findings = [
            f for f in result.findings
            if "password" in f.rule_id.lower() and "hardcoded" in f.message.lower()
        ]
        assert len(password_findings) == 0


class TestSecretsGateErrorHandling:
    """Test SecretsGate error handling."""

    def test_handles_nonexistent_path(self):
        gate = SecretsGate()
        result = gate.run("/nonexistent/path/that/does/not/exist")
        assert isinstance(result, GateResult)
        assert result.gate_name == "secrets"
        # Should not crash, may have error status or empty findings
        assert result.status in ("pass", "fail", "error")

    def test_handles_empty_directory(self):
        gate = SecretsGate()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = gate.run(tmpdir)
            assert isinstance(result, GateResult)
            assert result.gate_name == "secrets"
            assert result.findings_count == 0
            assert result.status == "pass"

    def test_returns_proper_gate_result_structure(self, vulnerable_repo_path):
        gate = SecretsGate()
        result = gate.run(vulnerable_repo_path)
        assert result.gate_name == "secrets"
        assert isinstance(result.findings, list)
        assert isinstance(result.duration_ms, int)
        assert isinstance(result.files_scanned, int)
        assert isinstance(result.files_skipped, int)
        assert isinstance(result.metadata, dict)

    def test_findings_are_finding_instances(self, vulnerable_repo_path):
        gate = SecretsGate()
        result = gate.run(vulnerable_repo_path)
        for finding in result.findings:
            assert isinstance(finding, Finding)
            assert finding.gate == "secrets"
