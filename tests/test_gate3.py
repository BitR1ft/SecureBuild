"""Tests for Gate 3: CVE / Dependency Vulnerability Audit"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from engine.models import Finding, GateResult
from gates.gate3_cve import CVEGate


class TestCVEGateInstantiation:
    """Test that the CVEGate can be instantiated."""

    def test_can_instantiate_with_defaults(self):
        gate = CVEGate()
        assert gate is not None
        assert gate.name == "cve"

    def test_can_instantiate_with_config(self, config):
        gate = CVEGate(config=config)
        assert gate.name == "cve"

    def test_gate_description_is_set(self):
        gate = CVEGate()
        assert gate.description
        assert "depend" in gate.description.lower() or "cve" in gate.description.lower()

    def test_severity_map_is_populated(self):
        gate = CVEGate()
        severity_map = gate.get_severity_map()
        assert isinstance(severity_map, dict)
        assert "cve-known-vulnerability" in severity_map


class TestCVEGateAgainstVulnerableRepo:
    """Test CVEGate against the vulnerable test fixture repo."""

    def test_finds_vulnerable_dependencies(self, vulnerable_repo_path):
        gate = CVEGate()
        result = gate.run(vulnerable_repo_path)
        assert isinstance(result, GateResult)
        assert result.gate_name == "cve"
        assert result.findings_count > 0

    def test_finds_vulnerable_requests(self, vulnerable_repo_path):
        gate = CVEGate()
        result = gate.run(vulnerable_repo_path)
        requests_findings = [
            f for f in result.findings
            if "requests" in f.message.lower()
        ]
        assert len(requests_findings) > 0

    def test_finds_vulnerable_django(self, vulnerable_repo_path):
        gate = CVEGate()
        result = gate.run(vulnerable_repo_path)
        django_findings = [
            f for f in result.findings
            if "django" in f.message.lower()
        ]
        assert len(django_findings) > 0

    def test_finds_vulnerable_pyyaml(self, vulnerable_repo_path):
        gate = CVEGate()
        result = gate.run(vulnerable_repo_path)
        yaml_findings = [
            f for f in result.findings
            if "pyyaml" in f.message.lower() or "yaml" in f.message.lower()
        ]
        assert len(yaml_findings) > 0

    def test_finds_vulnerable_flask(self, vulnerable_repo_path):
        gate = CVEGate()
        result = gate.run(vulnerable_repo_path)
        flask_findings = [
            f for f in result.findings
            if "flask" in f.message.lower()
        ]
        assert len(flask_findings) > 0

    def test_dependency_findings_have_fix_suggestion(self, vulnerable_repo_path):
        gate = CVEGate()
        result = gate.run(vulnerable_repo_path)
        dep_findings = [
            f for f in result.findings
            if f.finding_type == "dependency"
        ]
        for finding in dep_findings:
            assert finding.fix_suggestion, (
                f"Finding {finding.rule_id} missing fix_suggestion"
            )

    def test_metadata_includes_package_counts(self, vulnerable_repo_path):
        gate = CVEGate()
        result = gate.run(vulnerable_repo_path)
        assert "python_packages" in result.metadata
        assert isinstance(result.metadata["python_packages"], int)


class TestCVEGateAgainstFixedRepo:
    """Test CVEGate against the fixed (secure) test fixture repo."""

    def test_fewer_findings_than_vulnerable(self, vulnerable_repo_path, fixed_repo_path):
        gate = CVEGate()
        vuln_result = gate.run(vulnerable_repo_path)
        fixed_result = gate.run(fixed_repo_path)
        assert fixed_result.findings_count < vuln_result.findings_count

    def test_no_critical_cve_findings(self, fixed_repo_path):
        gate = CVEGate()
        result = gate.run(fixed_repo_path)
        critical_cve = [
            f for f in result.findings
            if f.rule_id == "cve-known-vulnerability" and f.severity == "critical"
        ]
        assert len(critical_cve) == 0


class TestCVEGateErrorHandling:
    """Test CVEGate error handling."""

    def test_handles_nonexistent_path(self):
        gate = CVEGate()
        result = gate.run("/nonexistent/path/that/does/not/exist")
        assert isinstance(result, GateResult)
        assert result.gate_name == "cve"
        assert result.status in ("pass", "fail", "error")

    def test_handles_empty_directory(self):
        gate = CVEGate()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = gate.run(tmpdir)
            assert isinstance(result, GateResult)
            assert result.gate_name == "cve"
            assert result.findings_count == 0

    def test_handles_no_requirements_file(self):
        gate = CVEGate()
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a Python file but no requirements.txt
            (Path(tmpdir) / "main.py").write_text("print('hello')")
            result = gate.run(tmpdir)
            assert isinstance(result, GateResult)
            assert result.gate_name == "cve"

    def test_returns_proper_gate_result_structure(self, vulnerable_repo_path):
        gate = CVEGate()
        result = gate.run(vulnerable_repo_path)
        assert result.gate_name == "cve"
        assert isinstance(result.findings, list)
        assert isinstance(result.duration_ms, int)
        assert isinstance(result.files_scanned, int)
        assert isinstance(result.metadata, dict)
