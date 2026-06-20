"""Tests for Gate 4: License Compliance Checker"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from engine.models import Finding, GateResult
from gates.gate4_license import LicenseGate


class TestLicenseGateInstantiation:
    """Test that the LicenseGate can be instantiated."""

    def test_can_instantiate_with_defaults(self):
        gate = LicenseGate()
        assert gate is not None
        assert gate.name == "license"

    def test_can_instantiate_with_config(self, config):
        gate = LicenseGate(config=config)
        assert gate.name == "license"

    def test_gate_description_is_set(self):
        gate = LicenseGate()
        assert gate.description
        assert "license" in gate.description.lower()

    def test_severity_map_is_populated(self):
        gate = LicenseGate()
        severity_map = gate.get_severity_map()
        assert isinstance(severity_map, dict)
        assert "license-copyleft-critical" in severity_map
        assert "license-copyleft-high" in severity_map
        assert "license-unknown" in severity_map


class TestLicenseGateAgainstVulnerableRepo:
    """Test LicenseGate against the vulnerable test fixture repo."""

    def test_scans_dependencies(self, vulnerable_repo_path):
        gate = LicenseGate()
        result = gate.run(vulnerable_repo_path)
        assert isinstance(result, GateResult)
        assert result.gate_name == "license"

    def test_finds_licenses_in_metadata(self, vulnerable_repo_path):
        gate = LicenseGate()
        result = gate.run(vulnerable_repo_path)
        assert "license_inventory" in result.metadata
        inventory = result.metadata["license_inventory"]
        assert isinstance(inventory, dict)

    def test_total_packages_in_metadata(self, vulnerable_repo_path):
        gate = LicenseGate()
        result = gate.run(vulnerable_repo_path)
        assert "total_packages" in result.metadata
        assert result.metadata["total_packages"] > 0

    def test_files_scanned_count(self, vulnerable_repo_path):
        gate = LicenseGate()
        result = gate.run(vulnerable_repo_path)
        assert result.files_scanned > 0

    def test_finding_type_is_compliance(self, vulnerable_repo_path):
        gate = LicenseGate()
        result = gate.run(vulnerable_repo_path)
        for finding in result.findings:
            assert finding.finding_type == "compliance"

    def test_findings_have_valid_severity(self, vulnerable_repo_path):
        gate = LicenseGate()
        result = gate.run(vulnerable_repo_path)
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for finding in result.findings:
            assert finding.severity in valid_severities


class TestLicenseGateAgainstFixedRepo:
    """Test LicenseGate against the fixed test fixture repo."""

    def test_scans_fixed_repo(self, fixed_repo_path):
        gate = LicenseGate()
        result = gate.run(fixed_repo_path)
        assert isinstance(result, GateResult)
        assert result.gate_name == "license"

    def test_metadata_includes_inventory(self, fixed_repo_path):
        gate = LicenseGate()
        result = gate.run(fixed_repo_path)
        assert "license_inventory" in result.metadata


class TestLicenseGateErrorHandling:
    """Test LicenseGate error handling."""

    def test_handles_nonexistent_path(self):
        gate = LicenseGate()
        result = gate.run("/nonexistent/path/that/does/not/exist")
        assert isinstance(result, GateResult)
        assert result.gate_name == "license"
        assert result.status in ("pass", "fail", "error")

    def test_handles_empty_directory(self):
        gate = LicenseGate()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = gate.run(tmpdir)
            assert isinstance(result, GateResult)
            assert result.gate_name == "license"
            assert result.findings_count == 0

    def test_handles_no_dependency_files(self):
        gate = LicenseGate()
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "README.md").write_text("# Hello")
            result = gate.run(tmpdir)
            assert isinstance(result, GateResult)
            assert result.files_scanned == 0

    def test_returns_proper_gate_result_structure(self, vulnerable_repo_path):
        gate = LicenseGate()
        result = gate.run(vulnerable_repo_path)
        assert result.gate_name == "license"
        assert isinstance(result.findings, list)
        assert isinstance(result.duration_ms, int)
        assert isinstance(result.metadata, dict)

    def test_handles_malformed_requirements(self):
        gate = LicenseGate()
        with tempfile.TemporaryDirectory() as tmpdir:
            req_path = Path(tmpdir) / "requirements.txt"
            req_path.write_text("!!!invalid package!!!\n")
            result = gate.run(tmpdir)
            assert isinstance(result, GateResult)
            # Should not crash
