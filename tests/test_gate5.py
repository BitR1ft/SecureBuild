"""Tests for Gate 5: Infrastructure-as-Code Security"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from engine.models import Finding, GateResult
from gates.gate5_iac import IACGate


class TestIACGateInstantiation:
    """Test that the IACGate can be instantiated."""

    def test_can_instantiate_with_defaults(self):
        gate = IACGate()
        assert gate is not None
        assert gate.name == "iac"

    def test_can_instantiate_with_config(self, config):
        gate = IACGate(config=config)
        assert gate.name == "iac"

    def test_gate_description_is_set(self):
        gate = IACGate()
        assert gate.description
        assert "iac" in gate.description.lower() or "infrastructure" in gate.description.lower()

    def test_severity_map_is_populated(self):
        gate = IACGate()
        severity_map = gate.get_severity_map()
        assert isinstance(severity_map, dict)
        assert "docker-root-user" in severity_map
        assert "docker-privileged" in severity_map


class TestIACGateAgainstVulnerableRepo:
    """Test IACGate against the vulnerable test fixture repo."""

    def test_finds_misconfigurations(self, vulnerable_repo_path):
        gate = IACGate()
        result = gate.run(vulnerable_repo_path)
        assert isinstance(result, GateResult)
        assert result.gate_name == "iac"
        assert result.findings_count > 0

    def test_finds_running_as_root(self, vulnerable_repo_path):
        gate = IACGate()
        result = gate.run(vulnerable_repo_path)
        root_findings = [
            f for f in result.findings
            if f.rule_id == "docker-root-user"
        ]
        assert len(root_findings) > 0

    def test_finds_privileged_mode(self, vulnerable_repo_path):
        gate = IACGate()
        result = gate.run(vulnerable_repo_path)
        priv_findings = [
            f for f in result.findings
            if f.rule_id == "docker-privileged"
        ]
        assert len(priv_findings) > 0

    def test_finds_host_network(self, vulnerable_repo_path):
        gate = IACGate()
        result = gate.run(vulnerable_repo_path)
        network_findings = [
            f for f in result.findings
            if f.rule_id == "docker-host-network"
        ]
        assert len(network_findings) > 0

    def test_finds_docker_socket_mount(self, vulnerable_repo_path):
        gate = IACGate()
        result = gate.run(vulnerable_repo_path)
        socket_findings = [
            f for f in result.findings
            if f.rule_id == "docker-socket-mount"
        ]
        assert len(socket_findings) > 0

    def test_finds_latest_tag(self, vulnerable_repo_path):
        gate = IACGate()
        result = gate.run(vulnerable_repo_path)
        latest_findings = [
            f for f in result.findings
            if f.rule_id == "docker-latest-tag"
        ]
        assert len(latest_findings) > 0

    def test_finds_ssh_exposed(self, vulnerable_repo_path):
        gate = IACGate()
        result = gate.run(vulnerable_repo_path)
        ssh_findings = [
            f for f in result.findings
            if f.rule_id == "docker-expose-ssh"
        ]
        assert len(ssh_findings) > 0

    def test_finding_type_is_misconfiguration(self, vulnerable_repo_path):
        gate = IACGate()
        result = gate.run(vulnerable_repo_path)
        for finding in result.findings:
            assert finding.finding_type == "misconfiguration"

    def test_hardcoded_env_secrets(self, vulnerable_repo_path):
        gate = IACGate()
        result = gate.run(vulnerable_repo_path)
        env_secret_findings = [
            f for f in result.findings
            if f.rule_id == "docker-hardcoded-env-secret"
        ]
        assert len(env_secret_findings) > 0


class TestIACGateAgainstFixedRepo:
    """Test IACGate against the fixed (secure) test fixture repo."""

    def test_fewer_findings_than_vulnerable(self, vulnerable_repo_path, fixed_repo_path):
        gate = IACGate()
        vuln_result = gate.run(vulnerable_repo_path)
        fixed_result = gate.run(fixed_repo_path)
        assert fixed_result.findings_count < vuln_result.findings_count

    def test_no_privileged_mode(self, fixed_repo_path):
        gate = IACGate()
        result = gate.run(fixed_repo_path)
        priv_findings = [
            f for f in result.findings
            if f.rule_id == "docker-privileged"
        ]
        assert len(priv_findings) == 0

    def test_no_host_network(self, fixed_repo_path):
        gate = IACGate()
        result = gate.run(fixed_repo_path)
        network_findings = [
            f for f in result.findings
            if f.rule_id == "docker-host-network"
        ]
        assert len(network_findings) == 0

    def test_has_user_instruction(self, fixed_repo_path):
        gate = IACGate()
        result = gate.run(fixed_repo_path)
        root_findings = [
            f for f in result.findings
            if f.rule_id == "docker-root-user"
        ]
        assert len(root_findings) == 0


class TestIACGateErrorHandling:
    """Test IACGate error handling."""

    def test_handles_nonexistent_path(self):
        gate = IACGate()
        result = gate.run("/nonexistent/path/that/does/not/exist")
        assert isinstance(result, GateResult)
        assert result.gate_name == "iac"
        assert result.status in ("pass", "fail", "error")

    def test_handles_empty_directory(self):
        gate = IACGate()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = gate.run(tmpdir)
            assert isinstance(result, GateResult)
            assert result.gate_name == "iac"
            assert result.findings_count == 0

    def test_handles_no_iac_files(self):
        gate = IACGate()
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "main.py").write_text("print('hello')")
            result = gate.run(tmpdir)
            assert isinstance(result, GateResult)
            assert result.findings_count == 0

    def test_returns_proper_gate_result_structure(self, vulnerable_repo_path):
        gate = IACGate()
        result = gate.run(vulnerable_repo_path)
        assert result.gate_name == "iac"
        assert isinstance(result.findings, list)
        assert isinstance(result.duration_ms, int)
        assert isinstance(result.files_scanned, int)
        assert isinstance(result.metadata, dict)
        assert "iac_files" in result.metadata

    def test_handles_malformed_dockerfile(self):
        gate = IACGate()
        with tempfile.TemporaryDirectory() as tmpdir:
            dockerfile_path = Path(tmpdir) / "Dockerfile"
            dockerfile_path.write_text("this is not a valid dockerfile !!!\n")
            result = gate.run(tmpdir)
            assert isinstance(result, GateResult)
            # Should not crash
