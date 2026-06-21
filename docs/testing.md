# Testing Documentation

> SecureBuild CI/CD Security Gate — Test Strategy and Execution Guide

This document describes the testing strategy, test structure, how to run tests, and how to interpret coverage reports for the SecureBuild project.

---

## Table of Contents

- [Test Strategy](#test-strategy)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Test Coverage](#test-coverage)
- [Test Fixtures](#test-fixtures)
- [Writing New Tests](#writing-new-tests)
- [Continuous Integration](#continuous-integration)

---

## Test Strategy

SecureBuild uses a layered testing approach that covers the full stack from individual gate logic to end-to-end pipeline execution:

### Test Pyramid

| Layer | Scope | Count | Purpose |
|---|---|---|---|
| **Unit Tests** | Individual gates, scoring functions, utilities | ~70 | Verify correctness of isolated components |
| **Integration Tests** | Orchestrator, database, reporter | ~15 | Verify components work together correctly |
| **End-to-End Tests** | Full pipeline (scan → score → report) | ~5 | Verify the complete workflow |

### Testing Principles

1. **Idempotent**: Tests produce the same results regardless of execution order or environment
2. **Isolated**: Each test creates its own temporary directory and database — no shared state
3. **Deterministic**: No reliance on external services, network calls, or random timing
4. **Fast**: The full test suite completes in under 30 seconds
5. **Comprehensive**: Every gate, scoring path, and error handling branch is tested

---

## Test Structure

```
tests/
├── __init__.py              # Package marker
├── conftest.py              # Shared fixtures (pytest)
├── test_gate1.py            # Secrets & Credential Scanner tests
├── test_gate2.py            # SAST Gate tests
├── test_gate3.py            # Dependency CVE Audit tests
├── test_gate4.py            # License Compliance Checker tests
├── test_gate5.py            # IaC Security Gate tests
└── fixtures/
    ├── vulnerable_repo/     # Repository with intentional vulnerabilities
    │   ├── app.py           # Code with eval(), SQL injection, hardcoded secrets
    │   ├── Dockerfile       # Runs as root, :latest tag, no HEALTHCHECK
    │   ├── docker-compose.yml  # Privileged container, Docker socket mount
    │   ├── requirements.txt # Vulnerable dependency versions
    │   └── deploy_key.pem  # Fake private key for detection testing
    └── demo_fixed_app/      # Repository with security best practices
        ├── app.py           # Secure code patterns
        ├── Dockerfile       # Non-root user, pinned tags, HEALTHCHECK
        ├── docker-compose.yml  # Resource limits, no privileged mode
        └── requirements.txt # Updated dependency versions
```

### Test Files

#### `conftest.py`

Shared pytest fixtures used across test files:

- `tmp_repo` — Creates a temporary repository directory with sample files
- `config` — Provides a default `SecureBuildConfig` instance
- `db_manager` — Creates an in-memory `DatabaseManager` for testing
- `vulnerable_repo` — Path to the `fixtures/vulnerable_repo` test fixture
- `fixed_repo` — Path to the `fixtures/demo_fixed_app` test fixture

#### `test_gate1.py` — Secrets Gate Tests

Tests for the Secrets & Credential Scanner:

| Test | Description |
|---|---|
| `test_detect_aws_access_key` | Verifies detection of `AKIA` prefix keys |
| `test_detect_aws_secret_key` | Verifies detection of AWS_SECRET_ACCESS_KEY assignments |
| `test_detect_github_pat` | Verifies detection of `ghp_` tokens |
| `test_detect_stripe_key` | Verifies detection of `sk_live_` keys |
| `test_detect_jwt_token` | Verifies detection of `eyJ` JWT format |
| `test_detect_private_key` | Verifies detection of PEM private key headers |
| `test_detect_hardcoded_password` | Verifies detection of `password=` assignments |
| `test_detect_api_key` | Verifies detection of `api_key=` assignments |
| `test_detect_generic_secret` | Verifies detection of `secret=` assignments |
| `test_detect_high_entropy` | Verifies entropy-based detection of random strings |
| `test_nosec_suppression` | Verifies `# nosec` comments suppress findings |
| `test_env_file_deep_scan` | Verifies .env file credential detection |
| `test_exclude_paths` | Verifies excluded paths are not scanned |
| `test_binary_file_skip` | Verifies binary files are skipped |
| `test_mask_credential` | Verifies credential masking in output |

#### `test_gate2.py` — SAST Gate Tests

Tests for the Static Application Security Testing gate:

| Test | Description |
|---|---|
| `test_detect_eval_usage` | Verifies detection of `eval()` calls |
| `test_detect_exec_usage` | Verifies detection of `exec()` calls |
| `test_detect_shell_injection` | Verifies detection of `subprocess.call(shell=True)` |
| `test_detect_sql_injection` | Verifies detection of SQL string formatting |
| `test_detect_insecure_deserialization` | Verifies detection of `pickle.loads()` |
| `test_detect_yaml_unsafe_load` | Verifies detection of `yaml.load()` without Loader |
| `test_detect_weak_hash` | Verifies detection of MD5/SHA1 usage |
| `test_detect_assert_security` | Verifies detection of assert for security checks |
| `test_detect_tempfile_mktemp` | Verifies detection of `tempfile.mktemp()` |
| `test_exclude_migrations` | Verifies migration files are excluded |
| `test_exclude_tests` | Verifies test directories are excluded |

#### `test_gate3.py` — CVE Gate Tests

Tests for the Dependency CVE Audit gate:

| Test | Description |
|---|---|
| `test_parse_requirements_txt` | Verifies requirements.txt parsing |
| `test_parse_package_json` | Verifies package.json parsing |
| `test_detect_known_cve` | Verifies CVE lookup against built-in database |
| `test_staleness_check` | Verifies detection of stale dependencies |
| `test_upgrade_suggestion` | Verifies upgrade version suggestions |
| `test_no_version_pin` | Verifies detection of unversioned dependencies |
| `test_empty_requirements` | Verifies handling of empty dependency files |

#### `test_gate4.py` — License Gate Tests

Tests for the License Compliance Checker gate:

| Test | Description |
|---|---|
| `test_detect_blocked_license` | Verifies detection of AGPL-3.0 in blocked list |
| `test_allow_permissive` | Verifies MIT/Apache-2.0 pass compliance check |
| `test_copyleft_in_commercial` | Verifies GPL detection in commercial project mode |
| `test_unknown_license` | Verifies handling of unrecognized license identifiers |
| `test_custom_allowed_list` | Verifies custom allowed_licenses configuration |
| `test_spdx_normalization` | Verifies SPDX license identifier normalization |

#### `test_gate5.py` — IaC Gate Tests

Tests for the Infrastructure-as-Code Security gate:

| Test | Description |
|---|---|
| `test_docker_root_user` | Verifies detection of running as root in Dockerfile |
| `test_docker_latest_tag` | Verifies detection of `:latest` base image tag |
| `test_docker_no_healthcheck` | Verifies detection of missing HEALTHCHECK |
| `test_docker_sensitive_port` | Verifies detection of exposed sensitive ports |
| `test_compose_privileged` | Verifies detection of privileged mode in compose |
| `test_compose_docker_socket` | Verifies detection of Docker socket mount |
| `test_compose_no_limits` | Verifies detection of missing resource limits |
| `test_k8s_privileged` | Verifies detection of privileged K8s containers |
| `test_k8s_hostpath` | Verifies detection of hostPath mounts |
| `test_k8s_no_security_context` | Verifies detection of missing securityContext |
| `test_gha_untrusted_checkout` | Verifies detection of untrusted checkout in GHA |
| `test_gha_script_injection` | Verifies detection of script injection in GHA |

---

## Running Tests

### Prerequisites

```bash
pip install pytest pytest-cov
```

### Run All Tests

```bash
pytest tests/ -v
```

### Run Specific Test File

```bash
pytest tests/test_gate1.py -v
```

### Run Specific Test

```bash
pytest tests/test_gate1.py::test_detect_aws_access_key -v
```

### Run with Coverage Report

```bash
pytest tests/ --cov=. --cov-report=term-missing
```

### Run with HTML Coverage Report

```bash
pytest tests/ --cov=. --cov-report=html
# Open htmlcov/index.html in a browser
```

### Run with Verbose Output

```bash
pytest tests/ -v -s
```

The `-s` flag disables output capturing, allowing `print()` statements to display.

### Run Only Unit Tests

```bash
pytest tests/ -v -k "not integration"
```

### Run Only Integration Tests

```bash
pytest tests/ -v -k "integration"
```

### Run with Timing Information

```bash
pytest tests/ -v --durations=10
```

---

## Test Coverage

### Coverage Targets

| Component | Target | Current |
|---|---|---|
| `gates/` | 85% | ~88% |
| `scoring/` | 90% | ~92% |
| `engine/` | 80% | ~82% |
| `dashboard/` | 60% | ~55% |
| Overall | 80% | ~82% |

### Coverage Exclusions

The following are excluded from coverage requirements:

- `cli.py` — CLI entry point (tested manually and via integration tests)
- `dashboard/templates/` — HTML templates (tested via dashboard route tests)
- `reporter/templates/` — Report templates (tested via report generation)
- Type checking and validation code with trivial branches

### Generating Coverage Reports

```bash
# Terminal report with missing lines
pytest tests/ --cov=. --cov-report=term-missing

# HTML report (detailed, line-by-line)
pytest tests/ --cov=. --cov-report=html

# XML report (for CI tools)
pytest tests/ --cov=. --cov-report=xml

# Multiple formats
pytest tests/ --cov=. --cov-report=html --cov-report=term-missing
```

---

## Test Fixtures

### `vulnerable_repo/`

A deliberately vulnerable repository used for positive test cases. Contains:

- **`app.py`**: Python code with `eval()`, SQL injection via f-strings, hardcoded passwords, `pickle.loads()`, `subprocess.call(shell=True)`, and weak hashing
- **`Dockerfile`**: Runs as root, uses `python:latest`, exposes port 22, no HEALTHCHECK, uses ADD instead of COPY
- **`docker-compose.yml`**: Privileged container, host network mode, mounted Docker socket, no resource limits
- **`requirements.txt`**: Vulnerable versions of Flask, Requests, and PyYAML
- **`deploy_key.pem`**: Fake private key file for testing secret detection

### `demo_fixed_app/`

A security-hardened repository used for negative test cases. Contains:

- **`app.py`**: Secure code using parameterized queries, environment variables for secrets, `yaml.safe_load()`, and `subprocess.run()` without `shell=True`
- **`Dockerfile`**: Non-root user, pinned version tag, HEALTHCHECK instruction, COPY instead of ADD
- **`docker-compose.yml`**: Resource limits, no privileged mode, no Docker socket mount
- **`requirements.txt`**: Updated, secure versions of all dependencies

---

## Writing New Tests

### Test Template

```python
"""Tests for [component name]."""

import pytest
from pathlib import Path
from gates.base import BaseGate
from engine.config import SecureBuildConfig


class TestYourFeature:
    """Test suite for [feature]."""

    @pytest.fixture
    def config(self):
        """Provide a test configuration."""
        return SecureBuildConfig()

    @pytest.fixture
    def tmp_repo(self, tmp_path):
        """Create a temporary repository with test files."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "app.py").write_text("# test code")
        return str(repo)

    def test_basic_functionality(self, config, tmp_repo):
        """Test that [feature] works correctly."""
        gate = YourGate(config=config)
        result = gate.run(tmp_repo)
        assert result.status == "pass"
        assert result.findings_count == 0

    def test_finding_detection(self, config, tmp_repo):
        """Test that [feature] detects expected findings."""
        # Add vulnerable code to the repo
        app_file = Path(tmp_repo) / "app.py"
        app_file.write_text("password = 'supersecret123'")

        gate = YourGate(config=config)
        result = gate.run(tmp_repo)
        assert result.findings_count > 0
        assert result.findings[0].severity == "high"
```

### Best Practices

1. **Use fixtures** for common setup (config, temporary repos, database connections)
2. **Test both positive and negative cases**: Verify detection works AND verify clean code produces no findings
3. **Test edge cases**: Empty files, binary files, very long lines, Unicode content
4. **Don't test external tools**: Mock Bandit/Semgrep responses rather than requiring them to be installed
5. **Clean up**: Use `tmp_path` fixture (pytest) for automatic cleanup of temporary files

---

## Continuous Integration

The test suite is designed to run in CI/CD environments:

```yaml
# GitHub Actions example
- name: Run Tests
  run: |
    pip install pytest pytest-cov
    pytest tests/ -v --cov=. --cov-report=xml --cov-report=term-missing

- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.xml
```

### CI Requirements

- **Python 3.11+** must be available
- **No external services** required (all tests use built-in fixtures)
- **No network access** required (all dependencies are mocked or built-in)
- **Test timeout**: The full suite should complete in under 60 seconds
