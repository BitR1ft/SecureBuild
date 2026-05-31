# SecureBuild — CI/CD Security Gate

> A multi-gate security scanning tool that enforces security standards in CI/CD pipelines. Scans repositories for secrets, vulnerabilities, dependency issues, license compliance, and infrastructure misconfigurations.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [The 5 Security Gates](#-the-5-security-gates)
  - [Gate 1: Secrets & Credential Scanner](#gate-1-secrets--credential-scanner)
  - [Gate 2: Static Application Security Testing (SAST)](#gate-2-static-application-security-testing-sast)
  - [Gate 3: Dependency CVE Audit](#gate-3-dependency-cve-audit)
  - [Gate 4: License Compliance Checker](#gate-4-license-compliance-checker)
  - [Gate 5: Infrastructure-as-Code Security](#gate-5-infrastructure-as-code-security)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
  - [CLI Commands](#cli-commands)
- [Risk Scoring](#-risk-scoring)
- [Reports](#-reports)
- [Web Dashboard](#-web-dashboard)
- [Testing](#-testing)
- [Architecture Deep Dive](#-architecture-deep-dive)
- [License](#-license)

---

## 🛡️ Overview

SecureBuild is a comprehensive security gate tool designed to integrate into CI/CD pipelines. It runs **5 independent security gates** against your codebase, calculates a **weighted risk score**, and can **block deployments** that don't meet your security threshold. Every finding includes a CVSS score, CWE mapping, and a remediation suggestion.

### Key Features

| Feature | Description |
|---|---|
| **5 Security Gates** | Secrets, SAST, CVE Audit, License Compliance, IaC Security |
| **Risk Scoring Engine** | Weighted CVSS-based scoring with trend analysis and percentile ranking |
| **HTML & JSON Reports** | Self-contained reports with severity breakdowns and fix suggestions |
| **Web Dashboard** | Flask-based dashboard with scan history, clickable reports, and findings |
| **SQLite Persistence** | All scan results stored in a local SQLite database |

### Why SecureBuild?

- **Shift Security Left**: Catch vulnerabilities before they reach production
- **Enforce Policies**: Block deployments that violate your security thresholds
- **Actionable Findings**: Every finding includes a fix suggestion, not just a description
- **Quantitative Scoring**: Risk scores with trend analysis let you track improvements over time

---

## Architecture

```
┌─────────────┐     ┌───────────────┐     ┌──────────────────────────────────┐
│  Code Repo  │────▶│  Orchestrator │────▶│     5 Security Gates (Parallel)  │
│ (local/git) │     │  (Controller) │     │                                  │
└─────────────┘     └───────┬───────┘     │  ┌──────────┐  ┌──────────────┐ │
                            │             │  │ Gate 1:  │  │ Gate 2:      │ │
                            │             │  │ Secrets  │  │ SAST         │ │
                            │             │  └──────────┘  └──────────────┘ │
                            │             │  ┌──────────┐  ┌──────────────┐ │
                            │             │  │ Gate 3:  │  │ Gate 4:      │ │
                            │             │  │ CVE      │  │ License      │ │
                            │             │  └──────────┘  └──────────────┘ │
                            │             │  ┌──────────┐                   │
                            │             │  │ Gate 5:  │                   │
                            │             │  │ IaC      │                   │
                            │             │  └──────────┘                   │
                            │             └──────────────┬───────────────────┘
                            │                            │
                            ▼                            ▼
                    ┌───────────────┐           ┌─────────────────┐
                    │  Risk Scorer  │◀──────────│  Gate Results   │
                    │  (Weighted)   │           │  (Findings)     │
                    └───────┬───────┘           └─────────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
      ┌──────────────┐ ┌──────────┐ ┌──────────────┐
      │  SQLite DB   │ │ Reporter │ │    Flask      │
      │  (Persist)   │ │ (HTML /  │ │  Dashboard   │
      │              │ │  JSON)   │ │              │
      └──────────────┘ └──────────┘ └──────────────┘
```

### Data Flow

1. **Input**: The orchestrator receives a repository path from the CLI
2. **Validation**: Repository path is validated and metadata (branch, commit hash) is collected
3. **Gate Execution**: All enabled gates run in parallel using `concurrent.futures.ThreadPoolExecutor`
4. **Scoring**: The risk scorer aggregates findings with gate weights and severity multipliers
5. **Persistence**: Results are stored in SQLite with full finding details
6. **Reporting**: HTML and/or JSON reports are generated
7. **Decision**: The pipeline passes or fails based on configured thresholds

---

## 🔒 The 5 Security Gates

### Gate 1: Secrets & Credential Scanner

**Detects**: Hardcoded API keys, passwords, tokens, private keys, and other credentials using regex pattern matching and Shannon entropy analysis.

**How it works**:

- Scans all text files using 9 primary regex patterns covering AWS keys, GitHub PATs, Stripe keys, JWT tokens, private keys, passwords, API keys, and generic secrets
- Performs deep scanning of `.env` files with 5 additional patterns for database credentials, application secrets, email credentials, AWS credentials, and Stripe credentials
- Runs Shannon entropy analysis on every line to detect high-entropy strings (entropy > 4.5, length > 20) that may be obfuscated secrets evading pattern-based detection
- Respects `# nosec` and `// nosec` inline suppression comments
- Masks credential values in findings for safe display

**Severity mapping**:

| Pattern | Severity | CVSS |
|---|---|---|
| Private Key | Critical | 9.8 |
| AWS Access Key | Critical | 9.1 |
| AWS Secret Key | Critical | 9.1 |
| GitHub PAT | Critical | 9.1 |
| Stripe Secret Key | Critical | 9.1 |
| Password (hardcoded) | High | 7.5 |
| API Key (hardcoded) | High | 7.5 |
| JWT Token | High | 7.5 |
| .env Credential | High | 8.0 |
| High Entropy String | Medium | 6.5 |
| Generic Secret | Medium | 5.5 |

**CWE Mapping**: Primarily CWE-798 (Use of Hard-coded Credentials), CWE-200 (Exposure of Sensitive Information)

### Gate 2: Static Application Security Testing (SAST)

**Detects**: SQL injection, command injection, eval() usage, insecure deserialization, weak cryptography, path traversal, and other code-level vulnerabilities.

**How it works**:

- Attempts to use **Bandit** (Python) and **Semgrep** (multi-language) for industry-standard SAST analysis
- Falls back to a **built-in Python AST scanner** when external tools are not available
- The built-in scanner uses `ast.parse()` to walk the Python AST and detect dangerous patterns:
  - `eval()`, `exec()`, `compile()` usage
  - `subprocess.call()` with `shell=True`
  - SQL string formatting with f-strings or `.format()`
  - `pickle.loads()` and `yaml.load()` without `Loader`
  - Insecure hash algorithms (MD5, SHA1) via `hashlib`
  - `assert` statements used for security checks
  - `tempfile.mktemp()` (race condition)
- Supports incremental scanning to only check changed files
- Excludes migration files and test directories by default

**Severity mapping**:

| Vulnerability | Severity | CVSS |
|---|---|---|
| SQL Injection | Critical | 9.8 |
| Command Injection | Critical | 9.1 |
| Insecure Deserialization | High | 8.1 |
| eval()/exec() | High | 7.5 |
| Path Traversal | High | 7.5 |
| Weak Cryptography | Medium | 5.3 |
| Assert for Security | Low | 3.5 |

### Gate 3: Dependency CVE Audit

**Detects**: Known vulnerabilities (CVEs) in project dependencies by cross-referencing against a built-in vulnerability database.

**How it works**:

- Parses `requirements.txt` (Python) and `package.json` (JavaScript/Node.js) to extract dependency names and versions
- Cross-references each dependency against a built-in CVE database containing known vulnerabilities
- Calculates staleness based on the `check_stale_days` configuration (default: 730 days / 2 years)
- Suggests specific upgrade versions when available
- Optionally checks dependency licenses if `check_licenses` is enabled
- Handles version specifier parsing (>=, ~=, ==, etc.) and range matching

**Built-in CVE database covers**:

- Python: Flask, Django, Requests, urllib3, Pillow, PyYAML, Jinja2, and more
- JavaScript: lodash, express, axios, node-forge, and more

**Severity mapping**: Directly derived from the CVE's CVSS score in the National Vulnerability Database.

### Gate 4: License Compliance Checker

**Detects**: Dependencies with licenses that conflict with your organization's policy.

**How it works**:

- Parses `requirements.txt` and `package.json` to identify all dependencies
- Uses `pip-licenses` (Python) and `npm` license queries to resolve license identifiers
- Normalizes license identifiers using SPDX license expression syntax
- Classifies licenses into risk categories based on project type context:

| Risk Level | Open Source Projects | Commercial Projects |
|---|---|---|
| Critical | AGPL-3.0 | AGPL-3.0 |
| High | GPL-2.0, GPL-3.0 | GPL-2.0, GPL-3.0 |
| Medium | LGPL-2.1, LGPL-3.0, MPL-2.0 | LGPL-2.1, LGPL-3.0, MPL-2.0 |
| Low | Apache-2.0, GPL variants | Apache-2.0, BSD, MIT |
| Minimal | MIT, BSD, ISC, PSF | MIT, BSD, ISC, PSF |

- Supports custom `allowed_licenses` and `blocked_licenses` lists in configuration
- Commercial projects have stricter default policies (all copyleft licenses blocked)

### Gate 5: Infrastructure-as-Code Security

**Detects**: Security misconfigurations in Dockerfiles, docker-compose.yml, Kubernetes manifests, and GitHub Actions workflows.

**How it works**:

- **Dockerfile scanning**: Detects running as root, use of `:latest` tags, exposed sensitive ports, missing HEALTHCHECK, ADD vs COPY, secret leaking in ENV/RUN instructions. Maps findings to CIS Docker Benchmark.
- **Docker Compose scanning**: Detects privileged containers, host network mode, mounted Docker socket, missing resource limits, exposed sensitive ports, and running as root.
- **Kubernetes manifest scanning**: Detects privileged containers, hostPath mounts, host network/port settings, missing resource limits, running as root (runAsNonRoot), and missing security contexts.
- **GitHub Actions scanning**: Detects untrusted checkout, `pull_request_target` with explicit checkout, script injections via untrusted context variables, and missing permissions blocks.

**Sub-scanners can be individually enabled/disabled**:

```yaml
gates:
  iac:
    check_docker: true
    check_compose: true
    check_k8s: true
    check_github_actions: true
    terraform_experimental: false  # Experimental Terraform support
```

**Severity mapping**:

| Misconfiguration | Severity | CVSS |
|---|---|---|
| Running as root | High | 7.5 |
| Privileged container | Critical | 9.1 |
| Docker socket mounted | Critical | 9.1 |
| `:latest` tag | Medium | 5.0 |
| Missing HEALTHCHECK | Low | 3.0 |
| Missing resource limits | Medium | 5.5 |
| Untrusted PR checkout | High | 8.5 |

---

## ⚡ Quick Start

Get scanning in 3 commands:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Initialize configuration
python cli.py init

# 3. Run your first scan
python cli.py scan /path/to/your/repo
```

**Expected output**:

```
SecureBuild Security Scan
==================================================
  Repository : /path/to/your/repo
  Output     : reports
  Format     : all

Scan Results Summary
──────────────────────────────────────────────────────────────────────
  Run ID       : 20250510-a3f2c1d4
  Repository   : your-repo
  Branch       : main
  Commit       : a3f2c1d4e5f6
  Timestamp    : 2025-05-10T14:30:00+00:00
  Duration     : 3420ms
  Overall Score: 78.5/100
  Status       : PASS

  Gate                 Status     Findings   Critical   High       Duration
  ──────────────────────────────────────────────────────────────────────────
  secrets              PASS        2          0          1          890ms
  sast                 FAIL        5          1          2          1240ms
  cve                  PASS        3          0          1          450ms
  license              PASS        1          0          0          230ms
  iac                  PASS        2          0          1          610ms

Pipeline PASSED: all security gates clear
```

---

## 📦 Installation

### Prerequisites

- **Python 3.11+** (required for modern type hints and performance features)
- **Git** (for repository metadata collection)
- **pip** (package manager)

### Standard Installation

```bash
# Clone the repository
git clone https://github.com/your-org/securebuild.git
cd securebuild

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Verify installation
python cli.py --help
```

### Development Installation

```bash
# Clone and install with dev dependencies
git clone https://github.com/your-org/securebuild.git
cd securebuild
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-cov

# Run the test suite to verify
pytest tests/ -v
```

### Optional External Tools

SecureBuild integrates with these external tools for enhanced detection. They are optional — the built-in scanners provide fallback coverage.

| Tool | Purpose | Install |
|---|---|---|
| **Bandit** | Python SAST | `pip install bandit` (included in requirements.txt) |
| **Semgrep** | Multi-language SAST | `pip install semgrep` (included in requirements.txt) |
| **detect-secrets** | Alternative secret scanner | `pip install detect-secrets` (included in requirements.txt) |
| **pip-licenses** | License detection | `pip install pip-licenses` (included in requirements.txt) |

---

## ⚙️ Configuration

SecureBuild is configured via `securebuild.yaml`. Generate a template with:

```bash
python cli.py init
```

### Configuration File Structure

```yaml
project:
  name: ""                    # Auto-detected from repository
  type: open_source           # open_source or commercial
  language: python            # python, javascript, or both

gates:
  secrets:
    enabled: true
    custom_patterns: []       # Add your own secret patterns
    exclude_paths: []
  sast:
    enabled: true
    incremental_scan: false
    exclude_paths: ["migrations/**", "*/tests/**"]
  cve:
    enabled: true
    check_stale_days: 730     # Flag deps older than 2 years
    check_licenses: true
    exclude_paths: []
  license:
    enabled: true
    allowed_licenses:
      - MIT
      - Apache-2.0
      - BSD-2-Clause
      - BSD-3-Clause
      - ISC
      - PSF
    blocked_licenses:
      - AGPL-3.0
    exclude_paths: []
  iac:
    enabled: true
    check_docker: true
    check_compose: true
    check_k8s: true
    check_github_actions: true
    terraform_experimental: false
    exclude_paths: []

thresholds:
  secrets:
    max_critical: 0
    max_high: 0     # Zero tolerance for hardcoded secrets
  sast:
    max_critical: 0
    max_high: 5
  cve:
    max_critical: 0
    max_high: 5
  license:
    max_critical: 0
    max_high: 10
  iac:
    max_critical: 0
    max_high: 5

fail_on_critical: true    # Block pipeline if ANY critical finding is found
fail_on_high: false       # Set true to block on high findings

exclude_paths:
  - "node_modules/**"
  - "venv/**"
  - ".git/**"
  - "*.lock"
  - "*.min.js"
  - "*.min.css"
  - "__pycache__/**"

reporting:
  default_format: html
  include_charts: true
  include_code_snippets: true
  max_findings_per_gate: 100
```

For the complete configuration reference, see [docs/configuration.md](docs/configuration.md).

> **Note on Database Path**: SecureBuild stores all scan results in `securebuild.db` in the project root by default. This is automatically detected by all commands — `scan`, `history`, `report`, and `dashboard` all read from and write to the same file without any extra configuration.

---

## 🚀 Usage

### CLI Commands

SecureBuild provides a command-line interface with the following commands:

#### `scan <path>` — Run a security scan

```bash
# Basic scan (generates HTML + JSON reports)
python cli.py scan /path/to/repo

# Generate only JSON output
python cli.py scan /path/to/repo --format json

# Dry-run mode (never blocks pipeline)
python cli.py scan /path/to/repo --dry-run

# Run only specific gates
python cli.py scan /path/to/repo --gates secrets sast

# Verbose output for debugging
python cli.py scan /path/to/repo --verbose

# Custom output directory
python cli.py scan /path/to/repo --output-dir ./my-reports

# Custom config file
python cli.py scan /path/to/repo --config ./my-securebuild.yaml
```

**Exit codes**:

| Code | Meaning |
|---|---|
| 0 | Pipeline passed — all gates clear |
| 1 | Pipeline blocked — security gate failures detected |
| 2 | Pipeline completed with errors |

#### `init` — Create a configuration file

```bash
# Create config for an open-source Python project
python cli.py init --project-type open_source --language python

# Create config for a commercial JavaScript project
python cli.py init --project-type commercial --language javascript
```

#### `dashboard` — Start the web dashboard

```bash
# Start on default port (5000)
python cli.py dashboard

# Start on custom port
python cli.py dashboard --port 8080

# Bind to all interfaces
python cli.py dashboard --host 0.0.0.0
```

Then open `http://localhost:5000` in your browser to view scan history and click any scan row to open its full HTML report.

#### `history` — View scan history in the terminal

```bash
# Show recent scans
python cli.py history

# Show last 50 runs
python cli.py history --limit 50

# Filter by repository
python cli.py history --repo my-project
```

#### `report <run_id>` — Generate a report for a past run

```bash
# Generate HTML report (default)
python cli.py report 20260602-39a8f9cc

# Generate JSON report
python cli.py report 20260602-39a8f9cc --format json

# Custom output path
python cli.py report 20260602-39a8f9cc --output ./reports/scan.html
```

---

## 📊 Risk Scoring

SecureBuild uses a **weighted CVSS-based scoring algorithm** that produces a risk score from 0 (no risk) to 100 (critical risk).

### Scoring Formula

```
Score = sum(cvss_score × gate_weight × severity_multiplier) / total_weight
```

The raw score is normalized to a 0–10 scale, then multiplied by 10 to produce a 0–100 value.

### Gate Weights

Higher weight = findings from this gate contribute more to the overall risk:

| Gate | Weight | Rationale |
|---|---|---|
| Secrets | 1.5 | Hardcoded credentials are immediately exploitable |
| SAST | 1.3 | Code vulnerabilities can be directly exploited |
| CVE (Dependencies) | 1.2 | Known CVEs have public exploits |
| IaC | 1.1 | Infrastructure misconfigurations expose attack surface |
| License | 0.8 | License issues are typically lower urgency |

### Severity Multipliers

| Severity | Multiplier | Effect |
|---|---|---|
| Critical | 2.0 | Doubles the CVSS contribution |
| High | 1.5 | 50% amplification |
| Medium | 1.0 | No amplification |
| Low | 0.5 | Halves the contribution |
| Info | 0.2 | Minimal contribution |

### Risk Level Thresholds

| Score Range | Risk Level | Action |
|---|---|---|
| 80–100 | Critical | Immediate remediation required; deployment blocked |
| 60–79 | High | Address critical/high findings before deployment |
| 40–59 | Medium | Prioritize high-severity fixes in upcoming sprints |
| 20–39 | Low | Address during regular maintenance |
| 0–19 | Minimal | Continue with standard security practices |

### Pipeline Blocking Rules

The pipeline is blocked if **any** of these conditions are met:

1. **Any critical finding** is present (configurable via `fail_on_critical`)
2. **Per-gate thresholds** are exceeded (configurable per gate in `thresholds`)

Set `fail_on_critical: false` and high thresholds to run in report-only mode.

### Trend Analysis

SecureBuild compares the current risk score against the average of the last 5 runs for the same repository:

| Trend | Condition | Meaning |
|---|---|---|
| `improving` | Delta < -0.5 | Security posture is improving |
| `stable` | |Delta| <= 0.5 | No significant change |
| `degrading` | Delta > 0.5 | Security posture is worsening |
| `critical_regression` | Delta > 2.0 | Severe security regression |
| `new` | No history | First scan for this repository |

---

## 📋 Reports

SecureBuild generates reports in two formats:

### HTML Report

- **Purpose**: Human-readable report for developers and security teams
- **Features**: Gradient header with pass/fail status, metric summary cards, severity breakdown tiles, gate results table, full findings detail with CVSS scores, CWE IDs, and fix suggestions
- **Output**: `reports/securebuild-{run_id}.html`
- **Self-contained**: Inline CSS, no external dependencies, works offline
- **Print-friendly**: `@media print` styles included

Access via the dashboard by clicking any row in the Recent Scans or Run History tables — the report opens in a new browser tab.

### JSON Report

- **Purpose**: Machine-readable format for integration with other tools
- **Features**: Complete `RunResult` serialization including all findings, risk scores, and metadata
- **Output**: `reports/securebuild-{run_id}.json`
- **Schema**: Matches the `RunResult.to_dict()` data model

---

## 🖥️ Web Dashboard

Start the dashboard with:

```bash
python cli.py dashboard
```

Then open `http://localhost:5000`.

### Dashboard Pages

| Page | URL | Description |
|---|---|---|
| **Home** | `/` | Metric cards (runs today, avg score, critical findings) + recent scans table |
| **Run History** | `/runs` | Full paginated run list with filters (repo, branch, date, status, score) |
| **HTML Report** | `/runs/<run_id>/report` | Generated HTML security report — opened when you click any scan row |

### Clicking a Scan Row

On both the home dashboard and the Run History page, clicking any row (or the **Report** button) opens the full HTML security report for that scan in a **new browser tab**. No separate file is needed — the report is generated from the database on demand.

---

## 🧪 Testing

SecureBuild includes a comprehensive test suite:

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=. --cov-report=html

# Run a specific gate's tests
pytest tests/test_gate1.py -v

# Run with verbose output
pytest tests/ -v -s
```

The test suite includes:

- **Unit tests** for each gate (`test_gate1.py` through `test_gate5.py`)
- **Test fixtures** with vulnerable and fixed code samples
- **Integration tests** for the orchestrator (`test_orchestrator.py`) and scoring engine (`test_scorer.py`)
- **Database tests** (`test_db.py`) for persistence layer verification
- **Edge case tests** for binary files, large files, and empty repositories

See [docs/testing.md](docs/testing.md) for detailed testing documentation.

---

## 🏗️ Architecture Deep Dive

### Component Overview

| Component | Location | Responsibility |
|---|---|---|
| **CLI** | `cli.py` | Command-line interface, report rendering, summary generation |
| **Orchestrator** | `engine/orchestrator.py` | Pipeline coordination, gate execution, scoring |
| **Gate Runner** | `engine/runner.py` | Parallel gate execution with ThreadPoolExecutor |
| **Base Gate** | `gates/base.py` | Abstract base class for all gates |
| **Gate 1–5** | `gates/gate*.py` | Individual security gate implementations |
| **Risk Scorer** | `scoring/scorer.py` | Weighted CVSS scoring, trend analysis, percentiles |
| **Database** | `engine/db.py` | SQLite persistence with CRUD operations |
| **Reporter** | `reporter/` | HTML and JSON report generation |
| **Dashboard** | `dashboard/` | Flask web UI (home, runs, report viewer) |
| **Config** | `engine/config.py` | YAML configuration loading and validation |
| **Models** | `engine/models.py` | Dataclass models (Finding, GateResult, RiskScore, RunResult) |

### Technology Decisions

| Decision | Choice | Rationale |
|---|---|---|
| **Database** | SQLite | Zero-config, file-based, sufficient for CI/CD workloads, easy backup |
| **Web Framework** | Flask | Lightweight, well-tested, sufficient for dashboard |
| **SAST Tools** | Bandit + Semgrep | Bandit for Python-specific checks, Semgrep for multi-language |
| **Secret Detection** | Regex + Entropy | Pattern matching for known formats, entropy for obfuscated secrets |
| **Scoring Scale** | 0–100 | Intuitive for humans, compatible with percentage-based thresholds |
| **Parallel Execution** | ThreadPoolExecutor | I/O-bound gate execution benefits from threading |
| **Report Formats** | HTML + JSON | HTML for viewing, JSON for integration |

### Error Handling Philosophy

SecureBuild follows a **fail-safe** approach:

- Individual gate failures do not prevent the pipeline from completing
- Errored gates are marked with status `"error"` and the pipeline continues
- If all gates error, the pipeline status is `"error"` (not `"fail"`)
- Database write failures are logged but do not crash the pipeline
- Report generation failures are logged but do not affect the scan result

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <strong>SecureBuild</strong> — Shift security left. Ship with confidence.
</p>
