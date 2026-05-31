# Changelog

All notable changes to the SecureBuild project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-05-10

### Added

#### Security Gates

- **Gate 1: Secrets & Credential Scanner** — Detects hardcoded API keys, passwords, tokens, and other credentials using 9 regex patterns and Shannon entropy analysis. Includes deep scanning of `.env` files with 5 additional patterns. Maps findings to CWE-798 (Use of Hard-coded Credentials) with severity levels from Critical (CVSS 9.8 for private keys) to Medium (CVSS 5.5 for generic secrets). Supports `# nosec` inline suppression and credential masking in output.

- **Gate 2: Static Application Security Testing (SAST)** — Integrates Bandit for Python-specific checks and Semgrep for multi-language SAST analysis, with a built-in Python AST scanner as fallback. Detects SQL injection (CWE-89), command injection (CWE-78), eval/exec usage (CWE-95), insecure deserialization (CWE-502), weak cryptography (CWE-328), and more. Supports incremental scanning for changed-files-only mode.

- **Gate 3: Dependency CVE Audit** — Audits dependencies for known vulnerabilities using a built-in CVE database covering Python (Flask, Django, Requests, urllib3, Pillow, PyYAML, Jinja2) and JavaScript (lodash, express, axios, node-forge) packages. Parses `requirements.txt` and `package.json`. Flags stale dependencies (default: 730 days) and suggests specific upgrade versions. Maps findings to CWE-1104 (Use of Unmaintained Third Party Components).

- **Gate 4: License Compliance Checker** — Checks dependency licenses against configurable organization policies. Classifies licenses from Critical (AGPL-3.0) to Minimal (MIT, ISC, PSF) using SPDX normalization. Supports different policy profiles for open-source and commercial projects. Custom `allowed_licenses` and `blocked_licenses` lists for fine-grained control.

- **Gate 5: Infrastructure-as-Code Security** — Scans Dockerfiles (mapped to CIS Docker Benchmark), docker-compose.yml, Kubernetes manifests, and GitHub Actions workflows for security misconfigurations. Detects running as root, privileged containers, Docker socket mounts, `:latest` tags, missing HEALTHCHECK, missing resource limits, host networking, hostPath mounts, and GitHub Actions script injection. Supports individual sub-scanner enable/disable and experimental Terraform scanning.

#### Risk Scoring Engine

- Weighted CVSS-based scoring algorithm with configurable gate weights (Secrets: 1.5, SAST: 1.3, CVE: 1.2, IaC: 1.1, License: 0.8)
- Severity multipliers (Critical: 2.0, High: 1.5, Medium: 1.0, Low: 0.5, Info: 0.2)
- Normalized 0–100 risk scale with risk level classification (Critical, High, Medium, Low, Minimal)
- Historical trend analysis comparing current score against the average of the last 5 runs
- Percentile ranking against all historical runs in the database
- Remediation simulation (`simulate_fix()`) to estimate score improvement from fixing specific findings
- Human-readable score explanations identifying top contributing findings and projected improvement
- Full CVSS v3.1 base score calculator implementation

#### Remediation Suggestion Engine

- 44 remediation templates covering all common finding types
- Before/after code examples for each template
- Effort estimation (low/medium/high) with time estimates in minutes
- Quick win detection for low-effort, high-impact fixes
- Reference links to relevant documentation and security standards

#### Report Generation

- **HTML reports** — Self-contained, interactive reports with summary cards, severity breakdown, gate results table, findings detail table, and remediation suggestions. Inline CSS, no external dependencies.
- **PDF reports** — Print-ready reports generated from HTML via WeasyPrint. Falls back to HTML if WeasyPrint is not installed.
- **JSON reports** — Complete `RunResult` data model serialization for integration with other tools, custom dashboards, and ticketing systems.
- **CI/CD summary** — Markdown summary (`summary.md`) compatible with GitHub Actions job summaries.

#### Web Dashboard

- Flask-based dashboard with dark-themed UI
- Home page with recent scans, statistics (total runs, critical/high counts, average score)
- Scan listing with filtering by repository and status
- Run detail view with gate breakdowns and findings
- Repository summary with aggregated metrics
- Real-time scan progress via Server-Sent Events (SSE)

#### GitHub Integration

- Pull request comments with scan summary and findings
- Inline review comments on specific lines with findings
- Commit status updates (pass/fail) for branch protection rules
- Job summary for GitHub Actions run pages
- Badge generation (shields.io SVG) for README embedding

#### REST API

- `GET /api/v1/health` — Health check endpoint (no auth required)
- `GET /api/v1/runs` — List pipeline runs with pagination and filtering
- `GET /api/v1/runs/{id}` — Get detailed run information with findings
- `GET /api/v1/repos` — List repositories with statistics
- `GET /api/v1/repos/{name}/score` — Get current security score with trend
- `POST /api/v1/trigger` — Trigger a new security scan
- `GET /api/v1/scan-progress` — SSE endpoint for real-time scan progress
- Bearer token authentication with SHA-256 hashed API key storage
- Pagination support with page metadata
- Consistent error response format (400, 401, 403, 404, 500, 503)

#### CLI

- `securebuild scan <path>` — Run full security scan with configurable format, gates, and thresholds
- `securebuild init` — Generate configuration file with project-type and language-specific defaults
- `securebuild dashboard` — Start Flask web dashboard
- `securebuild history` — View scan history with repository filtering
- `securebuild report <run_id>` — Generate report for a previous scan run
- `securebuild generate-api-key --name <name>` — Generate API key for REST API authentication
- ANSI color output for TTY with automatic disable for piped output
- Exit codes: 0 (pass), 1 (fail/blocked), 2 (error)

#### Configuration

- YAML-based configuration (`securebuild.yaml`) with full customization
- Per-gate enable/disable switches
- Per-gate exclusion paths
- Custom secret patterns for organization-specific credentials
- Configurable blocking thresholds (critical count, high count, risk score)
- Warn-only mode for non-blocking reporting
- Global exclusion paths for dependency directories, build artifacts, and generated files
- Notification settings for Slack and email
- GitHub integration settings
- Report format and content settings
- Environment variable overrides for sensitive values

#### Database

- SQLite persistence with four tables: `pipeline_runs`, `gate_results`, `findings`, `api_keys`
- Foreign key constraints and indexes for query performance
- Automatic schema creation on first use
- API key storage with SHA-256 hashing (plaintext never persisted)

#### Deployment

- **Docker support** — Multi-stage Dockerfile with non-root user, health check, and minimal image size
- **Docker Compose** — Configuration for persistent dashboard deployment with volumes
- **Kubernetes** — Deployment manifest with PVC, Service, health probes, and security context
- **GitHub Actions** — Workflow templates for basic and advanced CI/CD integration
- **Systemd** — Service file for Linux daemon deployment

#### Testing

- Comprehensive test suite with 90+ test cases covering all five gates
- Test fixtures with intentionally vulnerable and security-hardened repository samples
- Unit tests for gate detection logic, scoring engine, and database operations
- Integration tests for orchestrator pipeline and report generation
- pytest configuration with coverage reporting and fixture management

#### Documentation

- README.md — Main project documentation with overview, architecture, and usage
- docs/architecture.md — Detailed system architecture with component descriptions and data flow
- docs/configuration.md — Complete configuration reference for all YAML options
- docs/gates.md — Technical specifications for each security gate
- docs/api.md — REST API documentation with endpoints, schemas, and examples
- docs/cli.md — CLI command reference with examples
- docs/testing.md — Test strategy and execution guide
- docs/deployment.md — Deployment guide for local, Docker, CI/CD, and Kubernetes
- docs/user_guide.md — Getting started guide with troubleshooting FAQ
- CHANGELOG.md — Version history and release notes
