# Configuration Guide

> SecureBuild CI/CD Security Gate — Complete Configuration Reference

This document describes every configuration option available in `securebuild.yaml`. SecureBuild uses a single YAML configuration file that controls gate behavior, thresholds, notifications, GitHub integration, and reporting.

---

## Table of Contents

- [Configuration File Location](#configuration-file-location)
- [Generating a Configuration File](#generating-a-configuration-file)
- [Project Settings](#project-settings)
- [Gate Configuration](#gate-configuration)
  - [Secrets Gate](#secrets-gate-gatessecrets)
  - [SAST Gate](#sast-gate-gatessast)
  - [CVE Gate](#cve-gate-gatescve)
  - [License Gate](#license-gate-gateslicense)
  - [IaC Gate](#iac-gate-gatesiac)
- [Threshold Configuration](#threshold-configuration)
- [Global Exclusion Paths](#global-exclusion-paths)
- [Notification Settings](#notification-settings)
- [GitHub Integration](#github-integration)
- [Reporting Settings](#reporting-settings)
- [Environment Variables](#environment-variables)
- [Configuration Examples](#configuration-examples)

---

## Configuration File Location

SecureBuild searches for configuration files in this order:

1. Path specified via `--config` CLI argument
2. `securebuild.yaml` in the current working directory
3. `securebuild.yml` in the current working directory

If no configuration file is found, SecureBuild uses built-in defaults.

---

## Generating a Configuration File

Use the `init` command to generate a configuration template:

```bash
# Default: open-source Python project
python cli.py init

# Commercial Python project
python cli.py init --project-type commercial --language python

# Open-source JavaScript project
python cli.py init --project-type open_source --language javascript

# Polyglot project (both Python and JavaScript)
python cli.py init --project-type commercial --language both
```

The `--project-type` flag adjusts license compliance defaults (commercial projects block all copyleft licenses). The `--language` flag adjusts SAST exclusion paths for the appropriate language ecosystem.

---

## Project Settings

```yaml
project:
  name: ""              # Auto-detected from repository directory name
  type: open_source     # open_source or commercial
  language: python      # python, javascript, or both
```

### `project.name`

- **Type**: String
- **Default**: `""` (auto-detected)
- **Description**: The project name used in reports and dashboard display. When empty, SecureBuild auto-detects the name from the repository's directory name.
- **Example**: `name: "my-awesome-app"`

### `project.type`

- **Type**: String (`open_source` or `commercial`)
- **Default**: `open_source`
- **Description**: Determines the license compliance policy. Commercial projects have stricter defaults that block all copyleft licenses (GPL, LGPL, AGPL). Open-source projects allow permissive and weak copyleft licenses.
- **Impact**: Affects the default `allowed_licenses` and `blocked_licenses` lists in the License gate.

### `project.language`

- **Type**: String (`python`, `javascript`, or `both`)
- **Default**: `python`
- **Description**: The primary programming language(s) of the project. Affects which SAST tools are used, which dependency files are parsed, and which exclusion patterns are applied.
- **Impact**:
  - `python`: Scans `requirements.txt`, uses Bandit for SAST
  - `javascript`: Scans `package.json`, uses Semgrep for SAST
  - `both`: Scans both dependency files, uses both SAST tools

---

## Gate Configuration

Each gate can be individually enabled or disabled, and most gates support per-gate exclusion paths and custom settings.

### Secrets Gate (`gates.secrets`)

```yaml
gates:
  secrets:
    enabled: true
    custom_patterns: []
    exclude_paths: []
```

#### `gates.secrets.enabled`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable or disable the Secrets & Credential Scanner. When disabled, no secret detection patterns or entropy analysis will run.

#### `gates.secrets.custom_patterns`

- **Type**: List of objects
- **Default**: `[]`
- **Description**: Add custom regex patterns for detecting organization-specific secrets. Each pattern object has a `name` (for display) and `pattern` (regex string).
- **Example**:

```yaml
gates:
  secrets:
    custom_patterns:
      - name: "Internal API Key"
        pattern: "INTERNAL_[A-Z0-9]{32}"
      - name: "Custom Auth Token"
        pattern: "AUTH_TOKEN_[a-f0-9]{40}"
```

Custom patterns are evaluated alongside the built-in patterns. Findings from custom patterns are classified as severity `medium` with CVSS 5.5 unless a mapping is added to the severity map.

#### `gates.secrets.exclude_paths`

- **Type**: List of glob patterns
- **Default**: `[]`
- **Description**: Additional file paths to exclude from secret scanning, beyond the global `exclude_paths`. Useful for excluding configuration template files or test fixtures that intentionally contain fake credentials.
- **Example**:

```yaml
gates:
  secrets:
    exclude_paths:
      - "tests/fixtures/**"
      - "config/templates/**"
      - "**/*.example"
```

---

### SAST Gate (`gates.sast`)

```yaml
gates:
  sast:
    enabled: true
    incremental_scan: false
    exclude_paths: ["migrations/**", "*/tests/**"]
```

#### `gates.sast.enabled`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable or disable the Static Application Security Testing gate.

#### `gates.sast.incremental_scan`

- **Type**: Boolean
- **Default**: `false`
- **Description**: When enabled, only scans files that have changed since the last commit. This significantly reduces scan time for large repositories but may miss vulnerabilities in unchanged files that were not previously detected.
- **Note**: Requires Git history to be available. In CI/CD environments, ensure a full checkout (not shallow clone).

#### `gates.sast.exclude_paths`

- **Type**: List of glob patterns
- **Default**: `["migrations/**", "*/tests/**"]`
- **Description**: File paths to exclude from SAST scanning. Database migration files are excluded by default because they often contain raw SQL that triggers false positives. Test directories are excluded because test code often intentionally uses insecure patterns for testing purposes.
- **Language-specific defaults**:
  - Python: `["migrations/**", "*/tests/**", "conftest.py"]`
  - JavaScript: `["*/tests/**", "*/__tests__/**", "*/test/**", "jest.config.*"]`

---

### CVE Gate (`gates.cve`)

```yaml
gates:
  cve:
    enabled: true
    check_stale_days: 730
    check_licenses: true
    exclude_paths: []
```

#### `gates.cve.enabled`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable or disable the Dependency CVE Audit gate.

#### `gates.cve.check_stale_days`

- **Type**: Integer
- **Default**: `730` (2 years)
- **Description**: Flag dependencies that have not been updated in more than this many days as a medium-severity finding. Stale dependencies are more likely to have unpatched vulnerabilities.
- **Set to 0** to disable staleness checking.
- **Set to 365** for stricter freshness requirements.

#### `gates.cve.check_licenses`

- **Type**: Boolean
- **Default**: `true`
- **Description**: When enabled, the CVE gate also reports license information for each dependency. This provides a consolidated view of both vulnerability and license data. When disabled, license checking is solely handled by the License gate.
- **Note**: The License gate provides more detailed compliance analysis. This flag only adds license metadata to CVE findings.

#### `gates.cve.exclude_paths`

- **Type**: List of glob patterns
- **Default**: `[]`
- **Description**: File paths to exclude from dependency scanning. Useful when you have dependency files for tools that are not part of the application runtime (e.g., build tool dependencies).

---

### License Gate (`gates.license`)

```yaml
gates:
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
```

#### `gates.license.enabled`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable or disable the License Compliance Checker gate.

#### `gates.license.allowed_licenses`

- **Type**: List of SPDX license identifiers
- **Default**: `["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "PSF"]`
- **Description**: Licenses that are permitted for use in the project. Dependencies with licenses not in this list (and not in `blocked_licenses`) are flagged as informational findings.
- **Open-source project defaults** include permissive and weak copyleft licenses (GPL, LGPL, MPL).
- **Commercial project defaults** include only permissive licenses.
- **SPDX identifiers**: Use the standard SPDX license identifiers (e.g., `MIT`, `Apache-2.0`, `GPL-3.0-or-later`).

#### `gates.license.blocked_licenses`

- **Type**: List of SPDX license identifiers
- **Default**: `["AGPL-3.0"]`
- **Description**: Licenses that are explicitly blocked. Dependencies with these licenses are flagged as critical or high severity findings, regardless of the `allowed_licenses` list.
- **Open-source default**: Only AGPL-3.0 is blocked (strong copyleft with network clause).
- **Commercial default**: AGPL-3.0, GPL-2.0, and GPL-3.0 are blocked (all strong copyleft).

#### `gates.license.exclude_paths`

- **Type**: List of glob patterns
- **Default**: `[]`
- **Description**: File paths to exclude from license scanning.

---

### IaC Gate (`gates.iac`)

```yaml
gates:
  iac:
    enabled: true
    check_docker: true
    check_compose: true
    check_k8s: true
    check_github_actions: true
    terraform_experimental: false
    exclude_paths: []
```

#### `gates.iac.enabled`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable or disable the Infrastructure-as-Code Security gate.

#### `gates.iac.check_docker`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Scan Dockerfiles for security misconfigurations. Detects running as root, `:latest` tags, exposed sensitive ports, missing HEALTHCHECK, and more. Maps findings to CIS Docker Benchmark.

#### `gates.iac.check_compose`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Scan `docker-compose.yml` and `docker-compose.yaml` files. Detects privileged containers, host network mode, mounted Docker socket, missing resource limits, and more.

#### `gates.iac.check_k8s`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Scan Kubernetes manifests (`.yaml` files with `kind: Deployment`, `kind: Pod`, etc.). Detects privileged containers, hostPath mounts, missing resource limits, running as root, and missing security contexts.

#### `gates.iac.check_github_actions`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Scan GitHub Actions workflow files (`.github/workflows/*.yml`). Detects untrusted checkout, `pull_request_target` with explicit checkout, script injections via untrusted context variables, and missing permissions blocks.

#### `gates.iac.terraform_experimental`

- **Type**: Boolean
- **Default**: `false`
- **Description**: Enable experimental Terraform scanning. This feature is under development and may produce false positives. Scans `.tf` files for common misconfigurations like unencrypted S3 buckets, publicly accessible resources, and missing encryption.

#### `gates.iac.exclude_paths`

- **Type**: List of glob patterns
- **Default**: `[]`
- **Description**: File paths to exclude from IaC scanning. Useful for excluding example or template Dockerfiles.

---

## Threshold Configuration

```yaml
thresholds:
  block_on:
    critical: 1
    high: 5
    score: 7.0
  warn_only: false
```

### `thresholds.block_on.critical`

- **Type**: Integer
- **Default**: `1`
- **Description**: The pipeline is blocked if the number of critical findings equals or exceeds this value. Set to `0` to block on any critical finding (default). Set to a higher number to tolerate some critical findings.

### `thresholds.block_on.high`

- **Type**: Integer
- **Default**: `5`
- **Description**: The pipeline is blocked if the number of high findings equals or exceeds this value. Set to `0` to block on any high finding. Increase for projects with known technical debt.

### `thresholds.block_on.score`

- **Type**: Float
- **Default**: `7.0`
- **Description**: The pipeline is blocked if the overall risk score (0–10 scale) exceeds this threshold. The risk score is calculated from the weighted aggregate of all findings. A threshold of 7.0 means the pipeline fails when the risk level reaches "High" or above.
- **Range**: 0.0 – 10.0
- **Recommended values**:
  - `5.0` — Strict: fail on medium risk or above
  - `7.0` — Default: fail on high risk or above
  - `9.0` — Permissive: fail only on critical risk

### `thresholds.warn_only`

- **Type**: Boolean
- **Default**: `false`
- **Description**: When `true`, the pipeline never blocks regardless of findings. All findings are reported but the exit code is always 0. Useful for:
  - Initial rollout: Assess findings before enforcing policies
  - Development: Avoid blocking developers while security issues are triaged
  - Reporting-only mode: Generate security metrics without gate enforcement

---

## Global Exclusion Paths

```yaml
exclude_paths:
  - "node_modules/**"
  - "venv/**"
  - ".git/**"
  - "*.lock"
  - "*.min.js"
  - "*.min.css"
  - "__pycache__/**"
  - ".tox/**"
```

- **Type**: List of glob patterns
- **Description**: Files and directories matching these patterns are excluded from all gates. These are merged with any gate-specific exclusion patterns.
- **Defaults**: Common dependency directories, build artifacts, minified files, and cache directories.
- **Adding custom exclusions**:

```yaml
exclude_paths:
  - "node_modules/**"
  - "venv/**"
  - ".git/**"
  - "*.lock"
  - "*.min.js"
  - "*.min.css"
  - "__pycache__/**"
  - ".tox/**"
  - "third_party/**"         # Vendored dependencies
  - "generated/**"           # Auto-generated code
  - "**/*.pb.go"             # Generated Protocol Buffer code
```

---

## Notification Settings

```yaml
notifications:
  slack:
    enabled: false
    webhook_url: ""
  email:
    enabled: false
    smtp_host: ""
    smtp_port: 587
    to_address: ""
```

### Slack Notifications

#### `notifications.slack.enabled`

- **Type**: Boolean
- **Default**: `false`
- **Description**: Enable Slack notifications for scan results.

#### `notifications.slack.webhook_url`

- **Type**: String
- **Default**: `""`
- **Description**: The Slack incoming webhook URL. **Recommended**: Store this in the `SECUREBUILD_SLACK_WEBHOOK` environment variable rather than in the configuration file.
- **Format**: `https://hooks.slack.com/services/T.../B.../xxx...`

### Email Notifications

#### `notifications.email.enabled`

- **Type**: Boolean
- **Default**: `false`
- **Description**: Enable email notifications for scan results.

#### `notifications.email.smtp_host`

- **Type**: String
- **Default**: `""`
- **Description**: SMTP server hostname (e.g., `smtp.gmail.com`, `smtp.office365.com`).

#### `notifications.email.smtp_port`

- **Type**: Integer
- **Default**: `587`
- **Description**: SMTP server port. Use `587` for TLS or `465` for SSL.

#### `notifications.email.to_address`

- **Type**: String
- **Default**: `""`
- **Description**: Email address to send notifications to. Supports a single address.

---

## GitHub Integration

```yaml
github:
  post_pr_comments: true
  post_inline_comments: true
  update_commit_status: true
  job_summary: true
```

### `github.post_pr_comments`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Post a summary comment on pull requests with scan results. The comment includes the overall score, severity breakdown, and top findings.

### `github.post_inline_comments`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Post inline review comments on specific lines where findings were detected. Only posts for findings that have a valid file and line number.

### `github.update_commit_status`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Update the GitHub commit status (pass/fail) based on scan results. This enables branch protection rules that require the SecureBuild status check to pass before merging.

### `github.job_summary`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Add a GitHub Actions job summary with the scan results. The summary is displayed on the Actions run page.

**Required environment variables for GitHub integration**:

- `GITHUB_TOKEN` — GitHub personal access token or Actions token
- `GITHUB_REPOSITORY` — Repository in `owner/repo` format (auto-set in Actions)
- `GITHUB_PULL_REQUEST_NUMBER` — PR number for comment posting

---

## Reporting Settings

```yaml
reporting:
  default_format: html
  include_charts: true
  include_code_snippets: true
  max_findings_per_gate: 100
```

### `reporting.default_format`

- **Type**: String (`html`, `pdf`, `json`, or `all`)
- **Default**: `html`
- **Description**: The default report format when no `--format` flag is specified. Use `all` to generate all three formats.

### `reporting.include_charts`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Include visual charts (severity distribution, gate score breakdown) in HTML and PDF reports. Charts are rendered using CSS and do not require JavaScript.

### `reporting.include_code_snippets`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Include code snippets in findings to show the vulnerable code in context. Snippets show 3 lines of context around the finding.

### `reporting.max_findings_per_gate`

- **Type**: Integer
- **Default**: `100`
- **Description**: Maximum number of findings to include per gate in the report. Findings beyond this limit are summarized with a count. This prevents excessively large reports for repositories with many findings.
- **Set to `0`** to include all findings (no limit).

---

## Environment Variables

Environment variables override configuration file values and are the recommended way to provide sensitive data (API keys, webhook URLs).

| Variable | Description | Overrides |
|---|---|---|
| `SECUREBUILD_SLACK_WEBHOOK` | Slack webhook URL | `notifications.slack.webhook_url` |
| `SECUREBUILD_FAIL_ON_CRITICAL` | Block on any critical finding | `thresholds.block_on.critical` |
| `SECUREBUILD_FAIL_ON_HIGH` | Block on any high finding | `thresholds.block_on.high` |
| `SECUREBUILD_WARN_ONLY` | Never block pipeline | `thresholds.warn_only` |
| `DB_PATH` | Database file path | Default `data/securebuild.db` |
| `GITHUB_TOKEN` | GitHub API token | Required for GitHub integration |
| `GITHUB_REPOSITORY` | Repository in `owner/repo` format | Auto-detected in Actions |
| `FLASK_SECRET_KEY` | Flask session secret key | Auto-generated if not set |
| `SECUREBUILD_CONFIG` | Path to config file | `--config` CLI argument |
| `SECUREBUILD_OUTPUT_DIR` | Report output directory | `reporting.output_dir` |

### `.env` File Support

SecureBuild loads environment variables from a `.env` file in the project root if `python-dotenv` is installed. This is the recommended way to manage secrets locally:

```bash
# .env file
SECUREBUILD_SLACK_WEBHOOK=https://hooks.slack.com/services/T.../B.../xxx
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
DB_PATH=/var/lib/securebuild/securebuild.db
FLASK_SECRET_KEY=your-secret-key-here
```

---

## Configuration Examples

### Minimal Configuration (Open Source Python)

```yaml
project:
  name: "my-open-source-project"
  type: open_source
  language: python

gates:
  secrets:
    enabled: true
  sast:
    enabled: true
  cve:
    enabled: true
  license:
    enabled: true
  iac:
    enabled: true

thresholds:
  block_on:
    critical: 1
    high: 5
    score: 7.0
  warn_only: false
```

### Strict Commercial Configuration

```yaml
project:
  name: "enterprise-saas"
  type: commercial
  language: both

gates:
  secrets:
    enabled: true
    custom_patterns:
      - name: "Internal Service Token"
        pattern: "SVC_TKN_[A-Za-z0-9]{40}"
    exclude_paths:
      - "tests/fixtures/**"
  sast:
    enabled: true
    incremental_scan: true
    exclude_paths: ["migrations/**", "*/tests/**", "*/__tests__/**"]
  cve:
    enabled: true
    check_stale_days: 365
    check_licenses: true
  license:
    enabled: true
    allowed_licenses:
      - MIT
      - Apache-2.0
      - BSD-2-Clause
      - BSD-3-Clause
      - ISC
      - PSF
      - Proprietary
    blocked_licenses:
      - AGPL-3.0
      - GPL-2.0
      - GPL-3.0
  iac:
    enabled: true
    check_docker: true
    check_compose: true
    check_k8s: true
    check_github_actions: true
    terraform_experimental: false

thresholds:
  block_on:
    critical: 1
    high: 3
    score: 5.0
  warn_only: false

notifications:
  slack:
    enabled: true
    webhook_url: ""  # Set via SECUREBUILD_SLACK_WEBHOOK env var
  email:
    enabled: true
    smtp_host: "smtp.office365.com"
    smtp_port: 587
    to_address: "security@company.com"

github:
  post_pr_comments: true
  post_inline_comments: true
  update_commit_status: true
  job_summary: true
```

### Development-Only Configuration (Warn Mode)

```yaml
project:
  name: "my-project"
  type: open_source
  language: python

gates:
  secrets:
    enabled: true
  sast:
    enabled: true
  cve:
    enabled: true
  license:
    enabled: false  # Skip license checking during development
  iac:
    enabled: true

thresholds:
  block_on:
    critical: 999  # Effectively never block on critical count
    high: 999      # Effectively never block on high count
    score: 10.0    # Effectively never block on score
  warn_only: true  # Always report, never block
```
