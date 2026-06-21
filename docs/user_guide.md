# User Guide

> SecureBuild CI/CD Security Gate — Getting Started Guide

This guide walks you through installing, configuring, and using SecureBuild to improve your project's security posture. By the end, you'll know how to run scans, interpret results, configure thresholds, and fix common findings.

---

## Table of Contents

- [5 Minutes to Your First Scan](#5-minutes-to-your-first-scan)
- [Configuring Thresholds](#configuring-thresholds)
- [Reading the Dashboard](#reading-the-dashboard)
- [Interpreting Reports](#interpreting-reports)
- [Fixing Common Findings](#fixing-common-findings)
- [Troubleshooting FAQ](#troubleshooting-faq)

---

## 5 Minutes to Your First Scan

### Step 1: Install SecureBuild (1 minute)

```bash
# Clone and install
git clone https://github.com/your-org/securebuild.git
cd securebuild
pip install -r requirements.txt
```

### Step 2: Initialize Configuration (30 seconds)

```bash
python cli.py init --project-type open_source --language python
```

This creates a `securebuild.yaml` file with sensible defaults. You can edit it later, but the defaults work for most projects.

### Step 3: Run Your First Scan (2 minutes)

```bash
python cli.py scan /path/to/your/project
```

SecureBuild will:
1. Walk through your repository, scanning all text files
2. Run 5 security gates in parallel
3. Compute an overall risk score
4. Print a summary to your terminal
5. Generate an HTML report in the `reports/` directory

### Step 4: View the Report (1 minute)

Open the HTML report in your browser:

```bash
# macOS
open reports/securebuild-*.html

# Linux
xdg-open reports/securebuild-*.html

# Windows
start reports/securebuild-*.html
```

The report includes:
- **Summary cards**: Run ID, status, overall score, risk level
- **Severity breakdown**: Count of findings by severity level
- **Gate results**: Status and findings count for each gate
- **Findings detail**: Every finding with file location, CVSS score, CWE, and fix suggestion

### What Just Happened?

SecureBuild scanned your code through 5 independent security gates:

| Gate | What It Checks |
|---|---|
| **Secrets** | Hardcoded passwords, API keys, tokens, private keys |
| **SAST** | Code vulnerabilities like SQL injection, eval(), command injection |
| **CVE** | Known vulnerabilities in your dependencies |
| **License** | License compliance issues in your dependencies |
| **IaC** | Dockerfile, Docker Compose, Kubernetes, and GitHub Actions misconfigurations |

Each finding includes:
- **Severity**: How serious the issue is (Critical → Info)
- **CVSS Score**: A standardized vulnerability score (0.0–10.0)
- **CWE ID**: The Common Weakness Enumeration identifier
- **Fix Suggestion**: A specific, actionable recommendation

---

## Configuring Thresholds

SecureBuild uses thresholds to determine whether to block a pipeline. By default, the pipeline is blocked if:

- **Any critical finding** is found
- **5 or more high findings** are found
- **The risk score exceeds 7.0** (on a 0–10 scale)

### Adjusting Thresholds

Edit `securebuild.yaml`:

```yaml
thresholds:
  block_on:
    critical: 1    # Block if any critical finding
    high: 5        # Block if 5+ high findings
    score: 7.0     # Block if risk score > 7.0
  warn_only: false  # Set to true for reporting-only mode
```

### When to Use `warn_only: true`

Set `warn_only: true` during initial rollout to:
- Assess your current security posture without blocking developers
- Identify which findings are false positives for your project
- Tune your exclusion patterns before enforcing policies

```yaml
thresholds:
  warn_only: true   # Never block, always report
```

With `warn_only: true`, SecureBuild always exits with code 0, even if findings are detected. You'll still see all findings in the terminal output and reports.

### Per-Severity Thresholds Explained

| Threshold | Effect | Recommendation |
|---|---|---|
| `critical: 0` | Block on any critical finding | **Recommended** — Critical findings represent immediate risk |
| `critical: 1` | Allow 1 critical finding before blocking | Use during active remediation of a known critical issue |
| `high: 3` | Block if 3+ high findings | Stricter than default; good for security-critical projects |
| `high: 10` | Allow up to 10 high findings | Permissive; use for projects with significant technical debt |
| `score: 5.0` | Block on medium risk or above | Very strict; suitable for financial/healthcare projects |
| `score: 9.0` | Block only on critical risk | Very permissive; suitable for internal tools |

---

## Reading the Dashboard

Start the web dashboard:

```bash
python cli.py dashboard
```

Open `http://localhost:5000` in your browser.

### Home Page

The dashboard home page shows:

- **Total Runs**: How many scans have been completed
- **Critical Count**: Number of critical findings in the last 30 days
- **High Count**: Number of high findings in the last 30 days
- **Average Score**: Mean security score across all runs

### Recent Scans Table

| Column | Meaning |
|---|---|
| **Run ID** | Unique identifier for the scan |
| **Repository** | Which repo was scanned |
| **Branch** | Git branch that was scanned |
| **Score** | Security score (0–100, higher is better) |
| **Status** | PASS, FAIL, or ERROR |
| **Findings** | Total number of security findings |
| **Timestamp** | When the scan ran |
| **Duration** | How long the scan took |

### Understanding Scores

| Score Range | Risk Level | Color | Interpretation |
|---|---|---|---|
| 80–100 | Minimal | Green | Excellent security posture |
| 60–79 | Low | Light green | Good posture, minor issues |
| 40–59 | Medium | Yellow | Several issues need attention |
| 20–39 | High | Orange | Significant risk, prioritize fixes |
| 0–19 | Critical | Red | Severe risk, block deployment |

### Trend Indicators

The trend column shows how your security posture is changing:

| Trend | Meaning | Action |
|---|---|---|
| 🟢 `improving` | Risk score decreased by 0.5+ | Keep up the good work |
| 🟡 `stable` | Risk score changed by less than 0.5 | Maintain current practices |
| 🔴 `degrading` | Risk score increased by 0.5+ | Investigate new findings |
| ⚫ `critical_regression` | Risk score increased by 2.0+ | Immediate action required |
| 🔵 `new` | No previous scan for this repo | Establish a baseline |

---

## Interpreting Reports

### HTML Report Sections

#### Summary Cards

The top of the report displays key metrics:

- **Run ID**: The unique scan identifier (for referencing this scan)
- **Status**: PASS or FAIL (whether the pipeline would be blocked)
- **Overall Score**: 0–100, where higher is better
- **Risk Level**: Minimal, Low, Medium, High, or Critical
- **Repository**: Which repo was scanned
- **Branch**: Git branch name
- **Total Findings**: Count of all security findings
- **Duration**: Total scan time

#### Severity Breakdown

The severity breakdown shows the count of findings at each severity level:

| Severity | Typical Response |
|---|---|
| **Critical** | Must fix immediately; blocks deployment |
| **High** | Should fix before next release; may block deployment |
| **Medium** | Should fix in upcoming sprints |
| **Low** | Fix during regular maintenance |
| **Info** | Informational; no action required |

#### Gate Results

The gate results table shows how each gate performed:

| Column | Meaning |
|---|---|
| **Gate** | Which security gate ran |
| **Status** | PASS (no blocking findings) or FAIL (blocking findings) |
| **Findings** | Total findings from this gate |
| **Duration** | How long this gate took |
| **Files Scanned** | How many files were checked |

#### Findings Detail

The findings table lists every security finding:

| Column | Meaning |
|---|---|
| **Severity** | How serious the finding is |
| **Gate** | Which gate produced the finding |
| **Location** | File path and line number |
| **Message** | What was found |
| **CVSS** | Standardized vulnerability score (0.0–10.0) |
| **CWE** | Common Weakness Enumeration ID |
| **Fix** | Suggested remediation |

### JSON Report

The JSON report contains the complete scan data in machine-readable format. Use it to:

- Integrate with other security tools
- Build custom dashboards
- Feed into ticketing systems (Jira, Linear, etc.)
- Track metrics over time

```bash
# Extract critical findings with jq
cat reports/securebuild-*.json | jq '.gate_results[].findings[] | select(.severity == "critical")'

# Count findings by severity
cat reports/securebuild-*.json | jq '.risk_score.by_severity'

# Get the overall risk score
cat reports/securebuild-*.json | jq '.risk_score.overall'
```

---

## Fixing Common Findings

### Hardcoded Secrets (Gate 1)

**Finding**: `Hardcoded API Key detected: 'sk_live_abc...'`

**Problem**: API keys, passwords, and tokens are stored directly in source code. Anyone with access to the repository can see them.

**Fix**:

```python
# ❌ Before (vulnerable)
api_key = "sk_live_abc123def456"

# ✅ After (secure)
import os
api_key = os.environ["STRIPE_API_KEY"]
```

**Additional steps**:
1. Move the secret to an environment variable or secrets manager
2. Add the secret to `.env` (and `.env` to `.gitignore`)
3. Provide a `.env.example` file with placeholder values
4. **Rotate the exposed key immediately** if it was committed to version control

### SQL Injection (Gate 2)

**Finding**: `SQL Injection via string formatting`

**Problem**: User input is concatenated directly into SQL queries, allowing attackers to inject malicious SQL.

**Fix**:

```python
# ❌ Before (vulnerable)
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# ✅ After (secure)
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

### eval() Usage (Gate 2)

**Finding**: `Use of eval() detected`

**Problem**: `eval()` executes arbitrary Python code, which can lead to code injection if the input is user-controlled.

**Fix**:

```python
# ❌ Before (vulnerable)
result = eval(user_expression)

# ✅ After (secure) — use ast.literal_eval for safe evaluation
import ast
result = ast.literal_eval(user_expression)

# ✅ Or use a proper parser/DSL for the use case
```

### Vulnerable Dependencies (Gate 3)

**Finding**: `Flask 2.0.1 has known CVE: CVE-2023-30861`

**Problem**: A dependency has a known security vulnerability.

**Fix**:

```bash
# Check what version is recommended
pip install --upgrade Flask

# Pin the secure version in requirements.txt
# ❌ Before: Flask==2.0.1
# ✅ After:  Flask>=2.3.2
```

### Docker Running as Root (Gate 5)

**Finding**: `Container runs as root`

**Problem**: Running as root inside a Docker container increases the impact of container escape vulnerabilities.

**Fix**:

```dockerfile
# ❌ Before (vulnerable)
FROM python:3.11
COPY . /app
CMD ["python", "app.py"]

# ✅ After (secure)
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app
COPY --chown=appuser:appuser . .

USER appuser
CMD ["python", "app.py"]
```

### Missing Resource Limits in Docker Compose (Gate 5)

**Finding**: `No CPU/memory resource limits defined`

**Problem**: Without resource limits, a compromised or misbehaving container can consume all host resources.

**Fix**:

```yaml
# ❌ Before (vulnerable)
services:
  web:
    image: my-app:latest

# ✅ After (secure)
services:
  web:
    image: my-app:1.2.3
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
```

### Suppressing False Positives

For findings that you've reviewed and confirmed as safe, use inline suppression:

```python
api_key = "test_key_12345"  # nosec — test fixture, not a real key
```

For broader exclusions, add patterns to `securebuild.yaml`:

```yaml
gates:
  secrets:
    exclude_paths:
      - "tests/fixtures/**"
      - "**/*.example"
```

---

## Troubleshooting FAQ

### Q: The scan is taking too long. What can I do?

**A**: Try these approaches:

1. **Run specific gates**: `python cli.py scan /repo --gates secrets sast`
2. **Exclude large directories**: Add paths to `exclude_paths` in `securebuild.yaml`
3. **Enable incremental scanning**: Set `gates.sast.incremental_scan: true`
4. **Skip optional gates**: Disable gates you don't need with `enabled: false`

### Q: I'm getting too many false positives. How do I reduce them?

**A**:

1. **Add exclusion paths**: Exclude test fixtures, config templates, and generated code
2. **Use `# nosec` comments**: Suppress individual false positives inline
3. **Adjust entropy threshold**: Increase `config.entropy_threshold` (default: 4.5) to reduce entropy-based FPs
4. **Disable specific sub-scanners**: For example, set `gates.iac.check_compose: false` if you don't use Docker Compose

### Q: The pipeline is blocked but I need to deploy. What should I do?

**A**:

1. **Review findings**: Check if any are false positives that can be suppressed
2. **Use dry-run mode**: `python cli.py scan /repo --dry-run` to see what would be blocked without actually blocking
3. **Use warn_only temporarily**: Set `thresholds.warn_only: true` for a grace period while fixing issues
4. **Adjust thresholds**: Increase `block_on.high` or `block_on.score` if current thresholds are too strict

### Q: How do I scan a repository that's not on my local machine?

**A**:

```bash
# Clone the repo first
git clone https://github.com/owner/repo.git /tmp/repo
python cli.py scan /tmp/repo

# Or trigger via API
curl -X POST -H "Authorization: Bearer <key>" \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/repos/my-project"}' \
  http://localhost:5000/api/v1/trigger
```

### Q: Can I use SecureBuild with a language other than Python or JavaScript?

**A**: Yes, with caveats:

- **Secret scanning** (Gate 1) works on any text files — it's language-agnostic
- **SAST** (Gate 2) requires Bandit (Python) or Semgrep (multi-language). The built-in scanner only supports Python. Install Semgrep for other languages.
- **CVE auditing** (Gate 3) currently parses `requirements.txt` and `package.json` only
- **License checking** (Gate 4) works with any Python or Node.js package
- **IaC scanning** (Gate 5) is language-agnostic — it checks Dockerfiles, K8s manifests, and GitHub Actions

### Q: How do I integrate SecureBuild with my existing CI/CD pipeline?

**A**: See the [Deployment Guide](deployment.md) for detailed instructions for GitHub Actions, GitLab CI, and generic CI/CD systems. The key is:

1. Install SecureBuild as a CI step
2. Run `python cli.py scan .` in your project directory
3. Use the exit code (0=pass, 1=fail) to control pipeline flow
4. Upload reports as artifacts for later review

### Q: Where is the data stored?

**A**: SecureBuild uses SQLite with the database file at `data/securebuild.db` by default. You can change this with the `DB_PATH` environment variable. The database contains all scan runs, findings, and API keys (hashed).

### Q: How do I clean up old scan data?

**A**:

```bash
# Delete runs older than 90 days from the database
sqlite3 data/securebuild.db "DELETE FROM pipeline_runs WHERE timestamp < datetime('now', '-90 days');"

# Clean up orphaned findings and gate results
sqlite3 data/securebuild.db "DELETE FROM findings WHERE run_id NOT IN (SELECT id FROM pipeline_runs);"
sqlite3 data/securebuild.db "DELETE FROM gate_results WHERE run_id NOT IN (SELECT id FROM pipeline_runs);"

# Reclaim disk space
sqlite3 data/securebuild.db "VACUUM;"
```

### Q: Can I share reports with my team?

**A**: Yes, several options:

1. **HTML reports**: Share the HTML file directly — it's self-contained with no external dependencies
2. **Dashboard**: Start the dashboard and share the URL (`python cli.py dashboard --host 0.0.0.0`)
3. **JSON reports**: Import into custom dashboards or security tools
4. **GitHub PR comments**: Enable `github.post_pr_comments: true` to automatically comment on pull requests
5. **Slack notifications**: Enable `notifications.slack.enabled: true` to post scan results to a Slack channel
