# CLI Reference

> SecureBuild CI/CD Security Gate — Command-Line Interface Reference

All commands are invoked via `python cli.py <command> [options]`.

---

## Table of Contents

- [scan](#scan)
- [init](#init)
- [dashboard](#dashboard)
- [history](#history)
- [report](#report)
- [Exit Codes](#exit-codes)
- [Environment Variables](#environment-variables)

---

## `scan`

Run a full security scan on a local repository.

```bash
python cli.py scan <repo_path> [options]
```

### Arguments

| Argument | Description |
|---|---|
| `repo_path` | Absolute or relative path to the repository to scan |

### Options

| Flag | Default | Description |
|---|---|---|
| `--config`, `-c` | auto-detected | Path to `securebuild.yaml` |
| `--output-dir`, `-o` | `./reports` | Directory to write report files into |
| `--format`, `-f` | `all` | Report format: `html`, `json`, or `all` |
| `--threshold`, `-t` | from config | Override the score threshold |
| `--dry-run` | off | Run all gates but never block the pipeline |
| `--gates` | all enabled | Space-separated list of gates to run: `secrets sast cve license iac` |
| `--verbose`, `-v` | off | Enable DEBUG-level logging |

### Examples

```bash
# Basic scan — generates both HTML and JSON reports
python cli.py scan /path/to/repo

# Generate JSON only
python cli.py scan /path/to/repo --format json

# Run only the secrets and SAST gates
python cli.py scan /path/to/repo --gates secrets sast

# Dry-run: report findings but never exit with code 1
python cli.py scan /path/to/repo --dry-run

# Verbose debug output
python cli.py scan /path/to/repo --verbose

# Custom output directory and config
python cli.py scan /path/to/repo --output-dir ./security-reports --config ./custom.yaml
```

### Output

The scan command prints a summary table to stdout:

```
SecureBuild Security Scan
==================================================
  Repository : /home/user/my-project
  Output     : ./reports
  Format     : all

Scan Results Summary
──────────────────────────────────────────────────────────────────────
  Run ID       : 20260602-39a8f9cc
  Repository   : my-project
  Branch       : main
  Commit       : cd1e358247a4
  Timestamp    : 2026-06-02T04:03:24+00:00
  Duration     : 7650ms
  Overall Score: 32.4/100
  Status       : PASS

  Gate        Status   Findings  Critical  High   Duration
  ──────────────────────────────────────────────────────
  secrets     PASS      3         0         1      89ms
  sast        PASS      8         0         2      7638ms
  cve         PASS      0         0         0      64ms
  license     PASS      0         0         0      48ms
  iac         PASS      0         0         0      46ms

  HTML report : reports/securebuild-20260602-39a8f9cc.html
  JSON report : reports/securebuild-20260602-39a8f9cc.json

Pipeline PASSED: all security gates clear
```

### Generated Files

| File | Description |
|---|---|
| `securebuild-{run_id}.html` | Self-contained HTML security report |
| `securebuild-{run_id}.json` | Machine-readable JSON export of all findings |

---

## `init`

Create a `securebuild.yaml` configuration file in the current directory with sensible defaults.

```bash
python cli.py init [options]
```

### Options

| Flag | Default | Choices | Description |
|---|---|---|---|
| `--project-type` | `open_source` | `open_source`, `commercial` | Sets default license policies |
| `--language` | `python` | `python`, `javascript`, `both` | Optimises gate configuration for your stack |

### Examples

```bash
# Defaults (open-source Python project)
python cli.py init

# Commercial JavaScript project
python cli.py init --project-type commercial --language javascript

# Polyglot project
python cli.py init --language both
```

---

## `dashboard`

Start the Flask web dashboard for browsing scan history and viewing HTML reports.

```bash
python cli.py dashboard [options]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--host` | `0.0.0.0` | Interface to bind to |
| `--port` | `5000` | Port to listen on |
| `--debug` | off | Enable Flask debug mode |

### Examples

```bash
# Start on default port
python cli.py dashboard

# Start on a custom port
python cli.py dashboard --port 8080

# Local-only access
python cli.py dashboard --host 127.0.0.1
```

Then open `http://localhost:5000` in your browser.

### Dashboard Pages

| Page | URL | Description |
|---|---|---|
| Home | `/` | Metric overview and recent scans |
| Run History | `/runs` | Paginated list with filters |
| HTML Report | `/runs/<run_id>/report` | Full generated report (opens on row click) |

> **Tip**: Click any row on the Home or Run History pages to open the full HTML report for that scan in a new browser tab.

---

## `history`

Print scan history from the local database to the terminal.

```bash
python cli.py history [options]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--limit`, `-n` | `10` | Number of runs to display |
| `--repo`, `-r` | all | Filter by repository name |

### Examples

```bash
# Show last 10 runs
python cli.py history

# Show last 50 runs
python cli.py history --limit 50

# Filter to a specific project
python cli.py history --repo VaultGuard
```

---

## `report`

Generate a fresh report for a previous scan run using data stored in the database.

```bash
python cli.py report <run_id> [options]
```

### Arguments

| Argument | Description |
|---|---|
| `run_id` | The run ID to generate the report for (e.g. `20260602-39a8f9cc`) |

### Options

| Flag | Default | Choices | Description |
|---|---|---|---|
| `--format`, `-f` | `html` | `html`, `json` | Output format |
| `--output`, `-o` | auto | — | Custom output file path |

### Examples

```bash
# Re-generate the HTML report for a previous run
python cli.py report 20260602-39a8f9cc

# Generate a JSON export
python cli.py report 20260602-39a8f9cc --format json

# Write to a specific path
python cli.py report 20260602-39a8f9cc --output ./audit/report.html
```

---

## Exit Codes

| Code | Meaning | CI/CD Action |
|---|---|---|
| `0` | Pipeline passed — all gates clear | Continue deployment |
| `1` | Pipeline blocked — gate failure or threshold exceeded | Block deployment |
| `2` | Scan errored — unexpected exception during gate execution | Investigate logs |

### Using in CI/CD

```bash
# Fail CI job if SecureBuild blocks
python cli.py scan . || exit 1

# Always continue (report only)
python cli.py scan . --dry-run

# Capture exit code for custom handling
python cli.py scan /path/to/repo
RESULT=$?
if [ $RESULT -eq 1 ]; then
  echo "Security gate blocked the pipeline!"
fi
```

---

## Environment Variables

| Variable | Description | Example |
|---|---|---|
| `DB_PATH` | Override the database file path | `export DB_PATH=/data/securebuild.db` |
| `SECUREBUILD_CONFIG` | Path to config file (alternative to `--config`) | `export SECUREBUILD_CONFIG=/etc/securebuild.yaml` |
| `FLASK_SECRET_KEY` | Secret key for the Flask dashboard session | `export FLASK_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")` |

> **Note on Database Consistency**: All CLI commands (`scan`, `history`, `report`, `dashboard`) automatically read `securebuild.yaml` to determine the database path. This means they all use the **same database file** without requiring `DB_PATH` to be set manually.
