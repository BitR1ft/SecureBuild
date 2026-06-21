# Architecture

> SecureBuild CI/CD Security Gate — System Architecture Reference

---

## Table of Contents

- [System Overview](#system-overview)
- [Component Descriptions](#component-descriptions)
- [Data Flow](#data-flow)
- [Technology Decisions](#technology-decisions)
- [Database Schema](#database-schema)
- [Parallel Gate Execution](#parallel-gate-execution)
- [Scoring Algorithm](#scoring-algorithm)
- [Error Handling Strategy](#error-handling-strategy)

---

## System Overview

SecureBuild is structured around a **pipeline model**: a repository path enters the system, flows through five parallel security gates, is scored by a risk engine, persisted to SQLite, and reported as HTML/JSON. The web dashboard reads from the same database to display history.

### High-Level Component Diagram

```
                        CLI (cli.py)
                            │
                            ▼
                      Orchestrator
                   (engine/orchestrator.py)
                            │
             ┌────────────┼────────────┐
             │             │             │
             ▼             ▼             ▼
        Gate Runner    Risk Scorer    DatabaseManager
       (runner.py)    (scorer.py)       (db.py)
             │
    ┌───────┴───────┐
    │ 5 Gates (Parallel) │
    └───────────────┘
    gate1_secrets.py
    gate2_sast.py
    gate3_cve.py
    gate4_license.py
    gate5_iac.py

Outputs:
  ├─ SQLite DB (securebuild.db)
  ├─ HTML Report (reports/*.html)
  └─ JSON Report (reports/*.json)

Flask Dashboard (dashboard/):
  └─ Reads from securebuild.db
  └─ Renders reports on /runs/<id>/report
```

---

## Component Descriptions

### CLI (`cli.py`)

The entry point for all user interaction. Parses arguments, loads configuration, initialises the database connection, calls the Orchestrator, prints the summary table, and writes report files. All commands share the same database path resolution logic — they load `securebuild.yaml` automatically to find the correct `securebuild.db` location.

**Commands**: `scan`, `init`, `dashboard`, `history`, `report`

### Orchestrator (`engine/orchestrator.py`)

The pipeline controller. Receives a repository path, collects Git metadata (branch, commit hash), delegates gate execution to the Gate Runner, passes results to the Risk Scorer, and persists the `RunResult` to the database.

### Gate Runner (`engine/runner.py`)

Executes all enabled gates in parallel using `concurrent.futures.ThreadPoolExecutor`. Each gate runs in its own thread with a configurable timeout (default: 300 seconds). Gate failures are isolated — one gate erroring does not stop the others.

### Base Gate (`gates/base.py`)

Abstract base class that all gates inherit from. Defines the `scan()` interface, provides shared utilities (file discovery, path exclusion, binary file detection), and enforces per-gate configuration handling.

### Security Gates (`gates/gate*.py`)

Five independent, stateless gate implementations:

| Gate | File | What it scans |
|---|---|---|
| Gate 1: Secrets | `gate1_secrets.py` | Regex patterns + Shannon entropy |
| Gate 2: SAST | `gate2_sast.py` | Bandit, Semgrep, built-in AST scanner |
| Gate 3: CVE | `gate3_cve.py` | requirements.txt / package.json vs built-in CVE DB |
| Gate 4: License | `gate4_license.py` | pip-licenses / npm license resolution |
| Gate 5: IaC | `gate5_iac.py` | Dockerfile, Compose, Kubernetes, GitHub Actions |

### Risk Scorer (`scoring/scorer.py`)

Aggregates all gate findings into a single 0–100 risk score using weighted CVSS scores and severity multipliers. Also computes:
- **Trend**: compared against the last 5 runs for the same repository
- **Percentile**: compared against all runs in the database
- **Recommendation**: generated from the highest-CVSS finding

### Database Manager (`engine/db.py`)

SQLite persistence layer. All reads and writes go through this class. The database is auto-created and schema-initialised on first use. All commands resolve the database file path from `securebuild.yaml` — this ensures consistency across `scan`, `history`, `report`, and `dashboard`.

### Reporter (`reporter/`)

Generates scan reports:
- **HTML** (`renderer.py`): Self-contained HTML with inline CSS. Includes header, metric cards, severity breakdown, gate results table, and full findings detail with CVSS/CWE/fix suggestions.
- **JSON**: Produced directly in `cli.py` via `RunResult.to_dict()`.

### Flask Dashboard (`dashboard/`)

A Flask web application with three views:

| Blueprint | URL | Responsibility |
|---|---|---|
| `home_bp` | `/` | Metric cards + recent scans table |
| `runs_bp` | `/runs` | Paginated run history with filters |
| `runs_bp` | `/runs/<id>/report` | On-demand HTML report (generated from DB) |

The dashboard resolves its database path using the same `securebuild.yaml` lookup as the CLI, so it always points to the correct database.

### Configuration (`engine/config.py`)

Loads and validates `securebuild.yaml`. Provides a `SecureBuildConfig` dataclass with typed fields for all configuration options. Falls back to safe defaults for any missing keys.

### Models (`engine/models.py`)

Core dataclasses:

| Model | Purpose |
|---|---|
| `Finding` | Single security finding (severity, CVSS, CWE, file, line, message, fix) |
| `GateResult` | Output of one gate (status, findings list, duration, files scanned) |
| `RiskScore` | Aggregated score with trend, percentile, recommendation |
| `RunResult` | Complete pipeline run (all gate results, score, metadata) |

---

## Data Flow

### Phase 1: Input & Validation

```
CLI args → _load_config() → SecureBuildConfig
                                    │
                              repo path validation
                              git metadata collection
                              (branch, commit hash, repo name)
```

### Phase 2: Gate Execution

```
Orchestrator.run(repo_path)
    │
    ▼
GateRunner.run_all(gates)
    ├─ Thread: Gate1.scan(repo_path) → GateResult
    ├─ Thread: Gate2.scan(repo_path) → GateResult
    ├─ Thread: Gate3.scan(repo_path) → GateResult
    ├─ Thread: Gate4.scan(repo_path) → GateResult
    └─ Thread: Gate5.scan(repo_path) → GateResult
                    │
              [all complete]
                    │
                    ▼
              List[GateResult]
```

### Phase 3: Scoring & Decision

```
RiskScorer.compute(gate_results)
    │
    ├─ Weighted CVSS aggregation
    ├─ Severity multipliers
    ├─ Trend vs last 5 runs
    ├─ Percentile vs all runs
    └─ Recommendation from top finding
                    │
                    ▼
                RiskScore
                    │
              Pipeline status: PASS / FAIL
```

### Phase 4: Persistence & Output

```
RunResult ──┬───────────────── DatabaseManager.save_run()
           │                               (pipeline_runs + gate_results + findings)
           │
           └───────────────── _generate_reports()
                                   ├─ HTML: reports/securebuild-{run_id}.html
                                   └─ JSON: reports/securebuild-{run_id}.json
```

---

## Technology Decisions

| Decision | Choice | Rationale |
|---|---|---|
| **Database** | SQLite | Zero-config, file-based, no server needed, easy to backup |
| **Web Framework** | Flask | Lightweight, well-tested, no ORM overhead |
| **SAST Tools** | Bandit + Semgrep | Bandit excels at Python-specific checks; Semgrep provides multi-language rules |
| **Secret Detection** | Regex + Shannon Entropy | Regex catches known credential formats; entropy catches obfuscated or custom secrets |
| **Scoring Scale** | 0–100 | Human-intuitive, aligns with percentage-based thresholds |
| **Parallel Execution** | ThreadPoolExecutor | I/O-bound gate execution benefits from threading without GIL impact |
| **Report Formats** | HTML + JSON | HTML for human review; JSON for machine integration |
| **Config Format** | YAML | Human-readable, supports comments, widely understood |

---

## Database Schema

### `pipeline_runs`

| Column | Type | Description |
|---|---|---|
| `id` | TEXT PRIMARY KEY | Run ID (e.g. `20260602-39a8f9cc`) |
| `repo` | TEXT | Repository name |
| `branch` | TEXT | Git branch |
| `commit_hash` | TEXT | Full commit SHA |
| `timestamp` | TEXT | ISO-8601 timestamp |
| `status` | TEXT | `pass`, `fail`, or `error` |
| `overall_score` | REAL | 0–100 pipeline score |
| `duration_ms` | INTEGER | Total scan duration in milliseconds |
| `risk_score` | TEXT | JSON-serialized `RiskScore` |

### `gate_results`

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PRIMARY KEY | Auto-increment ID |
| `run_id` | TEXT | Foreign key → `pipeline_runs.id` |
| `gate_name` | TEXT | Gate identifier (e.g. `secrets`, `sast`) |
| `status` | TEXT | `pass`, `fail`, or `error` |
| `findings_count` | INTEGER | Total findings for this gate |
| `critical_count` | INTEGER | Critical-severity findings |
| `high_count` | INTEGER | High-severity findings |
| `duration_ms` | INTEGER | Gate execution time in milliseconds |
| `files_scanned` | INTEGER | Number of files examined |

### `findings`

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PRIMARY KEY | Auto-increment ID |
| `run_id` | TEXT | Foreign key → `pipeline_runs.id` |
| `gate` | TEXT | Gate that produced this finding |
| `severity` | TEXT | `critical`, `high`, `medium`, `low`, `info` |
| `file` | TEXT | Relative file path |
| `line` | INTEGER | Line number |
| `message` | TEXT | Human-readable description |
| `cvss_score` | REAL | CVSS v3 base score (0.0–10.0) |
| `cwe_id` | TEXT | CWE identifier (e.g. `CWE-798`) |
| `fix_suggestion` | TEXT | Remediation guidance |

---

## Parallel Gate Execution

All gates run concurrently inside a `ThreadPoolExecutor`:

```python
with ThreadPoolExecutor(max_workers=len(gates)) as executor:
    futures = {executor.submit(gate.scan, repo_path): gate for gate in gates}
    for future in as_completed(futures, timeout=timeout):
        result = future.result()
        gate_results.append(result)
```

**Performance benefit**: Without parallelism, 5 gates scanning a medium-sized repository take ~15–25 seconds sequentially. With parallelism, the total time equals roughly the slowest individual gate (SAST with Semgrep is typically the bottleneck at ~7–15 seconds).

**Thread safety**: Each gate is stateless — it reads files from disk and returns a `GateResult` without sharing any mutable state.

---

## Scoring Algorithm

The risk scorer converts raw findings into a 0–100 score:

**Step 1**: For each finding, compute its weighted contribution:

```
contribution = cvss_score × gate_weight × severity_multiplier
```

**Step 2**: Sum all contributions and normalize:

```
raw_score = sum(contributions) / total_weight
normalized = min(raw_score / 10.0, 1.0)   # cap at 1.0
final_score = normalized × 100            # 0–100 scale
```

**Gate weights**:

| Gate | Weight |
|---|---|
| Secrets | 1.5 |
| SAST | 1.3 |
| CVE | 1.2 |
| IaC | 1.1 |
| License | 0.8 |

**Severity multipliers**:

| Severity | Multiplier |
|---|---|
| Critical | 2.0 |
| High | 1.5 |
| Medium | 1.0 |
| Low | 0.5 |
| Info | 0.2 |

**Example**: A SAST gate finding of `HIGH` severity with CVSS 8.1:
```
contribution = 8.1 × 1.3 (SAST weight) × 1.5 (HIGH multiplier) = 15.795
```

---

## Error Handling Strategy

SecureBuild follows a **fail-safe** approach — errors are isolated and logged, never propagated to crash the pipeline:

| Scenario | Behaviour |
|---|---|
| One gate raises an exception | Gate status set to `error`; other gates continue |
| All gates error | Run status is `error` (not `fail`); exit code 2 |
| Database write fails | Logged as WARNING; scan result still printed and reported |
| External tool missing (Bandit/Semgrep) | Logged as INFO; built-in fallback scanner used |
| Report file cannot be written | Logged as WARNING; scan result unaffected |
| Config file missing | Safe defaults used; runs without a config file |
| Git metadata unavailable | Branch/commit recorded as `unknown`; scan proceeds |
