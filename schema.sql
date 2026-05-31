-- ============================================================================
-- SecureBuild CI/CD Security Gate - Database Schema
-- ============================================================================
-- SQLite schema for persisting pipeline runs, gate results, findings,
-- and API keys. Uses foreign key constraints and indexes for query
-- performance and data integrity.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Pipeline Runs
-- ---------------------------------------------------------------------------
-- Stores the top-level record for each SecureBuild pipeline execution.
-- One row per run, linked to gate_results and findings via run_id.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pipeline_runs (
    id              TEXT PRIMARY KEY,          -- Unique run ID (e.g., "20250510-a3f2c1d4")
    repo            TEXT NOT NULL,             -- Repository name or path
    branch          TEXT NOT NULL,             -- Git branch name
    timestamp       TEXT NOT NULL,             -- ISO 8601 UTC timestamp
    overall_score   REAL NOT NULL DEFAULT 0.0, -- Aggregate security score (0-100, higher is better)
    status          TEXT NOT NULL DEFAULT 'pass', -- Overall status: "pass", "fail", "error"
    commit_hash     TEXT NOT NULL DEFAULT '',  -- Full git commit SHA
    duration_ms     INTEGER NOT NULL DEFAULT 0, -- Total run duration in milliseconds
    metadata        TEXT                       -- JSON blob with additional run metadata
);

-- Indexes for common query patterns on pipeline_runs
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_repo ON pipeline_runs(repo);
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_timestamp ON pipeline_runs(timestamp);
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_status ON pipeline_runs(status);
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_score ON pipeline_runs(overall_score);

-- ---------------------------------------------------------------------------
-- Gate Results
-- ---------------------------------------------------------------------------
-- Stores the outcome of each security gate within a pipeline run.
-- One row per gate execution, linked to pipeline_runs via run_id.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS gate_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL,             -- Foreign key to pipeline_runs.id
    gate_name       TEXT NOT NULL,             -- Name of the gate (e.g., "secrets", "sast")
    findings_count  INTEGER NOT NULL DEFAULT 0, -- Total number of findings
    severity        TEXT NOT NULL DEFAULT 'info', -- Highest severity among findings
    duration_ms     INTEGER NOT NULL DEFAULT 0,  -- Gate execution time in milliseconds
    status          TEXT NOT NULL DEFAULT 'pass', -- Gate status: "pass", "fail", "error"
    metadata        TEXT,                      -- JSON blob with gate-specific metadata
    FOREIGN KEY (run_id) REFERENCES pipeline_runs(id) ON DELETE CASCADE
);

-- Indexes for gate_results
CREATE INDEX IF NOT EXISTS idx_gate_results_run_id ON gate_results(run_id);
CREATE INDEX IF NOT EXISTS idx_gate_results_gate_name ON gate_results(gate_name);
CREATE INDEX IF NOT EXISTS idx_gate_results_status ON gate_results(status);
CREATE INDEX IF NOT EXISTS idx_gate_results_severity ON gate_results(severity);

-- ---------------------------------------------------------------------------
-- Findings
-- ---------------------------------------------------------------------------
-- Stores individual security findings detected by gates.
-- One row per finding, linked to pipeline_runs via run_id.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL,             -- Foreign key to pipeline_runs.id
    gate            TEXT NOT NULL,             -- Name of the gate that produced this finding
    file            TEXT NOT NULL DEFAULT '',  -- Relative file path
    line            INTEGER NOT NULL DEFAULT 0, -- Line number (0 if not applicable)
    message         TEXT NOT NULL DEFAULT '',  -- Human-readable description
    cvss_score      REAL NOT NULL DEFAULT 0.0, -- CVSS v3.1 base score (0.0 - 10.0)
    severity        TEXT NOT NULL DEFAULT 'info', -- Severity: "critical", "high", "medium", "low", "info"
    fix_suggestion  TEXT NOT NULL DEFAULT '',  -- Human-readable fix suggestion
    cwe_id          TEXT NOT NULL DEFAULT '',  -- CWE identifier (e.g., "CWE-79")
    rule_id         TEXT NOT NULL DEFAULT '',  -- Rule/pattern that triggered this finding
    finding_type    TEXT NOT NULL DEFAULT 'vulnerability', -- Category of finding
    confidence      TEXT NOT NULL DEFAULT 'medium', -- Confidence: "high", "medium", "low"
    fix_diff        TEXT NOT NULL DEFAULT '',  -- Unified diff showing the proposed fix
    FOREIGN KEY (run_id) REFERENCES pipeline_runs(id) ON DELETE CASCADE
);

-- Indexes for findings
CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_gate ON findings(gate);
CREATE INDEX IF NOT EXISTS idx_findings_cwe_id ON findings(cwe_id);
CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_finding_type ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file);

-- ---------------------------------------------------------------------------
-- API Keys
-- ---------------------------------------------------------------------------
-- Stores hashed API keys for authenticating with the SecureBuild API.
-- Keys are stored as SHA-256 hashes — the plaintext key is never persisted.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash        TEXT NOT NULL UNIQUE,      -- SHA-256 hash of the API key
    name            TEXT NOT NULL DEFAULT '',  -- Human-readable name/description
    created_at      TEXT NOT NULL,             -- ISO 8601 timestamp of creation
    last_used       TEXT,                      -- ISO 8601 timestamp of last use
    active          INTEGER NOT NULL DEFAULT 1 -- 1 = active, 0 = revoked
);

-- Index for API key lookups
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(active);
