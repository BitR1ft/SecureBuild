# API Reference

> The SecureBuild REST API was removed as part of project scope reduction.
> All scan data is accessible through the web dashboard and CLI commands.

---

## Accessing Scan Data

Use the following alternatives to query scan results programmatically:

### CLI

```bash
# View recent scan history
python cli.py history --limit 50

# Export a specific run as JSON
python cli.py report <run_id> --format json --output scan.json
```

### JSON Reports

Every scan produces a JSON report at `reports/securebuild-{run_id}.json` containing
the complete `RunResult` including all gate results, findings, and the risk score.

```json
{
  "run_id": "20260602-39a8f9cc",
  "repo": "VaultGuard",
  "branch": "main",
  "commit_hash": "cd1e358247a4...",
  "timestamp": "2026-06-02T04:03:24Z",
  "status": "pass",
  "overall_score": 32.4,
  "duration_ms": 7650,
  "gate_results": [...],
  "findings": [...]
}
```

### Direct Database Access

The SQLite database (`securebuild.db`) can be queried directly:

```bash
# List all runs
sqlite3 securebuild.db "SELECT id, repo, status, overall_score, timestamp FROM pipeline_runs ORDER BY timestamp DESC LIMIT 10;"

# Count findings by severity for a specific run
sqlite3 securebuild.db "SELECT severity, COUNT(*) FROM findings WHERE run_id='20260602-39a8f9cc' GROUP BY severity;"
```

### Web Dashboard

Open `http://localhost:5000` after running `python cli.py dashboard` to browse
scan history and click any row to view the full HTML report.
