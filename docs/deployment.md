# Deployment Guide

> SecureBuild CI/CD Security Gate — Running SecureBuild locally and in CI/CD pipelines

---

## Table of Contents

- [Local Deployment](#local-deployment)
- [GitHub Actions Integration](#github-actions-integration)
- [Production Considerations](#production-considerations)
- [Troubleshooting](#troubleshooting)

---

## Local Deployment

### Prerequisites

| Requirement | Minimum | Notes |
|---|---|---|
| Python | 3.11+ | Required for modern type hints |
| pip | any | For package installation |
| Git | any | Required for repository metadata (branch, commit) |
| Disk | 100 MB | For database and reports |

### Installation Steps

```bash
# 1. Clone the repository
git clone https://github.com/your-org/securebuild.git
cd securebuild

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate    # Linux / macOS
# venv\Scripts\activate     # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify
python cli.py --help

# 5. Create a configuration file
python cli.py init

# 6. Run your first scan
python cli.py scan /path/to/your/repo
```

### Database

SecureBuild stores all scan results in a local SQLite file. By default this is `securebuild.db` in the project root — the same directory where you run `python cli.py`.

All commands (`scan`, `history`, `report`, `dashboard`) read `securebuild.yaml` automatically and use the same database path, so no extra configuration is needed to make history and the dashboard show your scans.

To use a custom location:

```bash
export DB_PATH=/data/securebuild.db
python cli.py scan /path/to/repo
python cli.py history         # reads from /data/securebuild.db automatically
python cli.py dashboard       # same
```

### Dashboard

```bash
# Start on default port 5000
python cli.py dashboard

# Custom port
python cli.py dashboard --port 8080

# Set a custom Flask secret key (recommended for shared machines)
export FLASK_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python cli.py dashboard
```

Open `http://localhost:5000` in your browser. Click any scan row to open the full HTML security report in a new tab.

### Keeping the Dashboard Running (Linux systemd)

To run the dashboard as a background service:

```ini
# /etc/systemd/system/securebuild.service
[Unit]
Description=SecureBuild Dashboard
After=network.target

[Service]
Type=simple
User=securebuild
WorkingDirectory=/opt/securebuild
Environment=FLASK_SECRET_KEY=your-secret-key-here
ExecStart=/opt/securebuild/venv/bin/python cli.py dashboard --host 0.0.0.0 --port 5000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable securebuild
sudo systemctl start securebuild
sudo systemctl status securebuild
```

---

## GitHub Actions Integration

Add SecureBuild to your CI/CD pipeline:

```yaml
# .github/workflows/securebuild.yml
name: Security Gate

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for better branch/commit metadata

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install SecureBuild
        run: pip install -r requirements.txt

      - name: Run Security Scan
        run: python cli.py scan . --format all --output-dir reports

      - name: Upload Reports
        if: always()   # Upload even if the scan blocks
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: reports/
```

### Running Only Specific Gates in CI

```yaml
      - name: Run secrets gate only (fast pre-check)
        run: python cli.py scan . --gates secrets --format json
```

### Non-Blocking Mode

Use `--dry-run` to always get the report without blocking the pipeline:

```yaml
      - name: Security scan (report only)
        run: python cli.py scan . --dry-run --format html
```

---

## Production Considerations

### Database Maintenance

The SQLite database grows over time as you accumulate scan history. Periodically archive or clean up old runs:

```bash
# Backup the database
cp securebuild.db securebuild-$(date +%Y%m%d).db

# Check database size
du -sh securebuild.db

# Remove runs older than 90 days (run from SQLite shell)
sqlite3 securebuild.db \
  "DELETE FROM pipeline_runs WHERE timestamp < datetime('now', '-90 days');"
```

### Security Notes

- The dashboard runs on HTTP by default — put it behind a reverse proxy (Nginx/Caddy) with TLS for shared environments
- The `securebuild.db` file contains full finding details; restrict filesystem access appropriately
- Set `FLASK_SECRET_KEY` to a random value to protect session cookies

### Nginx Reverse Proxy (Optional)

```nginx
server {
    listen 443 ssl;
    server_name securebuild.example.com;

    ssl_certificate /etc/ssl/certs/securebuild.crt;
    ssl_certificate_key /etc/ssl/private/securebuild.key;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Troubleshooting

### Common Issues

| Problem | Likely Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'flask'` | Dependencies not installed | `pip install -r requirements.txt` |
| `history` shows "No scan history found" | Wrong database file | Ensure `securebuild.yaml` is in the directory where you run CLI commands, or set `DB_PATH` |
| Dashboard shows no runs | DB path mismatch | Run `python cli.py history` first to verify the DB contains data |
| `bandit` not found | Optional tool missing | `pip install bandit` or the built-in AST scanner will be used |
| `semgrep` not found | Optional tool missing | `pip install semgrep` or Bandit/AST fallback will be used |
| Report not generating | Write permission | Check that the `reports/` directory is writable |
| Score is 0.0 / very low | High CVSS findings | Review findings — a CVSS 9.x finding with weight 1.5 significantly impacts the score |

### Database Path Debugging

If history or the dashboard is empty after a scan, check which database each command is using:

```bash
# The INFO log line shows the actual DB path used
python cli.py history
# [INFO] Database schema initialized at securebuild.db   ← correct
# [INFO] Database schema initialized at data/securebuild.db  ← mismatch!

# Fix: ensure securebuild.yaml is present in the current directory
ls securebuild.yaml   # should exist
```

### Getting Help

```bash
# View all available commands
python cli.py --help

# View help for a specific command
python cli.py scan --help
python cli.py dashboard --help
```
