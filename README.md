# SecureBuild

By: Muhammad Adeel Haider (BitR1ft)
Air University · National Centre for Cyber Security (NCSA)

SecureBuild is a CI/CD security gate framework that evaluates source code, dependencies, infrastructure definitions, and licensing requirements before deployment.

The platform executes five independent security gates, aggregates findings into a weighted risk score, and enforces configurable policy thresholds. Scan results are persisted in SQLite and exposed through HTML reports, JSON exports, and a web dashboard.

## Features

* Secret and credential detection
* Static application security testing (SAST)
* Dependency vulnerability auditing
* License compliance validation
* Infrastructure-as-Code security analysis
* Weighted risk scoring and policy enforcement
* HTML and JSON reporting
* Historical scan tracking
* Web dashboard for result exploration

## Security Gates

| Gate               | Purpose                                                                  |
| ------------------ | ------------------------------------------------------------------------ |
| Secrets            | Detect hardcoded credentials, tokens, keys, and sensitive values         |
| SAST               | Identify insecure coding patterns and common application vulnerabilities |
| Dependency Audit   | Detect vulnerable or outdated third-party packages                       |
| License Compliance | Validate dependency licenses against organizational policy               |
| IaC Security       | Detect security misconfigurations in infrastructure definitions          |

## Architecture

```text
Repository
    │
    ▼
Orchestrator
    │
    ├── Secrets Scanner
    ├── SAST Engine
    ├── Dependency Audit
    ├── License Compliance
    └── IaC Security
    │
    ▼
Risk Scoring Engine
    │
    ├── SQLite Storage
    ├── HTML Reports
    ├── JSON Reports
    └── Web Dashboard
```

## Quick Start

```bash
pip install -r requirements.txt

python cli.py init

python cli.py scan /path/to/repository
```

## Example

```bash
python cli.py scan ./my-project
```

Output:

```text
Repository      : my-project
Overall Score   : 78.5/100
Status          : PASS

Gate            Findings
--------------------------------
Secrets         2
SAST            5
Dependencies    3
License         1
IaC             2
```

## Installation

### Requirements

* Python 3.11+
* Git
* pip

### Setup

```bash
git clone https://github.com/<org>/securebuild.git
cd securebuild

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

## Configuration

Generate a configuration template:

```bash
python cli.py init
```

Configuration is stored in `securebuild.yaml`.

```yaml
project:
  type: open_source

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
```

Detailed configuration options are documented in `docs/configuration.md`.

## Reporting

SecureBuild generates:

* HTML reports for human review
* JSON reports for automation and integrations

Reports are stored in the configured output directory and can be regenerated from historical scan data.

## Dashboard

Start the dashboard:

```bash
python cli.py dashboard
```

The dashboard provides:

* Scan history
* Risk trends
* Finding summaries
* Report navigation

## Documentation

* Configuration Guide
* Testing Guide
* Architecture Reference
* Risk Scoring Model

## License

Released under the MIT License.
