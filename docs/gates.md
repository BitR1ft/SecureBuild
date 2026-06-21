# Gate Technical Specifications

> SecureBuild CI/CD Security Gate — Detailed Specification for Each Security Gate

This document provides an in-depth technical specification for each of SecureBuild's five security gates, including detection capabilities, tools used, finding classification, CVSS mapping, known limitations, and performance characteristics.

---

## Table of Contents

- [Gate 1: Secrets & Credential Scanner](#gate-1-secrets--credential-scanner)
- [Gate 2: Static Application Security Testing (SAST)](#gate-2-static-application-security-testing-sast)
- [Gate 3: Dependency CVE Audit](#gate-3-dependency-cve-audit)
- [Gate 4: License Compliance Checker](#gate-4-license-compliance-checker)
- [Gate 5: Infrastructure-as-Code Security](#gate-5-infrastructure-as-code-security)
- [Cross-Gate Concerns](#cross-gate-concerns)

---

## Gate 1: Secrets & Credential Scanner

### Overview

| Property | Value |
|---|---|
| **Gate Name** | `secrets` |
| **Implementation** | `gates/gate1_secrets.py` |
| **Gate Weight** | 1.5 (highest — secrets are immediately exploitable) |
| **Finding Type** | `secret` |
| **Default CWE** | CWE-798 (Use of Hard-coded Credentials) |

### What It Detects

The Secrets Gate detects hardcoded sensitive information in source code using two complementary detection methods:

#### Pattern-Based Detection (9 core patterns + 5 .env patterns)

| Rule ID | Pattern | Description |
|---|---|---|
| `secrets-aws-access-key` | `AKIA[0-9A-Z]{16}` | AWS Access Key IDs start with `AKIA` followed by 16 uppercase alphanumeric characters |
| `secrets-aws-secret-key` | `AWS_SECRET_ACCESS_KEY\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}` | AWS Secret Access Key assignments |
| `secrets-github-pat` | `ghp_[a-zA-Z0-9]{36}` | GitHub Personal Access Tokens (new format) |
| `secrets-stripe-key` | `sk_live_[0-9a-zA-Z]{24}` | Stripe live secret keys |
| `secrets-jwt-token` | `eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}` | JSON Web Tokens (Base64-encoded header.payload.signature) |
| `secrets-private-key` | `-----BEGIN (?:RSA \|EC \|DSA )?PRIVATE KEY-----` | PEM-encoded private key headers |
| `secrets-password` | `(?:password\|passwd\|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]` | Hardcoded passwords in assignments |
| `secrets-api-key` | `(?:api[_-]?key\|apikey)\s*[=:]\s*['\"][^'\"]{10,}['\"]` | Hardcoded API keys in assignments |
| `secrets-generic-secret` | `(?:secret\|token\|auth)\s*[=:]\s*['\"][^'\"]{10,}['\"]` | Generic secret/token assignments |

#### .env Deep Scan Patterns (5 additional patterns)

| Rule ID | Pattern | Description |
|---|---|---|
| `secrets-env-credential` | `DATABASE_URL\|DB_PASSWORD\|MONGO_URI` | Database connection strings and credentials |
| `secrets-env-credential` | `SECRET_KEY\|APP_SECRET\|SESSION_SECRET` | Application-level secrets |
| `secrets-env-credential` | `SMTP_PASSWORD\|MAIL_PASSWORD\|EMAIL_PASSWORD` | Email/SMTP credentials |
| `secrets-env-credential` | `AWS_ACCESS_KEY_ID\|AWS_SECRET_ACCESS_KEY` | AWS credentials in .env format |
| `secrets-env-credential` | `STRIPE_SECRET_KEY\|STRIPE_PUBLISHABLE_KEY\|STRIPE_API_KEY` | Stripe API credentials |

#### Entropy-Based Detection

High-entropy strings that evade pattern-based detection are flagged using Shannon entropy analysis:

- **Threshold**: Entropy > 4.5 (configurable via `config.entropy_threshold`)
- **Minimum length**: 20 characters
- **Extraction**: String literals in quotes and assignment values
- **Rule ID**: `secrets-high-entropy`

Shannon entropy measures the randomness of a string. A string with entropy above 4.5 bits per character is likely a random key, token, or encoded secret rather than natural language text.

### Tools Used

| Tool | Purpose | Required |
|---|---|---|
| Python `re` module | Regex pattern matching | Yes (built-in) |
| `gates/entropy.py` | Shannon entropy calculation | Yes (built-in) |
| `detect-secrets` | Alternative/complementary secret scanner | No (optional) |

The built-in scanner is always available. When `detect-secrets` is installed, its findings can supplement the built-in patterns.

### Finding Classification

#### Severity Mapping

| Rule ID | Severity | CVSS | Confidence |
|---|---|---|---|
| `secrets-private-key` | Critical | 9.8 | High |
| `secrets-aws-access-key` | Critical | 9.1 | High |
| `secrets-aws-secret-key` | Critical | 9.1 | High |
| `secrets-github-pat` | Critical | 9.1 | High |
| `secrets-stripe-key` | Critical | 9.1 | High |
| `secrets-env-credential` | High | 8.0 | High |
| `secrets-password` | High | 7.5 | High |
| `secrets-api-key` | High | 7.5 | High |
| `secrets-jwt-token` | High | 7.5 | High |
| `secrets-high-entropy` | Medium | 6.5 | Low |
| `secrets-generic-secret` | Medium | 5.5 | Medium |

#### CVSS Mapping Logic

- **Critical (CVSS 9.1–9.8)**: Credentials that grant direct, immediate access to production systems (AWS keys, private keys, Stripe live keys). An attacker can exploit these within minutes of discovery.
- **High (CVSS 7.5–8.0)**: Credentials that grant access but may require additional steps to exploit (passwords need a login endpoint, JWTs may be expired, .env credentials need the application context).
- **Medium (CVSS 5.5–6.5)**: Potential secrets that require verification (high-entropy strings, generic secret patterns). These may be false positives.

### Known Limitations

1. **No git history scanning**: The current implementation only scans the working tree, not git commit history. Secrets deleted in recent commits may still be recoverable from git history.
2. **Entropy false positives**: High-entropy detection produces false positives on base64-encoded data, minified CSS/JS class names, encoded images, and test fixtures. The `# nosec` inline comment can suppress these.
3. **Pattern coverage**: The 9 core patterns cover the most common secret formats but do not cover every cloud provider, payment processor, or SaaS platform. Use `custom_patterns` to add organization-specific patterns.
4. **Multi-line secrets**: The regex engine operates line-by-line and may miss secrets split across multiple lines (e.g., PEM certificates with line breaks are caught by the header pattern, but the full key content is not verified).
5. **No validation**: Detected patterns are not validated against the provider's API (e.g., AWS keys are not checked against the AWS STS API). This avoids rate limiting and credential exposure but means some findings could be expired or invalid keys.

### False Positive Rate

| Detection Method | Estimated FP Rate | Mitigation |
|---|---|---|
| Pattern-based (cloud keys) | < 5% | Cloud key prefixes are unique and unlikely to appear in non-key contexts |
| Pattern-based (passwords/API keys) | 10–20% | Assignment patterns may match test fixtures, documentation, or config templates |
| .env deep scan | 5–10% | .env files with real credentials; `.env.example` files may trigger false positives |
| Entropy-based | 30–50% | High-entropy strings are common in encoded data, hashes, and test fixtures. Use `# nosec` to suppress |

### Performance Characteristics

| Repository Size | Files Scanned | Scan Time |
|---|---|---|
| Small (< 100 files) | ~80 | ~0.5s |
| Medium (100–1000 files) | ~600 | ~2s |
| Large (1000–5000 files) | ~3000 | ~8s |
| Very large (5000+ files) | ~8000 | ~25s |

Secret scanning is CPU-bound (regex matching + entropy calculation) and scales linearly with the number and size of files.

---

## Gate 2: Static Application Security Testing (SAST)

### Overview

| Property | Value |
|---|---|
| **Gate Name** | `sast` |
| **Implementation** | `gates/gate2_sast.py` |
| **Gate Weight** | 1.3 |
| **Finding Type** | `vulnerability` |
| **Default CWE** | Varies by vulnerability type |

### What It Detects

The SAST Gate detects code-level security vulnerabilities through static analysis:

#### External Tool Coverage

| Tool | Languages | Detection Focus |
|---|---|---|
| **Bandit** | Python | Python-specific anti-patterns: `exec()`, `eval()`, `pickle`, `yaml.load()`, `subprocess(shell=True)`, `assert` for security, `tempfile.mktemp()`, hardcoded SQL, weak crypto |
| **Semgrep** | Python, JavaScript, TypeScript, Go, Java, and more | Pattern-based vulnerability detection across multiple languages |

#### Built-in AST Scanner (Fallback)

When external tools are not available, the built-in Python AST scanner detects:

| Rule ID | Vulnerability | Detection Method |
|---|---|---|
| `sast-eval-usage` | Use of `eval()` | AST: `ast.Call` with `func.id == "eval"` |
| `sast-exec-usage` | Use of `exec()` | AST: `ast.Call` with `func.id == "exec"` |
| `sast-shell-injection` | `subprocess.call(shell=True)` | AST: `subprocess.call` with `shell=True` keyword arg |
| `sast-sql-injection` | SQL string formatting | AST: f-strings or `.format()` calls containing SQL keywords |
| `sast-insecure-deserialization` | `pickle.loads()` / `yaml.load()` | AST: `pickle.loads/calls` or `yaml.load` without `Loader` kwarg |
| `sast-weak-hash` | MD5/SHA1 usage | AST: `hashlib.md5` or `hashlib.sha1` calls |
| `sast-assert-security` | Assert for security checks | AST: `ast.Assert` in security-relevant contexts |
| `sast-tempfile-race` | `tempfile.mktemp()` | AST: `tempfile.mktemp` calls (race condition) |

### Tools Used

| Tool | Purpose | Required |
|---|---|---|
| Bandit | Python SAST | No (falls back to built-in scanner) |
| Semgrep | Multi-language SAST | No (falls back to built-in scanner) |
| Python `ast` module | Built-in AST scanning | Yes (built-in) |

### Finding Classification

#### Severity Mapping

| Vulnerability | Severity | CVSS | CWE |
|---|---|---|---|
| SQL Injection | Critical | 9.8 | CWE-89 |
| Command Injection | Critical | 9.1 | CWE-78 |
| Insecure Deserialization | High | 8.1 | CWE-502 |
| `eval()` / `exec()` | High | 7.5 | CWE-95 |
| Path Traversal | High | 7.5 | CWE-22 |
| `subprocess(shell=True)` | High | 7.5 | CWE-78 |
| `yaml.load()` without Loader | High | 7.5 | CWE-502 |
| `pickle.loads()` | High | 7.5 | CWE-502 |
| Weak Hash (MD5/SHA1) | Medium | 5.3 | CWE-328 |
| Assert for Security | Low | 3.5 | CWE-617 |
| `tempfile.mktemp()` | Medium | 5.3 | CWE-377 |

#### CVSS Mapping Logic

- **Critical (CVSS 9.1–9.8)**: Vulnerabilities that allow unauthenticated remote code execution or data access (SQL injection, command injection).
- **High (CVSS 7.5–8.1)**: Vulnerabilities that may require specific conditions but can lead to code execution or data compromise (deserialization, eval, path traversal).
- **Medium (CVSS 5.3)**: Vulnerabilities that degrade security posture but require additional attack steps (weak hashing, race conditions).
- **Low (CVSS 3.5)**: Bad practices that are unlikely to be directly exploitable (assert for security).

### Known Limitations

1. **Python-only AST scanner**: The built-in fallback scanner only analyzes Python files. JavaScript/TypeScript SAST requires Semgrep.
2. **No data flow analysis**: The built-in scanner performs pattern matching on AST nodes but does not track data flow across function boundaries. This means it cannot detect cases where user input flows into a vulnerable function through intermediate variables.
3. **No taint analysis**: User input sources (request parameters, environment variables) are not tracked to sinks (database queries, command execution). This limits detection of second-order injection vulnerabilities.
4. **Incremental scan limitations**: When `incremental_scan` is enabled, only changed files are scanned. Vulnerabilities in unchanged files that depend on changed code may be missed.
5. **Bandit/Semgrep output parsing**: Findings from external tools are normalized into the SecureBuild Finding model. Some tool-specific metadata may be lost in translation.

### False Positive Rate

| Detection Method | Estimated FP Rate | Mitigation |
|---|---|---|
| Bandit | 10–15% | Bandit has good precision for Python but may flag intentional `eval()` in template engines or DSLs |
| Semgrep | 10–20% | Depends on rule set; custom rules may have higher FP rates |
| Built-in AST scanner | 15–25% | Pattern-based detection without data flow analysis produces more FPs on complex code patterns |

### Performance Characteristics

| Repository Size | Scan Time (Bandit) | Scan Time (Built-in) |
|---|---|---|
| Small (< 100 files) | ~1s | ~0.3s |
| Medium (100–1000 files) | ~3s | ~1s |
| Large (1000–5000 files) | ~10s | ~4s |
| Very large (5000+ files) | ~30s | ~15s |

---

## Gate 3: Dependency CVE Audit

### Overview

| Property | Value |
|---|---|
| **Gate Name** | `dependencies` (internal), `cve` (config) |
| **Implementation** | `gates/gate3_cve.py` |
| **Gate Weight** | 1.2 |
| **Finding Type** | `dependency` |
| **Default CWE** | CWE-1104 (Use of Unmaintained Third Party Components) |

### What It Detects

The CVE Gate audits project dependencies for known vulnerabilities:

1. **Dependency parsing**: Extracts package names and versions from `requirements.txt` and `package.json`
2. **CVE lookup**: Cross-references each dependency against the built-in vulnerability database
3. **Staleness check**: Flags dependencies older than `check_stale_days` (default: 730 days)
4. **Upgrade suggestions**: Recommends specific version upgrades when available

#### Built-in CVE Database

The built-in database contains known vulnerabilities for common packages:

| Ecosystem | Packages Covered | Example CVEs |
|---|---|---|
| Python | Flask, Django, Requests, urllib3, Pillow, PyYAML, Jinja2, cryptography, SQLAlchemistry | CVE-2023-30861, CVE-2022-40897 |
| JavaScript | lodash, express, axios, node-forge, underscore | CVE-2021-23337, CVE-2022-38397 |

Each entry includes:
- Package name
- Affected version range
- Fixed version
- CVE identifier(s)
- CVSS score
- Brief description

### Tools Used

| Tool | Purpose | Required |
|---|---|---|
| Built-in CVE database | Vulnerability lookup | Yes (built-in) |
| `pip-licenses` | License resolution for dependencies | No (optional, for `check_licenses`) |
| `requirements.txt` parser | Python dependency extraction | Yes (built-in) |
| `package.json` parser | JavaScript dependency extraction | Yes (built-in) |

### Finding Classification

#### Severity Mapping

| Condition | Severity | CVSS |
|---|---|---|
| CVE with CVSS ≥ 9.0 | Critical | Per CVE |
| CVE with CVSS 7.0–8.9 | High | Per CVE |
| CVE with CVSS 4.0–6.9 | Medium | Per CVE |
| CVE with CVSS < 4.0 | Low | Per CVE |
| Dependency stale > check_stale_days | Medium | 5.3 |
| Dependency with no version pin | Low | 3.5 |
| Dependency with version range (>=) | Info | 0.0 |

#### CVSS Mapping Logic

CVE severity directly maps from the National Vulnerability Database (NVD) CVSS v3.1 base scores. When a CVE has multiple CVSS scores (v2 and v3.1), the v3.1 score is used. When only a v2 score is available, it is converted using the FIRST.org CVSS v2-to-v3 calculator approximation.

### Known Limitations

1. **Built-in database scope**: The built-in CVE database covers only the most common packages. It does not cover every package in PyPI or npm. For comprehensive coverage, integrate with an external vulnerability API (e.g., OSV, Snyk, Safety).
2. **No transitive dependency analysis**: Only direct dependencies listed in `requirements.txt` and `package.json` are checked. Transitive dependencies (dependencies of dependencies) are not analyzed.
3. **Version range parsing**: Complex version specifiers (e.g., `>=1.0,<2.0,!=1.3.5`) may not be perfectly parsed. The scanner errs on the side of reporting potential vulnerabilities.
4. **No lock file support**: `Pipfile.lock` and `package-lock.json` are not currently parsed. These would provide exact resolved versions for more accurate CVE matching.
5. **Database freshness**: The built-in CVE database is static and does not auto-update. It should be refreshed regularly (weekly recommended) by updating the SecureBuild package.

### False Positive Rate

| Detection Method | Estimated FP Rate | Mitigation |
|---|---|---|
| CVE database lookup | < 5% | CVEs are verified against NVD; version matching is the primary source of FPs |
| Staleness check | 15–25% | Not all stale dependencies are vulnerable; some are simply mature and stable |
| Version range matching | 10–15% | Complex version specifiers may be misinterpreted |

### Performance Characteristics

| Repository Size | Dependencies | Scan Time |
|---|---|---|
| Small (< 10 deps) | ~5 | ~0.1s |
| Medium (10–50 deps) | ~25 | ~0.5s |
| Large (50–200 deps) | ~100 | ~2s |
| Very large (200+ deps) | ~300 | ~5s |

CVE auditing is fast because it involves dictionary lookups against the in-memory database rather than file scanning.

---

## Gate 4: License Compliance Checker

### Overview

| Property | Value |
|---|---|
| **Gate Name** | `compliance` (internal), `license` (config) |
| **Implementation** | `gates/gate4_license.py` |
| **Gate Weight** | 0.8 |
| **Finding Type** | `compliance` |
| **Default CWE** | N/A (compliance finding) |

### What It Detects

The License Gate checks dependency licenses against your organization's policy:

1. **License resolution**: Identifies the license for each dependency using `pip-licenses` (Python) and `npm` (JavaScript)
2. **SPDX normalization**: Normalizes license identifiers to standard SPDX format
3. **Policy check**: Compares each license against `allowed_licenses` and `blocked_licenses`
4. **Risk classification**: Assigns risk levels based on license type and project context

#### License Risk Classification

| Risk Level | License Examples | Open Source Policy | Commercial Policy |
|---|---|---|---|
| Critical | AGPL-3.0 | Blocked | Blocked |
| High | GPL-2.0, GPL-3.0 | Allowed with conditions | Blocked |
| Medium | LGPL-2.1, LGPL-3.0, MPL-2.0 | Allowed | Allowed with conditions |
| Low | Apache-2.0, BSD variants | Allowed | Allowed |
| Minimal | MIT, ISC, PSF, Unlicense | Allowed | Allowed |

### Tools Used

| Tool | Purpose | Required |
|---|---|---|
| `pip-licenses` | Python license resolution | No (falls back to metadata) |
| npm | JavaScript license resolution | No (falls back to package.json `license` field) |
| Built-in SPDX map | License normalization | Yes (built-in) |

### Finding Classification

#### Severity Mapping

| Condition | Severity | CVSS | Rule ID |
|---|---|---|---|
| License in `blocked_licenses` | Critical | 9.0 | `license-blocked` |
| Copyleft license (GPL) in commercial project | High | 7.5 | `license-copyleft-high` |
| Weak copyleft (LGPL, MPL) in commercial project | Medium | 5.0 | `license-weak-copyleft` |
| License not in `allowed_licenses` | Low | 3.0 | `license-unreviewed` |
| Unknown/unresolved license | Medium | 5.0 | `license-unknown` |

#### CVSS Mapping Logic

License compliance findings do not represent technical vulnerabilities, so CVSS scores are assigned heuristically:
- **Critical**: License that could legally force proprietary code to be open-sourced (AGPL network clause)
- **High**: License that requires source code distribution (GPL)
- **Medium**: License with specific conditions that may require legal review (LGPL, MPL)
- **Low**: License not in the allowed list but not explicitly blocked

### Known Limitations

1. **License resolution accuracy**: `pip-licenses` and npm rely on package metadata, which may be incomplete or inaccurate. Some packages have multiple licenses or complex license expressions.
2. **No legal analysis**: The gate identifies license types but does not perform legal analysis of license compatibility, patent grants, or trademark restrictions. Consult legal counsel for compliance decisions.
3. **Transitive dependencies**: Only direct dependencies are checked. Transitive dependencies may have different licenses.
4. **SPDX coverage**: The built-in SPDX normalization map covers ~50 common licenses. Less common licenses may be classified as "unknown".
5. **No license file scanning**: The gate does not scan `LICENSE` files within dependencies — it relies on package metadata only.

### False Positive Rate

| Detection Method | Estimated FP Rate | Mitigation |
|---|---|---|
| License identification | 5–10% | Package metadata is generally accurate for well-maintained packages |
| Policy violations | < 5% | Policy rules are deterministic; FPs come from incorrect license identification |
| Unknown license | 20–30% | Packages without explicit license metadata are flagged; many are MIT/BSD |

### Performance Characteristics

| Repository Size | Dependencies | Scan Time |
|---|---|---|
| Small (< 10 deps) | ~5 | ~1s |
| Medium (10–50 deps) | ~25 | ~3s |
| Large (50–200 deps) | ~100 | ~10s |
| Very large (200+ deps) | ~300 | ~25s |

License checking is slower than CVE auditing because `pip-licenses` and `npm` must be invoked as subprocesses.

---

## Gate 5: Infrastructure-as-Code Security

### Overview

| Property | Value |
|---|---|
| **Gate Name** | `iac` |
| **Implementation** | `gates/gate5_iac.py` |
| **Gate Weight** | 1.1 |
| **Finding Type** | `misconfiguration` |
| **Default CWE** | CWE-732 (Incorrect Permission Assignment for Critical Resource) |

### What It Detects

The IaC Gate scans infrastructure configuration files for security misconfigurations across four sub-scanners:

#### Dockerfile Scanner

| Rule ID | Misconfiguration | CIS Benchmark |
|---|---|---|
| `iac-docker-root-user` | Container runs as root (`USER root` or no USER directive) | CIS 4.1 |
| `iac-docker-latest-tag` | Base image uses `:latest` tag | CIS 4.6 |
| `iac-docker-sensitive-port` | Exposes sensitive ports (22, 3389, 5432, 6379, 27017) | — |
| `iac-docker-no-healthcheck` | No HEALTHCHECK instruction defined | CIS 4.7 |
| `iac-docker-add-vs-copy` | Uses ADD instead of COPY (can fetch remote URLs) | CIS 4.8 |
| `iac-docker-secret-env` | Secrets leaked via ENV or ARG instructions | CIS 4.10 |
| `iac-docker-apt-cache` | apt-get without rm -rf /var/lib/apt/lists/ | CIS 4.9 |
| `iac-docker-sudo` | Uses sudo in Dockerfile | — |

#### Docker Compose Scanner

| Rule ID | Misconfiguration |
|---|---|
| `iac-compose-privileged` | Container runs in privileged mode |
| `iac-compose-host-network` | Container uses host network mode |
| `iac-compose-docker-socket` | Docker socket is mounted into container |
| `iac-compose-no-limits` | No CPU/memory resource limits defined |
| `iac-compose-sensitive-port` | Sensitive ports mapped to host |
| `iac-compose-root-user` | Container runs as root |

#### Kubernetes Manifest Scanner

| Rule ID | Misconfiguration |
|---|---|
| `iac-k8s-privileged` | Container runs in privileged mode |
| `iac-k8s-hostpath` | hostPath volume mount |
| `iac-k8s-host-network` | hostNetwork: true |
| `iac-k8s-host-port` | hostPort is defined |
| `iac-k8s-no-limits` | No resource limits defined |
| `iac-k8s-root-user` | runAsNonRoot not set or false |
| `iac-k8s-no-security-context` | No securityContext defined |

#### GitHub Actions Scanner

| Rule ID | Misconfiguration |
|---|---|
| `iac-gha-untrusted-checkout` | Checks out untrusted code without pinning |
| `iac-gha-pull-request-target` | Uses `pull_request_target` with explicit checkout |
| `iac-gha-script-injection` | Uses untrusted context variables in script blocks |
| `iac-gha-no-permissions` | No top-level permissions block defined |

### Tools Used

| Tool | Purpose | Required |
|---|---|---|
| Built-in Dockerfile parser | Line-by-line Dockerfile analysis | Yes |
| Built-in YAML parser | docker-compose.yml and K8s manifest parsing | Yes (uses PyYAML) |
| Built-in GitHub Actions parser | Workflow YAML analysis | Yes |
| Checkov | Comprehensive IaC scanning (optional) | No (experimental) |

### Finding Classification

#### Severity Mapping

| Misconfiguration | Severity | CVSS |
|---|---|---|
| Privileged container | Critical | 9.1 |
| Docker socket mounted | Critical | 9.1 |
| `pull_request_target` exploit | Critical | 9.1 |
| Script injection (GHA) | High | 8.5 |
| Running as root | High | 7.5 |
| Host network mode | High | 7.5 |
| Host path mount | High | 7.0 |
| Missing resource limits | Medium | 5.5 |
| `:latest` tag | Medium | 5.0 |
| No HEALTHCHECK | Low | 3.0 |
| Missing permissions (GHA) | Low | 3.5 |
| ADD vs COPY | Low | 2.5 |

#### CVSS Mapping Logic

- **Critical (CVSS 9.1)**: Misconfigurations that grant container escape or host-level access (privileged mode, Docker socket mount). These can compromise the entire host.
- **High (CVSS 7.0–8.5)**: Misconfigurations that expand the attack surface significantly (running as root, host networking, script injection in CI).
- **Medium (CVSS 5.0–5.5)**: Misconfigurations that violate best practices but require additional conditions to exploit (no resource limits, `:latest` tags).
- **Low (CVSS 2.5–3.5)**: Minor issues that reduce operational reliability (no HEALTHCHECK, missing permissions).

### Known Limitations

1. **Dockerfile multi-stage builds**: The scanner analyzes each stage independently and may report findings for builder stages that are not present in the final image.
2. **Kubernetes Helm charts**: Raw Helm chart templates (with Go templating `{{ }}`) are not parsed. Only rendered YAML manifests are analyzed.
3. **GitHub Actions reusable workflows**: Reusable workflow calls are not followed. Findings may be missed if the reusable workflow has security issues.
4. **No Terraform support (stable)**: Terraform scanning is experimental and may produce false positives. Enable via `terraform_experimental: true`.
5. **YAML parsing ambiguity**: Kubernetes manifests and GitHub Actions workflows use different YAML structures. The parser uses heuristics to distinguish between them, which may occasionally misidentify files.

### False Positive Rate

| Sub-scanner | Estimated FP Rate | Mitigation |
|---|---|---|
| Dockerfile | 5–10% | Most Dockerfile misconfigurations are deterministic; FPs come from multi-stage builds |
| Docker Compose | 10–15% | Development compose files may intentionally use privileged mode or host networking |
| Kubernetes | 10–20% | DaemonSets and system pods may legitimately use privileged mode or host networking |
| GitHub Actions | 15–25% | Script injection patterns are heuristic-based and may flag safe usage patterns |

### Performance Characteristics

| Configuration Files | Scan Time |
|---|---|
| 1 Dockerfile | ~0.1s |
| 1 Dockerfile + 1 Compose | ~0.2s |
| 5 K8s manifests + 1 Dockerfile | ~0.5s |
| Full stack (10+ files) | ~1s |

IaC scanning is fast because it involves parsing specific configuration files rather than walking the entire file tree.

---

## Cross-Gate Concerns

### Finding Deduplication

SecureBuild does not currently deduplicate findings across gates. A dependency that is both vulnerable (Gate 3) and has a problematic license (Gate 4) will produce separate findings. This is intentional — each finding represents a distinct concern requiring different remediation.

### CWE Mapping

All findings include a `cwe_id` field. The mapping from internal rule IDs to CWE identifiers is maintained in `gates/cwe_map.py`. When a finding does not map to a specific CWE, the gate's default CWE is used.

### Confidence Levels

Every finding includes a `confidence` field:

| Level | Description | Usage |
|---|---|---|
| `high` | Pattern-based detection of known formats | Secret patterns, CVE lookups |
| `medium` | Heuristic or AST-based detection | License resolution, SAST patterns |
| `low` | Statistical or probabilistic detection | Entropy analysis, script injection heuristics |

The scoring engine can be configured to weight findings by confidence level, though this is not currently applied in the default scoring algorithm.

### Inline Suppression

Developers can suppress false positives using inline comments:

```python
api_key = "sk_live_abc123"  # nosec
```

The Secrets Gate skips lines containing `# nosec` or `// nosec`. Other gates do not currently support inline suppression — findings should be addressed or excluded via configuration instead.
