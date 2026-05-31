# Security Policy

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in SecureBuild, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report security vulnerabilities by emailing:

**security@securebuild.dev**

Include the following information:
- A description of the vulnerability
- Steps to reproduce the issue
- The potential impact of the vulnerability
- Any suggested mitigations or fixes

## Response Timeline

| Stage | Target Time |
|-------|-------------|
| Acknowledgment | Within 24 hours |
| Initial Assessment | Within 72 hours |
| Status Update | Within 7 days |
| Resolution | Within 30 days (critical), 90 days (others) |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes     |
| < 1.0   | ❌ No      |

## Security Best Practices

When deploying SecureBuild:

1. **Never commit secrets** — Use `.env` files or environment variables for all sensitive configuration (API keys, tokens, database credentials).
2. **Restrict database access** — The SQLite database contains scan results and API key hashes. Ensure file permissions are restrictive (`0600`).
3. **Use HTTPS in production** — Deploy behind a reverse proxy (nginx, Caddy, Traefik) with TLS termination.
4. **Rotate API keys regularly** — Use `securebuild generate-api-key` to create new keys and revoke old ones.
5. **Review scan results** — SecureBuild is a tool to assist security review; it does not replace human security audits.
6. **Keep dependencies updated** — Run `pip audit` and `make audit` regularly to check for known CVEs in dependencies.

## Secure Development

- All contributions are scanned by SecureBuild before merging.
- Pre-commit hooks enforce linting, formatting, and secret detection.
- Dependencies are pinned and audited via `pip-audit`.
- The Docker image runs as a non-root user.

## Disclosure Policy

We follow coordinated disclosure:
1. We acknowledge the report and begin investigation.
2. We develop and test a fix.
3. We release the fix and publish a security advisory.
4. We credit the reporter (unless they prefer to remain anonymous).
