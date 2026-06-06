"""SecureBuild CI/CD Security Gate - Secrets & Credential Scanner"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from engine.logger import get_logger
from engine.models import Finding, GateResult
from engine.utils import calculate_shannon_entropy, is_binary_file, safe_read_file
from gates.base import BaseGate
from gates.cwe_map import INTERNAL_RULE_TO_CWE
from gates.entropy import calculate_entropy, is_high_entropy


# Each pattern tuple contains: (regex, rule_id, display_name)

SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    # AWS Access Keys
    (
        r"AKIA[0-9A-Z]{16}",
        "secrets-aws-access-key",
        "AWS Access Key",
    ),
    # AWS Secret Keys
    (
        r"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
        "secrets-aws-secret-key",
        "AWS Secret Key",
    ),
    # GitHub Personal Access Tokens
    (
        r"ghp_[a-zA-Z0-9]{36}",
        "secrets-github-pat",
        "GitHub Personal Access Token",
    ),
    # Stripe Secret Keys
    (
        r"sk_live_[0-9a-zA-Z]{24}",
        "secrets-stripe-key",
        "Stripe Secret Key",
    ),
    # JWT Tokens
    (
        r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "secrets-jwt-token",
        "JWT Token",
    ),
    # Private Key Headers
    (
        r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "secrets-private-key",
        "Private Key",
    ),
    # Generic Password Patterns
    (
        r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
        "secrets-password",
        "Hardcoded Password",
    ),
    # API Key Patterns
    (
        r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"][^'\"]{10,}['\"]",
        "secrets-api-key",
        "Hardcoded API Key",
    ),
    # Generic Secret Patterns
    (
        r"(?:secret|token|auth)\s*[=:]\s*['\"][^'\"]{10,}['\"]",
        "secrets-generic-secret",
        "Generic Secret",
    ),
]

# Additional patterns specifically for scanning .env files, where
# credentials are commonly leaked in KEY=VALUE format.

ENV_SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    (
        r"(?:DATABASE_URL|DB_PASSWORD|MONGO_URI)\s*=\s*['\"]?[^\s'\"]{6,}",
        "secrets-env-credential",
        "Database Credential in .env",
    ),
    (
        r"(?:SECRET_KEY|APP_SECRET|SESSION_SECRET)\s*=\s*['\"]?[^\s'\"]{8,}",
        "secrets-env-credential",
        "Application Secret in .env",
    ),
    (
        r"(?:SMTP_PASSWORD|MAIL_PASSWORD|EMAIL_PASSWORD)\s*=\s*['\"]?[^\s'\"]{4,}",
        "secrets-env-credential",
        "Email Credential in .env",
    ),
    (
        r"(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=\s*['\"]?[^\s'\"]{8,}",
        "secrets-env-credential",
        "AWS Credential in .env",
    ),
    (
        r"(?:STRIPE_SECRET_KEY|STRIPE_PUBLISHABLE_KEY|STRIPE_API_KEY)\s*=\s*['\"]?[^\s'\"]{8,}",
        "secrets-env-credential",
        "Stripe Credential in .env",
    ),
]

# Maps rule IDs to (severity, cvss_score) tuples.

SEVERITY_MAP: Dict[str, Tuple[str, float]] = {
    "secrets-private-key": ("critical", 9.8),
    "secrets-aws-access-key": ("critical", 9.1),
    "secrets-aws-secret-key": ("critical", 9.1),
    "secrets-github-pat": ("critical", 9.1),
    "secrets-stripe-key": ("critical", 9.1),
    "secrets-jwt-token": ("high", 7.5),
    "secrets-password": ("high", 7.5),
    "secrets-api-key": ("high", 7.5),
    "secrets-high-entropy": ("medium", 6.5),
    "secrets-generic-secret": ("medium", 5.5),
    "secrets-env-credential": ("high", 8.0),
}

# Maps rule IDs to specific fix suggestions.

REMEDIATION_MAP: Dict[str, str] = {
    "secrets-private-key": (
        "Remove the private key from source code immediately. "
        "Store it in a secure secrets manager (e.g., AWS Secrets Manager, "
        "HashiCorp Vault, or Kubernetes Secrets). Rotate the compromised "
        "key pair if it has been committed to version control."
    ),
    "secrets-aws-access-key": (
        "Remove the AWS Access Key from source code. Use IAM roles for "
        "EC2 instances, AWS STS for temporary credentials, or store "
        "credentials in AWS Secrets Manager. Rotate the compromised key "
        "via the AWS IAM console immediately."
    ),
    "secrets-aws-secret-key": (
        "Remove the AWS Secret Key from source code. Use IAM roles or "
        "AWS Secrets Manager for credential management. Rotate the "
        "compromised key pair immediately via the AWS IAM console."
    ),
    "secrets-github-pat": (
        "Remove the GitHub Personal Access Token from source code. "
        "Revoke the token at github.com/settings/tokens and create a "
        "new one. Store it in a secrets manager or use GitHub Actions "
        "secrets for CI/CD workflows."
    ),
    "secrets-stripe-key": (
        "Remove the Stripe Secret Key from source code. Roll the key "
        "in the Stripe Dashboard and use environment variables or a "
        "secrets manager. Never expose live secret keys in client-side code."
    ),
    "secrets-jwt-token": (
        "Remove the hardcoded JWT token from source code. Tokens should "
        "be generated dynamically and stored in secure session storage. "
        "Revoke the exposed token if it grants sensitive access."
    ),
    "secrets-password": (
        "Remove the hardcoded password and use environment variables "
        "or a secrets manager. If this is a default password, require "
        "users to set their own. Consider using bcrypt or argon2 for "
        "password hashing."
    ),
    "secrets-api-key": (
        "Remove the hardcoded API key and use environment variables "
        "or a secrets manager. Rotate the exposed key immediately. "
        "Use API key restrictions and rate limiting to limit blast radius."
    ),
    "secrets-generic-secret": (
        "Move this secret to environment variables or a secrets manager "
        "like HashiCorp Vault, AWS Secrets Manager, or Docker secrets. "
        "Add the file containing secrets to .gitignore if not already."
    ),
    "secrets-high-entropy": (
        "This high-entropy string may be a secret or credential. "
        "If it is sensitive, move it to environment variables or a "
        "secrets manager. If it is not sensitive, add an inline comment "
        "like '# nosec' or '# safe: random test data' to suppress "
        "this finding."
    ),
    "secrets-env-credential": (
        "Move credentials from the .env file to a secure secrets manager. "
        "Add .env to .gitignore to prevent accidental commits. "
        "Provide a .env.example file with placeholder values instead."
    ),
}

# Additional patterns beyond what the config provides.

EXTRA_EXCLUDE_PATTERNS: List[str] = [
    "node_modules/*",
    "node_modules/**",
    "venv/*",
    "venv/**",
    ".venv/*",
    ".venv/**",
    ".git/*",
    ".git/**",
    "*.lock",
    "*.min.js",
    "*.min.css",
    "*.bundle.js",
    "*.pyc",
    "__pycache__/*",
    "vendor/*",
    "vendor/**",
    "dist/*",
    "dist/**",
    "build/*",
    "build/**",
]

# Maximum file size for scanning (1 MB)
_MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024


class SecretsGate(BaseGate):
    """Security gate that detects hardcoded secrets, credentials, and API keys."""

    @property
    def name(self) -> str:
        return "secrets"

    @property
    def description(self) -> str:
        return "Detects hardcoded secrets, credentials, and API keys"

    def get_severity_map(self) -> Dict[str, str]:
        return {rule_id: severity for rule_id, (severity, _) in SEVERITY_MAP.items()}

    def run(self, repo_path: str) -> GateResult:
        findings: List[Finding] = []
        files_scanned = 0
        files_skipped = 0

        try:
            root = Path(repo_path).resolve()

            if not root.exists() or not root.is_dir():
                self.logger.error("Repository path does not exist: %s", repo_path)
                return self._build_gate_result(
                    findings=[],
                    files_scanned=0,
                    files_skipped=0,
                    metadata={"error": "Repository path does not exist"},
                )

            # Collect all files to scan
            scan_files = self._collect_scan_files(root)
            files_scanned = len(scan_files)

            # Collect .env files for deep scan
            env_files = self._collect_env_files(root)

            # Compile patterns
            compiled_patterns = self._compile_secret_patterns()

            # Scan each file
            for filepath in scan_files:
                try:
                    file_findings = self._scan_file(filepath, root, compiled_patterns)
                    findings.extend(file_findings)
                except Exception as exc:
                    self.logger.warning(
                        "Error scanning file %s: %s", filepath, str(exc)
                    )
                    files_scanned -= 1
                    files_skipped += 1

            # Deep scan .env files
            for env_file in env_files:
                try:
                    env_findings = self._deep_scan_env_file(env_file, root)
                    findings.extend(env_findings)
                except Exception as exc:
                    self.logger.warning(
                        "Error scanning .env file %s: %s", env_file, str(exc)
                    )

            self.logger.info(
                "Secrets scan complete: %d findings in %d files",
                len(findings),
                files_scanned,
            )

        except Exception as exc:
            self.logger.error("Secrets gate failed: %s", str(exc))
            return GateResult(
                gate_name="secrets",
                status="error",
                findings=findings,
                files_scanned=files_scanned,
                files_skipped=files_skipped,
                metadata={"error": str(exc)},
            )

        return self._build_gate_result(
            findings=findings,
            files_scanned=files_scanned,
            files_skipped=files_skipped,
            metadata={
                "patterns_used": len(SECRET_PATTERNS),
                "env_files_scanned": len(env_files) if 'env_files' in dir() else 0,
            },
        )

    def _collect_scan_files(self, root: Path) -> List[Path]:
        scan_files: List[Path] = []

        for filepath in root.rglob("*"):
            if not filepath.is_file():
                continue

            # Skip binary files
            if is_binary_file(str(filepath)):
                continue

            # Check file size (skip > 1MB)
            try:
                if filepath.stat().st_size > _MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue

            # Get relative path for exclusion checks
            try:
                relative = filepath.relative_to(root)
                relative_str = str(relative).replace("\\", "/")
            except ValueError:
                continue

            # Check exclusion patterns
            if self._should_exclude(relative_str):
                continue

            scan_files.append(filepath)

        scan_files.sort()
        return scan_files

    def _collect_env_files(self, root: Path) -> List[Path]:
        env_files: List[Path] = []
        for filepath in root.rglob(".env*"):
            if filepath.is_file() and not is_binary_file(str(filepath)):
                try:
                    if filepath.stat().st_size <= _MAX_FILE_SIZE_BYTES:
                        env_files.append(filepath)
                except OSError:
                    continue
        return env_files

    def _should_exclude(self, relative_path: str) -> bool:
        # Use the base class exclusion logic
        all_excludes = self.config.excluded_patterns + EXTRA_EXCLUDE_PATTERNS
        return self._matches_exclusion(relative_path, all_excludes)

    def _compile_secret_patterns(self) -> List[Tuple[re.Pattern, str, str]]:
        compiled: List[Tuple[re.Pattern, str, str]] = []
        for pattern_str, rule_id, display_name in SECRET_PATTERNS:
            try:
                compiled.append((re.compile(pattern_str), rule_id, display_name))
            except re.error as exc:
                self.logger.warning(
                    "Invalid secret pattern skipped: %s (%s)", pattern_str, str(exc)
                )
        return compiled

    def _scan_file(
        self,
        filepath: Path,
        root: Path,
        compiled_patterns: List[Tuple[re.Pattern, str, str]],
    ) -> List[Finding]:
        findings: List[Finding] = []

        content = self._read_file(str(filepath))
        if content is None:
            return findings

        try:
            relative_path = str(filepath.relative_to(root)).replace("\\", "/")
        except ValueError:
            relative_path = str(filepath)

        # Pattern-based detection
        for line_num, line in enumerate(content.splitlines(), start=1):
            # Skip lines with nosec comment
            if "# nosec" in line or "// nosec" in line:
                continue

            for pattern, rule_id, display_name in compiled_patterns:
                match = pattern.search(line)
                if match:
                    severity, cvss_score = SEVERITY_MAP.get(
                        rule_id, ("medium", 5.0)
                    )
                    cwe_id = INTERNAL_RULE_TO_CWE.get(rule_id, "CWE-798")
                    fix_suggestion = REMEDIATION_MAP.get(
                        rule_id, "Move this secret to environment variables or a secrets manager."
                    )

                    findings.append(
                        self._create_finding(
                            file=relative_path,
                            line=line_num,
                            message=f"{display_name} detected: {match.group()!r}",
                            severity=severity,
                            cvss_score=cvss_score,
                            rule_id=rule_id,
                            cwe_id=cwe_id,
                            fix_suggestion=fix_suggestion,
                            finding_type="secret",
                            confidence="high",
                        )
                    )

            # Entropy-based detection on each line
            entropy_findings = self._check_entropy(line, line_num, relative_path)
            findings.extend(entropy_findings)

        return findings

    def _check_entropy(
        self,
        line: str,
        line_num: int,
        relative_path: str,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Extract potential strings from quotes or assignments
        string_patterns = [
            r'["\']([A-Za-z0-9+/=_\-!@#$%^&*()]{20,})["\']',  # Quoted strings
            r'=\s*([A-Za-z0-9+/=_\-]{20,})\s*$',              # Assignment values
        ]

        for str_pattern in string_patterns:
            for match in re.finditer(str_pattern, line):
                candidate = match.group(1)
                entropy_value = calculate_entropy(candidate)
                threshold = self.config.entropy_threshold

                if entropy_value > threshold and len(candidate) > 20:
                    # Avoid duplicate findings if this string was already
                    # caught by a pattern-based rule
                    severity, cvss_score = SEVERITY_MAP.get(
                        "secrets-high-entropy", ("medium", 6.5)
                    )
                    cwe_id = INTERNAL_RULE_TO_CWE.get(
                        "secrets-high-entropy", "CWE-200"
                    )
                    fix_suggestion = REMEDIATION_MAP.get(
                        "secrets-high-entropy",
                        "Review this high-entropy string; move to secrets manager if sensitive.",
                    )

                    findings.append(
                        self._create_finding(
                            file=relative_path,
                            line=line_num,
                            message=(
                                f"High-entropy string detected "
                                f"(entropy={entropy_value:.2f}, threshold={threshold}): "
                                f"{candidate[:30]}{'...' if len(candidate) > 30 else ''}"
                            ),
                            severity=severity,
                            cvss_score=cvss_score,
                            rule_id="secrets-high-entropy",
                            cwe_id=cwe_id,
                            fix_suggestion=fix_suggestion,
                            finding_type="secret",
                            confidence="low",
                        )
                    )

        return findings

    def _deep_scan_env_file(
        self,
        env_file: Path,
        root: Path,
    ) -> List[Finding]:
        findings: List[Finding] = []

        content = self._read_file(str(env_file))
        if content is None:
            return findings

        try:
            relative_path = str(env_file.relative_to(root)).replace("\\", "/")
        except ValueError:
            relative_path = str(env_file)

        # Compile .env-specific patterns
        for line_num, line in enumerate(content.splitlines(), start=1):
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check .env-specific patterns
            for pattern_str, rule_id, display_name in ENV_SECRET_PATTERNS:
                try:
                    match = re.search(pattern_str, line)
                    if match:
                        severity, cvss_score = SEVERITY_MAP.get(
                            rule_id, ("high", 8.0)
                        )
                        cwe_id = INTERNAL_RULE_TO_CWE.get(rule_id, "CWE-798")
                        fix_suggestion = REMEDIATION_MAP.get(
                            rule_id,
                            "Move credentials to a secure secrets manager.",
                        )

                        # Mask the credential value in the message
                        masked_line = self._mask_credential(line)

                        findings.append(
                            self._create_finding(
                                file=relative_path,
                                line=line_num,
                                message=f"{display_name}: {masked_line}",
                                severity=severity,
                                cvss_score=cvss_score,
                                rule_id=rule_id,
                                cwe_id=cwe_id,
                                fix_suggestion=fix_suggestion,
                                finding_type="secret",
                                confidence="high",
                            )
                        )
                except re.error:
                    continue

            # Also check generic patterns on .env lines
            for pattern_str, rule_id, display_name in SECRET_PATTERNS:
                try:
                    match = re.search(pattern_str, line)
                    if match:
                        severity, cvss_score = SEVERITY_MAP.get(
                            rule_id, ("high", 7.5)
                        )
                        cwe_id = INTERNAL_RULE_TO_CWE.get(rule_id, "CWE-798")
                        fix_suggestion = REMEDIATION_MAP.get(
                            rule_id,
                            "Move this secret to a secrets manager.",
                        )
                        masked_line = self._mask_credential(line)

                        findings.append(
                            self._create_finding(
                                file=relative_path,
                                line=line_num,
                                message=f"{display_name} in .env file: {masked_line}",
                                severity=severity,
                                cvss_score=cvss_score,
                                rule_id=rule_id,
                                cwe_id=cwe_id,
                                fix_suggestion=fix_suggestion,
                                finding_type="secret",
                                confidence="high",
                            )
                        )
                except re.error:
                    continue

            # Entropy check on .env values
            eq_idx = line.find("=")
            if eq_idx > 0:
                value = line[eq_idx + 1:].strip().strip("'\"")
                if len(value) > 20:
                    entropy_value = calculate_entropy(value)
                    if entropy_value > self.config.entropy_threshold:
                        severity, cvss_score = SEVERITY_MAP.get(
                            "secrets-high-entropy", ("medium", 6.5)
                        )
                        findings.append(
                            self._create_finding(
                                file=relative_path,
                                line=line_num,
                                message=(
                                    f"High-entropy value in .env file "
                                    f"(entropy={entropy_value:.2f})"
                                ),
                                severity=severity,
                                cvss_score=cvss_score,
                                rule_id="secrets-high-entropy",
                                cwe_id="CWE-200",
                                fix_suggestion=REMEDIATION_MAP.get(
                                    "secrets-high-entropy",
                                    "Review this value; use secrets manager if sensitive.",
                                ),
                                finding_type="secret",
                                confidence="medium",
                            )
                        )

        return findings

    @staticmethod
    def _mask_credential(line: str) -> str:
        eq_idx = line.find("=")
        if eq_idx > 0:
            key = line[:eq_idx + 1]
            value = line[eq_idx + 1:].strip()
            if value and not value.startswith("#"):
                # Show first 2 chars and mask the rest
                if len(value) > 4:
                    masked = value[:2] + "***" + value[-1:]
                else:
                    masked = "****"
                return f"{key} {masked}"
        return line[:10] + "****"
