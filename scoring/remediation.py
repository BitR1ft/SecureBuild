"""SecureBuild CI/CD Security Gate - Remediation Suggestion Engine"""

from __future__ import annotations

import os
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from engine.logger import get_logger
from engine.models import Finding, RemediationSuggestion, RunResult

logger = get_logger("remediation")


class RemediationEngine:
    """Generates remediation suggestions for security findings."""

    # Maps finding_type or specific patterns to estimated fix times.
    FIX_TIME_BY_TYPE: Dict[str, int] = {
        "secret": 10,
        "dependency": 5,
        "compliance": 15,
        "misconfiguration": 20,
        "vulnerability": 60,
    }

    # CWE-specific fix time overrides (minutes)
    FIX_TIME_BY_CWE: Dict[str, int] = {
        "CWE-89": 45,    # SQL Injection - moderate code change
        "CWE-79": 30,    # XSS - output encoding
        "CWE-78": 60,    # Command Injection - needs rearchitecture
        "CWE-22": 30,    # Path Traversal - input validation
        "CWE-502": 90,   # Insecure Deserialization - major refactor
        "CWE-327": 20,   # Weak Crypto - library swap
        "CWE-918": 45,   # SSRF - URL validation + allowlist
        "CWE-611": 30,   # XXE - parser configuration
        "CWE-798": 10,   # Hardcoded Credentials - move to env
        "CWE-200": 25,   # Sensitive Data Exposure - add filtering
        "CWE-306": 20,   # Missing Auth - add middleware
        "CWE-862": 25,   # Missing Authorization - add checks
        "CWE-434": 40,   # Unrestricted File Upload - validation
        "CWE-1188": 15,  # Insecure Defaults - config change
    }

    # Effort level thresholds (minutes)
    EFFORT_LOW_THRESHOLD: int = 15
    EFFORT_MEDIUM_THRESHOLD: int = 60

    def __init__(self, templates_path: Optional[str] = None) -> None:
        if templates_path is None:
            # Default: look for templates in the data/ directory
            project_root = Path(__file__).resolve().parent.parent
            templates_path = str(project_root / "data" / "remediation_templates.yaml")

        self.templates_path = templates_path
        self.templates: Dict[str, Dict[str, Any]] = {}
        self._load_templates()


    def _load_templates(self) -> None:
        if not os.path.isfile(self.templates_path):
            logger.info(
                "No remediation templates found at %s; "
                "using dynamic generation only",
                self.templates_path,
            )
            return

        try:
            import yaml  # type: ignore

            with open(self.templates_path, "r", encoding="utf-8") as fh:
                raw_templates = yaml.safe_load(fh)

            if not raw_templates or not isinstance(raw_templates, dict):
                logger.warning(
                    "Remediation templates file is empty or malformed"
                )
                return

            # Index templates by composite keys for O(1) lookup
            templates_list = raw_templates.get("templates", [])
            if isinstance(templates_list, list):
                for tmpl in templates_list:
                    if not isinstance(tmpl, dict):
                        continue
                    key = tmpl.get("key", "")
                    if key:
                        self.templates[key] = tmpl

            logger.info(
                "Loaded %d remediation templates from %s",
                len(self.templates),
                self.templates_path,
            )

        except ImportError:
            logger.warning(
                "PyYAML not installed; cannot load remediation templates. "
                "Install with: pip install pyyaml"
            )
        except Exception as exc:
            logger.warning(
                "Failed to load remediation templates: %s", str(exc)
            )


    def generate_remediations(
        self, run_result: RunResult
    ) -> List[RemediationSuggestion]:
        suggestions: List[RemediationSuggestion] = []
        all_findings = run_result.all_findings

        for finding in all_findings:
            try:
                suggestion = self.generate_remediation_for_finding(finding)
                suggestions.append(suggestion)
            except Exception as exc:
                logger.warning(
                    "Failed to generate remediation for finding %s: %s",
                    finding.id,
                    str(exc),
                )
                # Provide a minimal fallback suggestion
                suggestions.append(
                    RemediationSuggestion(
                        finding_id=finding.id,
                        title=f"Fix {finding.severity.title()} finding: {finding.message[:80]}",
                        explanation=finding.fix_suggestion or finding.message,
                        effort="medium",
                        estimated_minutes=30,
                    )
                )

        logger.info(
            "Generated %d remediation suggestions for %d findings",
            len(suggestions),
            len(all_findings),
        )
        return suggestions

    def generate_remediation_for_finding(
        self, finding: Finding
    ) -> RemediationSuggestion:
        template = self._find_template(finding)

        if template:
            return self._build_from_template(finding, template)

        return self._build_dynamic(finding)

    def group_similar_findings(
        self, findings: List[Finding]
    ) -> List[Dict[str, Any]]:
        groups: Dict[str, List[Finding]] = defaultdict(list)

        for f in findings:
            key = f.cwe_id if f.cwe_id else f"{f.gate}:{f.rule_id or f.finding_type}"
            groups[key].append(f)

        result: List[Dict[str, Any]] = []
        for key, group_findings in groups.items():
            # Sort by CVSS descending — representative is the worst
            sorted_group = sorted(
                group_findings, key=lambda f: f.cvss_score, reverse=True
            )
            representative = sorted_group[0]
            locations = [(f.file, f.line) for f in sorted_group]

            result.append({
                "cwe_id": key,
                "count": len(sorted_group),
                "representative": representative,
                "locations": locations,
                "findings": sorted_group,
            })

        # Sort groups by count descending
        result.sort(key=lambda g: g["count"], reverse=True)
        return result

    def identify_quick_wins(self, findings: List[Finding]) -> List[Finding]:
        quick_wins: List[Finding] = []

        for f in findings:
            if f.severity not in ("critical", "high"):
                continue

            # Secret findings — delete or rotate, very quick
            if f.finding_type == "secret":
                quick_wins.append(f)
                continue

            # Dependency findings — upgrade version, very quick
            if f.finding_type == "dependency":
                quick_wins.append(f)
                continue

            # Compliance/misconfiguration — often config changes
            if f.finding_type in ("compliance", "misconfiguration"):
                estimated = self.calculate_estimated_fix_time(f)
                if estimated <= self.EFFORT_LOW_THRESHOLD:
                    quick_wins.append(f)
                    continue

            # Specific CWEs that are known quick fixes
            quick_cwe = {
                "CWE-798",   # Hardcoded Credentials - move to env
                "CWE-327",   # Weak Crypto - library swap
                "CWE-1188",  # Insecure Defaults - config change
                "CWE-306",   # Missing Auth middleware
            }
            if f.cwe_id in quick_cwe:
                quick_wins.append(f)
                continue

        # Sort by CVSS score descending
        quick_wins.sort(key=lambda f: f.cvss_score, reverse=True)
        return quick_wins

    def calculate_estimated_fix_time(self, finding: Finding) -> int:
        # CWE-specific overrides take priority
        if finding.cwe_id and finding.cwe_id in self.FIX_TIME_BY_CWE:
            return self.FIX_TIME_BY_CWE[finding.cwe_id]

        # Type-based defaults
        base_time = self.FIX_TIME_BY_TYPE.get(
            finding.finding_type, 60
        )

        # Adjust by severity (critical findings often need more care)
        severity_adjustment = {
            "critical": 1.5,
            "high": 1.2,
            "medium": 1.0,
            "low": 0.8,
            "info": 0.5,
        }
        multiplier = severity_adjustment.get(finding.severity, 1.0)

        return max(5, int(base_time * multiplier))

    def calculate_total_fix_time(self, findings: List[Finding]) -> int:
        cwe_seen: Dict[str, int] = defaultdict(int)
        total = 0

        for f in findings:
            base_time = self.calculate_estimated_fix_time(f)
            key = f.cwe_id or f"{f.gate}:{f.finding_type}"

            if cwe_seen[key] > 0:
                # Same root cause: apply 50% discount for subsequent fixes
                total += int(base_time * 0.5)
            else:
                total += base_time

            cwe_seen[key] += 1

        return total

    def generate_fix_command(self, finding: Finding) -> str:
        if finding.finding_type == "dependency" or finding.gate in (
            "cve", "dependencies",
        ):
            return self._generate_dependency_fix_command(finding)

        if finding.finding_type == "secret" or finding.gate == "secrets":
            return self._generate_secret_fix_command(finding)

        if finding.gate == "iac" or finding.finding_type == "misconfiguration":
            return self._generate_iac_fix_command(finding)

        if finding.gate in ("license", "compliance"):
            return self._generate_compliance_fix_command(finding)

        return ""

    def priority_sort(self, findings: List[Finding]) -> List[Finding]:
        # Ease-of-fix ranking (lower = easier)
        ease_rank = {
            "secret": 0,
            "dependency": 1,
            "compliance": 2,
            "misconfiguration": 3,
            "vulnerability": 4,
        }

        # Severity ranking (higher = worse)
        severity_rank = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0,
        }

        # Confidence ranking (higher = more certain)
        confidence_rank = {
            "high": 2,
            "medium": 1,
            "low": 0,
        }

        return sorted(
            findings,
            key=lambda f: (
                -f.cvss_score,                          # Higher CVSS first
                ease_rank.get(f.finding_type, 5),       # Easier fixes first
                -severity_rank.get(f.severity, 0),      # Higher severity first
                -confidence_rank.get(f.confidence, 0),  # Higher confidence first
            ),
        )


    def _find_template(self, finding: Finding) -> Optional[Dict[str, Any]]:
        # 1. gate + cwe_id
        if finding.cwe_id:
            key = f"{finding.gate}_{finding.cwe_id}"
            if key in self.templates:
                return self.templates[key]

        # 2. gate + rule_id
        if finding.rule_id:
            key = f"{finding.gate}_{finding.rule_id}"
            if key in self.templates:
                return self.templates[key]

        # 3. gate + finding_type
        key = f"{finding.gate}_{finding.finding_type}"
        if key in self.templates:
            return self.templates[key]

        # 4. cwe_id alone
        if finding.cwe_id and finding.cwe_id in self.templates:
            return self.templates[finding.cwe_id]

        # 5. finding_type alone
        if finding.finding_type in self.templates:
            return self.templates[finding.finding_type]

        return None

    def _build_from_template(
        self,
        finding: Finding,
        template: Dict[str, Any],
    ) -> RemediationSuggestion:
        estimated = self.calculate_estimated_fix_time(finding)
        effort = self._minutes_to_effort(estimated)
        quick_win = effort == "low" and estimated <= self.EFFORT_LOW_THRESHOLD

        return RemediationSuggestion(
            finding_id=finding.id,
            title=template.get("title", f"Fix {finding.severity.title()} finding"),
            explanation=template.get("explanation", finding.message),
            fix_code_before=template.get("fix_code_before", ""),
            fix_code_after=template.get("fix_code_after", ""),
            references=template.get("references", []),
            effort=effort,
            quick_win=quick_win,
            estimated_minutes=estimated,
        )

    def _build_dynamic(self, finding: Finding) -> RemediationSuggestion:
        estimated = self.calculate_estimated_fix_time(finding)
        effort = self._minutes_to_effort(estimated)
        quick_win = effort == "low" and estimated <= self.EFFORT_LOW_THRESHOLD

        title = self._generate_dynamic_title(finding)
        explanation = self._generate_dynamic_explanation(finding)
        fix_before = self._generate_dynamic_before(finding)
        fix_after = self._generate_dynamic_after(finding)
        references = self._generate_dynamic_references(finding)

        return RemediationSuggestion(
            finding_id=finding.id,
            title=title,
            explanation=explanation,
            fix_code_before=fix_before,
            fix_code_after=fix_after,
            references=references,
            effort=effort,
            quick_win=quick_win,
            estimated_minutes=estimated,
        )


    def _generate_dynamic_title(self, finding: Finding) -> str:
        cwe_label = f" ({finding.cwe_id})" if finding.cwe_id else ""
        type_label = finding.finding_type.replace("_", " ").title()
        return f"Fix {finding.severity.title()} {type_label}{cwe_label}: {finding.message[:60]}"

    def _generate_dynamic_explanation(self, finding: Finding) -> str:
        parts: List[str] = []

        if finding.cwe_id:
            cwe_descriptions: Dict[str, str] = {
                "CWE-89": "SQL Injection allows attackers to execute arbitrary SQL commands by injecting malicious input into database queries.",
                "CWE-79": "Cross-site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users.",
                "CWE-78": "Command Injection allows attackers to execute arbitrary operating system commands through vulnerable input fields.",
                "CWE-22": "Path Traversal allows attackers to access files and directories outside the intended directory by manipulating file paths.",
                "CWE-502": "Insecure Deserialization allows attackers to inject malicious objects that execute arbitrary code when deserialized.",
                "CWE-327": "Weak Cryptography uses broken or obsolete cryptographic algorithms that can be easily broken.",
                "CWE-918": "Server-Side Request Forgery (SSRF) allows attackers to induce the server to make requests to unintended locations.",
                "CWE-611": "XML External Entity (XXE) Injection allows attackers to interfere with XML parsing to access server files or services.",
                "CWE-798": "Hardcoded Credentials expose sensitive authentication data in source code, making it accessible to anyone with code access.",
                "CWE-200": "Sensitive Data Exposure allows unauthorized access to sensitive information through insufficient protection.",
                "CWE-306": "Missing Authentication for Critical Function allows unauthenticated users to access protected functionality.",
                "CWE-862": "Missing Authorization allows authenticated users to perform actions beyond their intended permissions.",
                "CWE-434": "Unrestricted File Upload allows attackers to upload malicious files that may be executed on the server.",
                "CWE-1188": "Insecure Default Initialization of Resource uses insecure defaults that may expose the system to attack.",
            }
            desc = cwe_descriptions.get(finding.cwe_id)
            if desc:
                parts.append(desc)

        parts.append(f"Finding detected in {finding.file or 'unknown file'}"
                     f" at line {finding.line} by the {finding.gate} gate.")

        if finding.fix_suggestion:
            parts.append(f"Suggested fix: {finding.fix_suggestion}")
        else:
            parts.append("Review and address this finding according to your "
                         "organization's security policies.")

        return " ".join(parts)

    def _generate_dynamic_before(self, finding: Finding) -> str:
        type_snippets: Dict[str, str] = {
            "secret": '# WARNING: Hardcoded secret\nAPI_KEY = "sk-abc123..."',
            "dependency": "# requirements.txt\nvulnerable-package==1.0.0  # CVE-2023-32681: Proxy-Authorization header leak",
            "misconfiguration": '# Dockerfile\nFROM ubuntu:latest\nUSER root',
            "compliance": "# License: GPL-3.0 (incompatible with commercial use)",
            "vulnerability": (
                f"# {finding.cwe_id or 'Vulnerable'} code pattern\n"
                f"# See finding: {finding.message[:60]}"
            ),
        }
        return type_snippets.get(
            finding.finding_type,
            f"# Vulnerable code in {finding.file or 'source'}",
        )

    def _generate_dynamic_after(self, finding: Finding) -> str:
        type_snippets: Dict[str, str] = {
            "secret": "# Use environment variables for secrets\nimport os\nAPI_KEY = os.environ['API_KEY']",
            "dependency": "# requirements.txt\nvulnerable-package>=2.0.0  # Patched version",
            "misconfiguration": "# Dockerfile\nFROM ubuntu:latest\nUSER appuser  # Non-root user",
            "compliance": "# License: MIT (compatible with commercial use)",
            "vulnerability": (
                f"# Fixed code pattern for {finding.cwe_id or 'vulnerability'}\n"
                f"# Apply input validation and secure coding practices"
            ),
        }
        return type_snippets.get(
            finding.finding_type,
            f"# Secure code in {finding.file or 'source'}",
        )

    def _generate_dynamic_references(self, finding: Finding) -> List[str]:
        refs: List[str] = []

        if finding.cwe_id:
            cwe_num = finding.cwe_id.replace("CWE-", "")
            refs.append(f"https://cwe.mitre.org/data/definitions/{cwe_num}.html")

        if finding.gate == "sast":
            refs.append("https://owasp.org/www-project-top-ten/")
        elif finding.gate == "secrets":
            refs.append("https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_cryptographic_key")
        elif finding.gate in ("cve", "dependencies"):
            refs.append("https://nvd.nist.gov/vuln/search")

        return refs


    def _generate_dependency_fix_command(self, finding: Finding) -> str:
        message = finding.message.lower()

        # Try to extract package name from the message
        # Common patterns: "package-name X.X.X has vulnerability"
        package = ""

        # Try to find package name from the rule_id or message
        if finding.rule_id:
            # rule_id might be the package name
            package = finding.rule_id.split(":")[0] if ":" in finding.rule_id else finding.rule_id

        if not package:
            # Try to parse from message
            import re
            match = re.search(r'([a-zA-Z0-9_-]+(?:[./-][a-zA-Z0-9_-]+)*)\s*[\s(]', finding.message)
            if match:
                package = match.group(1)

        if package:
            # Detect package manager from file path
            if "package.json" in finding.file or "yarn.lock" in finding.file:
                return f"npm audit fix && npm install {package}@latest"
            elif "requirements" in finding.file or ".txt" in finding.file:
                return f"pip install --upgrade {package}"
            elif "Pipfile" in finding.file:
                return f"pipenv update {package}"
            elif "go.mod" in finding.file or "go.sum" in finding.file:
                return f"go get -u {package} && go mod tidy"
            else:
                return f"pip install --upgrade {package}"

        return "# Review and upgrade the vulnerable dependency manually"

    def _generate_secret_fix_command(self, finding: Finding) -> str:
        file_path = finding.file or "path/to/file"

        if finding.cwe_id == "CWE-798" or "hardcoded" in finding.message.lower():
            return (
                f"# Step 1: Remove the secret from source code\n"
                f"# Step 2: Revoke and rotate the compromised credential\n"
                f"# Step 3: Remove from git history if committed:\n"
                f"git filter-branch --force --index-filter \\\n"
                f'  "git rm --cached --ignore-unmatch {file_path}" \\\n'
                f"  --prune-empty -- --all\n"
                f"# Step 4: Use environment variables or a secrets manager"
            )

        return (
            f"# Remove the exposed secret from {file_path}\n"
            f"# Rotate the credential immediately\n"
            f"# Consider using: vault, AWS Secrets Manager, or .env files"
        )

    def _generate_iac_fix_command(self, finding: Finding) -> str:
        message = finding.message.lower()

        if "root" in message and "docker" in message:
            return (
                "# Add non-root user to Dockerfile:\n"
                "RUN useradd -m appuser\n"
                "USER appuser"
            )

        if "privileged" in message:
            return (
                "# Remove privileged mode from container:\n"
                "# Change: privileged: true\n"
                "# To:     privileged: false"
            )

        if "ssh" in message and "port" in message:
            return (
                "# Do not expose SSH port in Dockerfile/docker-compose:\n"
                "# Remove: EXPOSE 22\n"
                "# or change to a non-standard port with proper key management"
            )

        return f"# Review and fix IaC misconfiguration in {finding.file or 'config file'}"

    def _generate_compliance_fix_command(self, finding: Finding) -> str:
        message = finding.message.lower()

        if "gpl" in message or "license" in message:
            return (
                "# Replace the GPL-licensed dependency with an alternative:\n"
                "# 1. Find a permissive-licensed alternative (MIT, Apache-2.0, BSD)\n"
                "# 2. Update requirements.txt / package.json\n"
                "# 3. Verify license compatibility at: https://opensource.org/licenses"
            )

        return f"# Review and address compliance issue in {finding.file or 'project'}"


    def _minutes_to_effort(self, minutes: int) -> str:
        if minutes <= self.EFFORT_LOW_THRESHOLD:
            return "low"
        elif minutes <= self.EFFORT_MEDIUM_THRESHOLD:
            return "medium"
        else:
            return "high"
