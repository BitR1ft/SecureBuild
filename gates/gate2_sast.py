"""SecureBuild CI/CD Security Gate - SAST Analysis"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from engine.logger import get_logger
from engine.models import Finding, GateResult
from engine.utils import is_binary_file, safe_read_file
from gates.base import BaseGate
from gates.cwe_map import BANDIT_TO_CWE, INTERNAL_RULE_TO_CWE, SEMGREP_TO_CWE, rule_to_cwe


SEVERITY_MAP: Dict[str, Tuple[str, float]] = {
    # Critical: Code execution / shell injection
    "sast-eval-usage": ("critical", 9.8),
    "sast-exec-usage": ("critical", 9.8),
    "sast-shell-true": ("critical", 9.1),
    "sast-sql-injection": ("high", 8.1),
    # High: Deserialization / data exposure
    "sast-pickle-load": ("high", 8.8),
    "sast-yaml-load": ("high", 7.5),
    "sast-insecure-hash": ("high", 7.5),
    "sast-http-url": ("medium", 6.5),
    # Medium: Configuration / best practices
    "sast-assert-statement": ("medium", 5.0),
    "sast-input-validation": ("medium", 5.5),
}


REMEDIATION_MAP: Dict[str, str] = {
    "sast-eval-usage": (
        "Avoid using eval() with user-supplied input. If dynamic code "
        "execution is required, use ast.literal_eval() for safe evaluation "
        "of literals, or use a sandboxed execution environment. "
        "If eval() is unavoidable, sanitize and validate all inputs strictly."
    ),
    "sast-exec-usage": (
        "Avoid using exec() with user-supplied input. If dynamic code "
        "execution is required, consider using a restricted execution "
        "environment or refactor to use function dispatch. "
        "Sanitize and validate all inputs if exec() is unavoidable."
    ),
    "sast-shell-true": (
        "Avoid using subprocess with shell=True, especially with "
        "user-supplied arguments. Use shell=False and pass arguments "
        "as a list instead. Example: subprocess.run(['ls', user_input]) "
        "instead of subprocess.run(f'ls {user_input}', shell=True)."
    ),
    "sast-sql-injection": (
        "Use parameterized queries instead of string formatting for SQL. "
        "Example: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)) "
        "instead of cursor.execute(f'SELECT * FROM users WHERE id = {user_id}'). "
        "Use an ORM like SQLAlchemy with proper query building."
    ),
    "sast-pickle-load": (
        "Avoid using pickle.load() or pickle.loads() on untrusted data. "
        "Use safer serialization formats like JSON, or implement a "
        "whitelist-based unpickler. Consider using hmac to verify "
        "data integrity before unpickling."
    ),
    "sast-yaml-load": (
        "Use yaml.safe_load() instead of yaml.load(). The yaml.load() "
        "function can execute arbitrary Python code during deserialization. "
        "If you need custom YAML tags, use yaml.load() with an explicit "
        "Loader=yaml.SafeLoader parameter."
    ),
    "sast-insecure-hash": (
        "Use secure hashing algorithms like SHA-256 or SHA-3 for password "
        "hashing. For passwords, use bcrypt, argon2, or PBKDF2 with "
        "sufficient iterations. MD5 and SHA-1 are vulnerable to collision "
        "attacks and should not be used for security purposes."
    ),
    "sast-http-url": (
        "Use HTTPS instead of HTTP for all URLs, especially those "
        "transmitting sensitive data. HTTP connections can be intercepted "
        "by man-in-the-middle attacks. Update the URL to use https:// "
        "and verify the server's TLS certificate."
    ),
    "sast-assert-statement": (
        "Do not use assert statements for security checks, as they can "
        "be stripped out when Python is run with the -O (optimize) flag. "
        "Use explicit if/raise statements instead. "
        "Example: if not condition: raise ValueError('message') "
        "instead of: assert condition, 'message'."
    ),
    "sast-input-validation": (
        "Validate and sanitize all user inputs before processing. "
        "Use type checking, range validation, and allowlist patterns. "
        "Never trust data from external sources without verification."
    ),
}


class SASTGate(BaseGate):
    """Security gate for Static Application Security Testing."""

    @property
    def name(self) -> str:
        return "sast"

    @property
    def description(self) -> str:
        return "Static Application Security Testing using Bandit and Semgrep"

    def get_severity_map(self) -> Dict[str, str]:
        return {rule_id: severity for rule_id, (severity, _) in SEVERITY_MAP.items()}

    def run(self, repo_path: str) -> GateResult:
        findings: List[Finding] = []
        files_scanned = 0
        files_skipped = 0
        tools_used: List[str] = []
        tools_unavailable: List[str] = []

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

            bandit_findings, bandit_scanned = self._run_bandit(repo_path)
            if bandit_findings is not None:
                findings.extend(bandit_findings)
                files_scanned += bandit_scanned
                tools_used.append("bandit")
            else:
                tools_unavailable.append("bandit")

            semgrep_findings, semgrep_scanned = self._run_semgrep(repo_path)
            if semgrep_findings is not None:
                findings.extend(semgrep_findings)
                files_scanned += semgrep_scanned
                tools_used.append("semgrep")
            else:
                tools_unavailable.append("semgrep")

            if not tools_used:
                self.logger.info(
                    "No external SAST tools available; using built-in AST scanner"
                )

            ast_findings, ast_scanned, ast_skipped = self._run_ast_scanner(root)
            findings.extend(ast_findings)
            files_scanned += ast_scanned
            files_skipped += ast_skipped

            if ast_findings:
                tools_used.append("ast-scanner")

            # Deduplicate findings (same file + line + rule_id)
            findings = self._deduplicate_findings(findings)

            self.logger.info(
                "SAST scan complete: %d findings (tools: %s)",
                len(findings),
                ", ".join(tools_used),
            )

        except Exception as exc:
            self.logger.error("SAST gate failed: %s", str(exc))
            return GateResult(
                gate_name="sast",
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
                "tools_used": tools_used,
                "tools_unavailable": tools_unavailable,
            },
        )


    def _run_bandit(
        self, repo_path: str
    ) -> Tuple[Optional[List[Finding]], int]:
        try:
            result = subprocess.run(
                ["bandit", "-r", repo_path, "-f", "json"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode not in (0, 1):
                # Bandit returns 1 when findings are found, 0 when clean
                self.logger.warning(
                    "Bandit returned non-standard exit code %d", result.returncode
                )

            try:
                bandit_output = json.loads(result.stdout)
            except json.JSONDecodeError:
                self.logger.warning("Bandit output is not valid JSON")
                return None, 0

            findings: List[Finding] = []
            metrics = bandit_output.get("metrics", {})
            files_scanned = metrics.get("_totals", {}).get("loc", 0)

            for issue in bandit_output.get("results", []):
                bandit_id = issue.get("test_id", "")
                cwe_id = BANDIT_TO_CWE.get(bandit_id, "CWE-20")
                severity = self._map_bandit_severity(
                    issue.get("issue_confidence", "MEDIUM"),
                    issue.get("issue_severity", "MEDIUM"),
                )
                cvss = self._severity_to_cvss(severity)
                rule_id = f"bandit-{bandit_id}"

                findings.append(
                    self._create_finding(
                        file=issue.get("filename", ""),
                        line=issue.get("line_number", 0),
                        message=issue.get("issue_text", ""),
                        severity=severity,
                        cvss_score=cvss,
                        rule_id=rule_id,
                        cwe_id=cwe_id,
                        fix_suggestion=self._get_bandit_remediation(bandit_id),
                        finding_type="vulnerability",
                        confidence=self._map_confidence(
                            issue.get("issue_confidence", "MEDIUM")
                        ),
                    )
                )

            self.logger.info(
                "Bandit found %d issues", len(findings)
            )
            return findings, files_scanned

        except FileNotFoundError:
            self.logger.info("Bandit not installed; skipping Bandit scan")
            return None, 0
        except subprocess.TimeoutExpired:
            self.logger.warning("Bandit scan timed out after 300 seconds")
            return None, 0
        except Exception as exc:
            self.logger.warning("Bandit scan failed: %s", str(exc))
            return None, 0


    def _run_semgrep(
        self, repo_path: str
    ) -> Tuple[Optional[List[Finding]], int]:
        try:
            result = subprocess.run(
                ["semgrep", "--config=p/python", "--json", repo_path],
                capture_output=True,
                text=True,
                timeout=600,
            )

            try:
                semgrep_output = json.loads(result.stdout)
            except json.JSONDecodeError:
                self.logger.warning("Semgrep output is not valid JSON")
                return None, 0

            findings: List[Finding] = []
            files_scanned = len(
                semgrep_output.get("paths", {}).get("scanned", [])
            )

            for issue in semgrep_output.get("results", []):
                check_id = issue.get("check_id", "")
                cwe_id = SEMGREP_TO_CWE.get(check_id, "CWE-20")
                extra = issue.get("extra", {})
                severity_str = extra.get("severity", "WARNING")
                severity = self._normalize_severity_string(severity_str)
                cvss = self._severity_to_cvss(severity)

                start = issue.get("start", {})
                findings.append(
                    self._create_finding(
                        file=issue.get("path", ""),
                        line=start.get("line", 0),
                        message=extra.get("message", ""),
                        severity=severity,
                        cvss_score=cvss,
                        rule_id=f"semgrep-{check_id}",
                        cwe_id=cwe_id,
                        fix_suggestion=extra.get("fix", ""),
                        finding_type="vulnerability",
                        confidence="medium",
                    )
                )

            self.logger.info(
                "Semgrep found %d issues", len(findings)
            )
            return findings, files_scanned

        except FileNotFoundError:
            self.logger.info("Semgrep not installed; skipping Semgrep scan")
            return None, 0
        except subprocess.TimeoutExpired:
            self.logger.warning("Semgrep scan timed out after 600 seconds")
            return None, 0
        except Exception as exc:
            self.logger.warning("Semgrep scan failed: %s", str(exc))
            return None, 0


    def _run_ast_scanner(
        self, root: Path
    ) -> Tuple[List[Finding], int, int]:
        findings: List[Finding] = []
        files_scanned = 0
        files_skipped = 0

        python_files = self._collect_python_files(root)

        for filepath in python_files:
            try:
                content = self._read_file(str(filepath))
                if content is None:
                    files_skipped += 1
                    continue

                try:
                    relative_path = str(filepath.relative_to(root)).replace("\\", "/")
                except ValueError:
                    relative_path = str(filepath)

                # Parse AST
                try:
                    tree = ast.parse(content, filename=str(filepath))
                except SyntaxError:
                    # Fall back to line-by-line scanning for files with
                    # syntax errors
                    line_findings = self._scan_lines(
                        content, relative_path
                    )
                    findings.extend(line_findings)
                    files_scanned += 1
                    continue

                # AST-based checks
                ast_findings = self._analyze_ast(tree, content, relative_path)
                findings.extend(ast_findings)

                # Line-based checks (for patterns AST can't catch)
                line_findings = self._scan_lines(content, relative_path)
                findings.extend(line_findings)

                files_scanned += 1

            except Exception as exc:
                self.logger.warning(
                    "Error scanning %s: %s", filepath, str(exc)
                )
                files_skipped += 1

        return findings, files_scanned, files_skipped

    def _collect_python_files(self, root: Path) -> List[Path]:
        python_files: List[Path] = []
        for filepath in root.rglob("*.py"):
            if not filepath.is_file():
                continue
            if is_binary_file(str(filepath)):
                continue
            try:
                if filepath.stat().st_size > _MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue

            # Check exclusion patterns
            try:
                relative = filepath.relative_to(root)
                relative_str = str(relative).replace("\\", "/")
            except ValueError:
                continue

            if self._matches_exclusion(
                relative_str, self.config.excluded_patterns
            ):
                continue

            python_files.append(filepath)

        python_files.sort()
        return python_files

    def _analyze_ast(
        self,
        tree: ast.AST,
        content: str,
        relative_path: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == "eval":
                    if not self._is_nosec_line(lines, node.lineno):
                        findings.append(
                            self._create_sast_finding(
                                relative_path, node.lineno,
                                "sast-eval-usage",
                                "Use of eval() detected - potential code injection",
                            )
                        )

                if isinstance(func, ast.Name) and func.id == "exec":
                    if not self._is_nosec_line(lines, node.lineno):
                        findings.append(
                            self._create_sast_finding(
                                relative_path, node.lineno,
                                "sast-exec-usage",
                                "Use of exec() detected - potential code injection",
                            )
                        )

                if isinstance(func, ast.Attribute) and func.attr == "call":
                    if isinstance(func.value, ast.Name) and func.value.id == "subprocess":
                        if self._has_shell_true(node):
                            if not self._is_nosec_line(lines, node.lineno):
                                findings.append(
                                    self._create_sast_finding(
                                        relative_path, node.lineno,
                                        "sast-shell-true",
                                        "subprocess.call with shell=True - OS command injection risk",
                                    )
                                )

                if isinstance(func, ast.Name) and func.id == "call":
                    # Check for subprocess.run/call/Popen with shell=True
                    pass  # Handled by attribute check above

                if isinstance(func, ast.Attribute) and func.attr in ("load", "loads"):
                    if isinstance(func.value, ast.Name) and func.value.id == "pickle":
                        if not self._is_nosec_line(lines, node.lineno):
                            findings.append(
                                self._create_sast_finding(
                                    relative_path, node.lineno,
                                    "sast-pickle-load",
                                    f"Use of pickle.{func.attr}() - insecure deserialization",
                                )
                            )

                if isinstance(func, ast.Attribute) and func.attr == "load":
                    if isinstance(func.value, ast.Name) and func.value.id == "yaml":
                        if not self._has_loader_arg(node):
                            if not self._is_nosec_line(lines, node.lineno):
                                findings.append(
                                    self._create_sast_finding(
                                        relative_path, node.lineno,
                                        "sast-yaml-load",
                                        "yaml.load() without Loader - insecure deserialization",
                                    )
                                )

                if isinstance(func, ast.Attribute) and func.attr == "execute":
                    if self._has_string_format_arg(node):
                        if not self._is_nosec_line(lines, node.lineno):
                            findings.append(
                                self._create_sast_finding(
                                    relative_path, node.lineno,
                                    "sast-sql-injection",
                                    "SQL query with string formatting - potential SQL injection",
                                )
                            )

                if isinstance(func, ast.Attribute) and func.attr in ("md5", "sha1"):
                    if isinstance(func.value, ast.Name) and func.value.id == "hashlib":
                        if not self._is_nosec_line(lines, node.lineno):
                            findings.append(
                                self._create_sast_finding(
                                    relative_path, node.lineno,
                                    "sast-insecure-hash",
                                    f"Use of hashlib.{func.attr}() - insecure hash algorithm",
                                )
                            )

            if isinstance(node, ast.Assert):
                if not self._is_nosec_line(lines, node.lineno):
                    findings.append(
                        self._create_sast_finding(
                            relative_path, node.lineno,
                            "sast-assert-statement",
                            "Assert statement used - can be optimized away with -O flag",
                        )
                    )

        return findings

    def _scan_lines(
        self,
        content: str,
        relative_path: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        # Patterns for line-based detection
        line_patterns: List[Tuple[str, str, str]] = [
            # Subprocess shell=True (line-based fallback)
            (
                r"subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
                "sast-shell-true",
                "subprocess call with shell=True - OS command injection risk",
            ),
            # Hardcoded HTTP URLs
            (
                r"https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|test\.)[^\s'\"]+",
                "sast-http-url",
                "Hardcoded HTTP URL - potential insecure communication",
            ),
            # SQL injection pattern (string format in execute)
            (
                r"\.execute\s*\(\s*(?:f['\"]|format\(|%s|%d)",
                "sast-sql-injection",
                "Potential SQL injection via string formatting in execute()",
            ),
            # Input without validation
            (
                r"(?:input|raw_input)\s*\(",
                "sast-input-validation",
                "User input without validation - potential security risk",
            ),
        ]

        for line_num, line in enumerate(lines, start=1):
            # Skip nosec lines
            if self._is_nosec_line(lines, line_num):
                continue

            for pattern_str, rule_id, message in line_patterns:
                try:
                    if re.search(pattern_str, line):
                        findings.append(
                            self._create_sast_finding(
                                relative_path, line_num,
                                rule_id, message,
                            )
                        )
                except re.error:
                    continue

        return findings


    @staticmethod
    def _has_shell_true(call_node: ast.Call) -> bool:
        for keyword in call_node.keywords:
            if keyword.arg == "shell":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    return True
                if isinstance(keyword.value, ast.NameConstant) and keyword.value.value is True:
                    return True
        return False

    @staticmethod
    def _has_loader_arg(call_node: ast.Call) -> bool:
        for keyword in call_node.keywords:
            if keyword.arg == "Loader":
                return True
        return False

    @staticmethod
    def _has_string_format_arg(call_node: ast.Call) -> bool:
        if not call_node.args:
            return False

        first_arg = call_node.args[0]

        # f-string (JoinedStr in AST)
        if isinstance(first_arg, ast.JoinedStr):
            return True

        # .format() call
        if isinstance(first_arg, ast.Call):
            if isinstance(first_arg.func, ast.Attribute):
                if first_arg.func.attr == "format":
                    return True

        # % formatting (BinOp with Mod)
        if isinstance(first_arg, ast.BinOp):
            if isinstance(first_arg.op, ast.Mod):
                return True

        return False

    @staticmethod
    def _is_nosec_line(lines: List[str], line_num: int) -> bool:
        if 1 <= line_num <= len(lines):
            line = lines[line_num - 1]
            return "# nosec" in line
        return False


    def _create_sast_finding(
        self,
        file: str,
        line: int,
        rule_id: str,
        message: str,
    ) -> Finding:
        severity, cvss_score = SEVERITY_MAP.get(rule_id, ("medium", 5.0))
        cwe_id = INTERNAL_RULE_TO_CWE.get(rule_id, "CWE-20")
        fix_suggestion = REMEDIATION_MAP.get(rule_id, "")

        return self._create_finding(
            file=file,
            line=line,
            message=message,
            severity=severity,
            cvss_score=cvss_score,
            rule_id=rule_id,
            cwe_id=cwe_id,
            fix_suggestion=fix_suggestion,
            finding_type="vulnerability",
            confidence="high",
        )

    @staticmethod
    def _map_bandit_severity(
        confidence: str,
        severity: str,
    ) -> str:
        severity_upper = severity.upper()
        if severity_upper == "HIGH":
            return "high"
        elif severity_upper == "MEDIUM":
            return "medium"
        elif severity_upper == "LOW":
            return "low"
        return "medium"

    @staticmethod
    def _normalize_severity_string(severity: str) -> str:
        s = severity.strip().upper()
        mapping = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "ERROR": "high",
            "WARNING": "medium",
            "MEDIUM": "medium",
            "INFO": "low",
            "LOW": "low",
            "NOTE": "info",
        }
        return mapping.get(s, "medium")

    @staticmethod
    def _severity_to_cvss(severity: str) -> float:
        cvss_map = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.5,
            "low": 3.0,
            "info": 0.0,
        }
        return cvss_map.get(severity, 5.0)

    @staticmethod
    def _map_confidence(confidence: str) -> str:
        c = confidence.strip().upper()
        mapping = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
        return mapping.get(c, "medium")

    @staticmethod
    def _get_bandit_remediation(bandit_id: str) -> str:
        # Map Bandit IDs to our internal rules for remediation lookup
        bandit_to_internal = {
            "B608": "sast-sql-injection",
            "B609": "sast-sql-injection",
            "B307": "sast-eval-usage",
            "B102": "sast-exec-usage",
            "B602": "sast-shell-true",
            "B603": "sast-shell-true",
            "B604": "sast-shell-true",
            "B605": "sast-shell-true",
            "B606": "sast-shell-true",
            "B301": "sast-pickle-load",
            "B304": "sast-pickle-load",
            "B506": "sast-yaml-load",
            "B303": "sast-insecure-hash",
            "B324": "sast-insecure-hash",
            "B101": "sast-assert-statement",
        }
        internal_rule = bandit_to_internal.get(bandit_id, "")
        return REMEDIATION_MAP.get(
            internal_rule,
            "Review this finding and apply appropriate security measures.",
        )

    @staticmethod
    def _deduplicate_findings(
        findings: List[Finding],
    ) -> List[Finding]:
        seen: Set[Tuple[str, int, str]] = set()
        unique: List[Finding] = []
        for finding in findings:
            key = (finding.file, finding.line, finding.rule_id)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique


# Maximum file size for AST scanning (1 MB)
_MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024
