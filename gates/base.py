"""SecureBuild CI/CD Security Gate - Abstract Gate Base Class"""

from __future__ import annotations

import fnmatch
import re
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from engine.config import SecureBuildConfig
from engine.logger import get_logger
from engine.models import Finding, GateResult
from engine.utils import is_binary_file, safe_read_file


class BaseGate(ABC):
    """Abstract base class for all security gates."""

    def __init__(self, config: Optional[SecureBuildConfig] = None) -> None:
        self.config = config or SecureBuildConfig()
        self.logger = get_logger(
            f"gate.{self.__class__.__name__.lower()}",
            gate=self.name if hasattr(self, '_name_resolved') else "",
        )
        # Resolve name after class is fully constructed
        self._gate_name = self.name


    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        ...

    @abstractmethod
    def run(self, repo_path: str) -> GateResult:
        ...

    @abstractmethod
    def get_severity_map(self) -> Dict[str, str]:
        ...


    def _scan_files(
        self,
        repo_path: str,
        extensions: Optional[Set[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
    ) -> List[Path]:
        root = Path(repo_path).resolve()
        config_excludes = self.config.excluded_patterns
        extra_excludes = exclude_patterns or []
        all_excludes = config_excludes + extra_excludes

        max_size_bytes = self.config.max_file_size_mb * 1024 * 1024
        scan_files: List[Path] = []

        for filepath in root.rglob("*"):
            # Skip directories
            if not filepath.is_file():
                continue

            # Skip binary files
            if is_binary_file(str(filepath)):
                continue

            # Check file extension filter
            if extensions and filepath.suffix.lower() not in extensions:
                continue

            # Check file size
            try:
                if filepath.stat().st_size > max_size_bytes:
                    continue
            except OSError:
                continue

            # Check exclusion patterns (match against relative path)
            try:
                relative = filepath.relative_to(root)
                relative_str = str(relative).replace("\\", "/")
            except ValueError:
                continue

            if self._matches_exclusion(relative_str, all_excludes):
                continue

            scan_files.append(filepath)

        scan_files.sort()
        self.logger.info(
            "Found %d files to scan (extensions=%s)",
            len(scan_files),
            extensions or "all",
        )
        return scan_files

    @staticmethod
    def _matches_exclusion(relative_path: str, patterns: List[str]) -> bool:
        for pattern in patterns:
            # Match against the full path
            if fnmatch.fnmatch(relative_path, pattern):
                return True
            # Match against individual path components (for ** patterns)
            if "/" in pattern:
                if fnmatch.fnmatch(relative_path, pattern):
                    return True
            # Match directory prefix
            parts = relative_path.split("/")
            for i in range(len(parts)):
                partial = "/".join(parts[: i + 1])
                if fnmatch.fnmatch(partial, pattern.rstrip("/*")):
                    return True
        return False

    def _read_file(self, filepath: str) -> Optional[str]:
        max_bytes = self.config.max_file_size_mb * 1024 * 1024
        return safe_read_file(filepath, max_size_bytes=max_bytes)


    def _create_finding(
        self,
        file: str,
        line: int,
        message: str,
        severity: str = "medium",
        cvss_score: float = 0.0,
        rule_id: str = "",
        cwe_id: str = "",
        fix_suggestion: str = "",
        fix_diff: str = "",
        finding_type: str = "vulnerability",
        confidence: str = "medium",
    ) -> Finding:
        return Finding(
            id=str(uuid.uuid4()),
            gate=self._gate_name,
            file=file,
            line=line,
            message=message,
            cvss_score=cvss_score,
            severity=severity,
            fix_suggestion=fix_suggestion,
            fix_diff=fix_diff,
            cwe_id=cwe_id,
            rule_id=rule_id,
            finding_type=finding_type,
            confidence=confidence,
        )


    def _compile_patterns(self, patterns: List[str]) -> List[re.Pattern]:
        compiled: List[re.Pattern] = []
        for pattern_str in patterns:
            try:
                compiled.append(re.compile(pattern_str))
            except re.error as exc:
                self.logger.warning(
                    "Invalid regex pattern skipped: %s (%s)",
                    pattern_str,
                    str(exc),
                )
        return compiled

    def _search_content(
        self,
        content: str,
        patterns: List[re.Pattern],
        file_path: str,
        rule_id_prefix: str = "",
    ) -> List[Finding]:
        findings: List[Finding] = []
        severity_map = self.get_severity_map()

        for line_num, line in enumerate(content.splitlines(), start=1):
            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    rule_id = f"{rule_id_prefix}{pattern.pattern}" if rule_id_prefix else pattern.pattern
                    severity = severity_map.get(rule_id, "medium")
                    findings.append(
                        self._create_finding(
                            file=file_path,
                            line=line_num,
                            message=f"Pattern match: {match.group()!r}",
                            severity=severity,
                            rule_id=rule_id,
                        )
                    )
        return findings


    def _build_gate_result(
        self,
        findings: List[Finding],
        files_scanned: int = 0,
        files_skipped: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GateResult:
        # Count findings by severity
        severity_counts: Dict[str, int] = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        # Determine status based on thresholds
        threshold = self.config.get_gate_threshold(self._gate_name)
        status = "pass"

        if severity_counts.get("critical", 0) > threshold.max_critical:
            status = "fail"
        elif severity_counts.get("high", 0) > threshold.max_high:
            status = "fail"
        elif severity_counts.get("medium", 0) > threshold.max_medium:
            status = "fail"
        elif severity_counts.get("low", 0) > threshold.max_low and threshold.max_low >= 0:
            status = "fail"

        result_metadata = metadata or {}
        result_metadata["severity_counts"] = severity_counts

        return GateResult(
            gate_name=self._gate_name,
            status=status,
            findings=findings,
            files_scanned=files_scanned,
            files_skipped=files_skipped,
            metadata=result_metadata,
        )

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self._gate_name!r})>"
