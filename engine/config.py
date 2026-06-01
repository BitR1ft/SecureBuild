"""SecureBuild CI/CD Security Gate - Configuration Loader"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from engine.exceptions import ConfigValidationError
from engine.logger import get_logger

logger = get_logger("config")


_DEFAULT_THRESHOLDS: Dict[str, int] = {
    "critical": 0,   # Zero tolerance for critical findings
    "high": 5,       # Allow up to 5 high-severity findings
    "medium": 20,    # Allow up to 20 medium-severity findings
    "low": 50,       # Allow up to 50 low-severity findings
    "info": -1,      # -1 means no limit (informational only)
}

_DEFAULT_ENABLED_GATES: List[str] = [
    "secrets",
    "sast",
    "cve",
    "license",
    "iac",
]

_DEFAULT_EXCLUDE_PATTERNS: List[str] = [
    "*.pyc",
    "__pycache__/*",
    ".git/*",
    ".git/**",
    "node_modules/*",
    "node_modules/**",
    ".venv/*",
    ".venv/**",
    "venv/*",
    "venv/**",
    "dist/*",
    "dist/**",
    "build/*",
    "build/**",
    ".tox/*",
    ".tox/**",
    "*.min.js",
    "*.min.css",
    "*.bundle.js",
    "vendor/*",
    "vendor/**",
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "Pipfile.lock",
    "poetry.lock",
]

_DEFAULT_SECRET_PATTERNS: List[str] = [
    r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}",
    r"(?i)(secret[_-]?key|secretkey)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}",
    r"(?i)(access[_-]?key|accesskey)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}",
    r"(?i)(private[_-]?key|privatekey)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}",
    r"(?i)password\s*[:=]\s*['\"]?[^\s'\"]{8,}",
    r"(?i)token\s*[:=]\s*['\"]?[a-zA-Z0-9._-]{20,}",
    r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    r"ghp_[a-zA-Z0-9]{36}",           # GitHub PAT
    r"gho_[a-zA-Z0-9]{36}",           # GitHub OAuth
    r"ghu_[a-zA-Z0-9]{36}",           # GitHub User-to-Server
    r"ghs_[a-zA-Z0-9]{36}",           # GitHub Server-to-Server
    r"sk-[a-zA-Z0-9]{48}",            # OpenAI API key
    r"AKIA[0-9A-Z]{16}",              # AWS Access Key ID
    r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[a-zA-Z0-9/+=]{40}",
    r"eyJ[a-zA-Z0-9._-]+",            # JWT tokens
    r"xox[bpas]-[a-zA-Z0-9-]+",       # Slack tokens
]

_DEFAULT_ENTROPY_THRESHOLD: float = 4.5
_DEFAULT_MAX_FILE_SIZE_MB: int = 10
_DEFAULT_GATE_TIMEOUT_SECONDS: int = 300  # 5 minutes
_DEFAULT_MAX_WORKERS: int = 5
_DEFAULT_DATABASE_PATH: str = "securebuild.db"


@dataclass
class GateThreshold:
    """Threshold configuration for a single gate."""

    enabled: bool = True
    max_critical: int = 0
    max_high: int = 5
    max_medium: int = 20
    max_low: int = 50
    custom_patterns: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "max_critical": self.max_critical,
            "max_high": self.max_high,
            "max_medium": self.max_medium,
            "max_low": self.max_low,
            "custom_patterns": self.custom_patterns,
            "extra": self.extra,
        }


class SecureBuildConfig:
    """Central configuration for the SecureBuild engine."""

    def __init__(self, config_data: Optional[Dict[str, Any]] = None) -> None:
        data = config_data or {}
        self._raw = data
        self._load_env_overrides()

        self._thresholds: Dict[str, GateThreshold] = self._parse_thresholds(
            data.get("thresholds", {})
        )

        # Parse enabled gates from the YAML "gates" section if present
        gates_section = data.get("gates", {})
        if isinstance(gates_section, dict) and gates_section:
            enabled_gates = [
                name for name, cfg in gates_section.items()
                if isinstance(cfg, dict) and cfg.get("enabled", True)
            ]
            self._enabled_gates: List[str] = data.get(
                "enabled_gates", enabled_gates
            )
        else:
            self._enabled_gates: List[str] = data.get(
                "enabled_gates", _DEFAULT_ENABLED_GATES
            )
        self._excluded_patterns: List[str] = data.get(
            "excluded_patterns", _DEFAULT_EXCLUDE_PATTERNS
        )
        self._secret_patterns: List[str] = data.get(
            "secret_patterns", _DEFAULT_SECRET_PATTERNS
        )

        self._entropy_threshold: float = float(
            data.get("entropy_threshold", _DEFAULT_ENTROPY_THRESHOLD)
        )
        self._max_file_size_mb: int = int(
            data.get("max_file_size_mb", _DEFAULT_MAX_FILE_SIZE_MB)
        )
        self._gate_timeout_seconds: int = int(
            data.get("gate_timeout_seconds", _DEFAULT_GATE_TIMEOUT_SECONDS)
        )
        self._max_workers: int = int(
            data.get("max_workers", _DEFAULT_MAX_WORKERS)
        )

        self._database_path: str = data.get(
            "database_path", _DEFAULT_DATABASE_PATH
        )

        self._fail_on_critical: bool = bool(
            data.get("fail_on_critical", True)
        )
        self._fail_on_high: bool = bool(data.get("fail_on_high", False))

        self._output_dir: str = data.get("output_dir", "reports")

        self._ai_provider: str = data.get("ai_provider", "")
        self._ai_api_key: str = data.get("ai_api_key", "")
        self._ai_model: str = data.get("ai_model", "")

        self._validate()


    def _load_env_overrides(self) -> None:
        env_mapping = {
            "SECUREBUILD_DATABASE_PATH": ("database_path", str),
            "SECUREBUILD_AI_API_KEY": ("ai_api_key", str),
            "SECUREBUILD_AI_PROVIDER": ("ai_provider", str),
            "SECUREBUILD_AI_MODEL": ("ai_model", str),
            "SECUREBUILD_FAIL_ON_CRITICAL": ("fail_on_critical", self._parse_bool),
            "SECUREBUILD_FAIL_ON_HIGH": ("fail_on_high", self._parse_bool),
            "SECUREBUILD_GATE_TIMEOUT": ("gate_timeout_seconds", int),
            "SECUREBUILD_MAX_WORKERS": ("max_workers", int),
            "SECUREBUILD_ENTROPY_THRESHOLD": ("entropy_threshold", float),
        }

        for env_var, (config_key, type_func) in env_mapping.items():
            value = os.environ.get(env_var)
            if value is not None:
                self._raw[config_key] = type_func(value)

    @staticmethod
    def _parse_bool(value: str) -> bool:
        return value.strip().lower() in ("true", "1", "yes", "on")


    def _parse_thresholds(
        self, thresholds_data: Dict[str, Any]
    ) -> Dict[str, GateThreshold]:
        thresholds: Dict[str, GateThreshold] = {}

        # Build thresholds for all known gates
        all_gates = set(_DEFAULT_ENABLED_GATES) | set(thresholds_data.keys())
        for gate_name in all_gates:
            gate_data = thresholds_data.get(gate_name, {})
            if isinstance(gate_data, dict):
                thresholds[gate_name] = GateThreshold(
                    enabled=gate_data.get("enabled", True),
                    max_critical=gate_data.get("max_critical", _DEFAULT_THRESHOLDS["critical"]),
                    max_high=gate_data.get("max_high", _DEFAULT_THRESHOLDS["high"]),
                    max_medium=gate_data.get("max_medium", _DEFAULT_THRESHOLDS["medium"]),
                    max_low=gate_data.get("max_low", _DEFAULT_THRESHOLDS["low"]),
                    custom_patterns=gate_data.get("custom_patterns", []),
                    extra=gate_data.get("extra", {}),
                )
            else:
                # If the gate data is not a dict, use defaults
                thresholds[gate_name] = GateThreshold()

        return thresholds


    def _validate(self) -> None:
        # Validate entropy threshold range
        if not (0.0 <= self._entropy_threshold <= 8.0):
            raise ConfigValidationError(
                field="entropy_threshold",
                value=self._entropy_threshold,
                constraint="must be between 0.0 and 8.0",
            )

        # Validate max file size
        if self._max_file_size_mb < 1:
            raise ConfigValidationError(
                field="max_file_size_mb",
                value=self._max_file_size_mb,
                constraint="must be at least 1 MB",
            )

        # Validate gate timeout
        if self._gate_timeout_seconds < 10:
            raise ConfigValidationError(
                field="gate_timeout_seconds",
                value=self._gate_timeout_seconds,
                constraint="must be at least 10 seconds",
            )

        # Validate max workers
        if self._max_workers < 1:
            raise ConfigValidationError(
                field="max_workers",
                value=self._max_workers,
                constraint="must be at least 1",
            )

        # Validate enabled gates list is not empty
        if not self._enabled_gates:
            raise ConfigValidationError(
                field="enabled_gates",
                value=self._enabled_gates,
                constraint="at least one gate must be enabled",
            )

        # Validate threshold values for each gate
        for gate_name, threshold in self._thresholds.items():
            for severity_field in ("max_critical", "max_high", "max_medium", "max_low"):
                value = getattr(threshold, severity_field)
                if value < -1:
                    raise ConfigValidationError(
                        field=f"thresholds.{gate_name}.{severity_field}",
                        value=value,
                        constraint="must be -1 (no limit) or >= 0",
                    )


    @classmethod
    def from_file(cls, path: str = "securebuild.yaml") -> SecureBuildConfig:
        config_path = Path(path)

        if not config_path.exists():
            logger.info(
                "Config file not found at %s; using defaults",
                path,
            )
            return cls()

        try:
            import yaml  # type: ignore

            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            logger.info("Loaded configuration from %s", path)
            return cls(config_data=data)

        except ImportError:
            logger.warning(
                "PyYAML not installed; cannot parse %s. Using defaults.",
                path,
            )
            return cls()
        except Exception as exc:
            raise ConfigValidationError(
                field="config_file",
                value=path,
                constraint=f"failed to parse: {exc}",
            )


    @property
    def thresholds(self) -> Dict[str, GateThreshold]:
        return self._thresholds

    @property
    def enabled_gates(self) -> List[str]:
        return self._enabled_gates

    @property
    def excluded_patterns(self) -> List[str]:
        return self._excluded_patterns

    @property
    def secret_patterns(self) -> List[str]:
        return self._secret_patterns

    @property
    def entropy_threshold(self) -> float:
        return self._entropy_threshold

    @property
    def max_file_size_mb(self) -> int:
        return self._max_file_size_mb

    @property
    def gate_timeout_seconds(self) -> int:
        return self._gate_timeout_seconds

    @property
    def max_workers(self) -> int:
        return self._max_workers

    @property
    def database_path(self) -> str:
        return self._database_path

    @property
    def fail_on_critical(self) -> bool:
        return self._fail_on_critical

    @property
    def fail_on_high(self) -> bool:
        return self._fail_on_high

    @property
    def output_dir(self) -> str:
        return self._output_dir

    @property
    def ai_provider(self) -> str:
        return self._ai_provider

    @property
    def ai_api_key(self) -> str:
        return self._ai_api_key

    @property
    def ai_model(self) -> str:
        return self._ai_model

    @property
    def is_ai_enabled(self) -> bool:
        return bool(self._ai_provider and self._ai_api_key)


    def get_gate_threshold(self, gate_name: str) -> GateThreshold:
        return self._thresholds.get(gate_name, GateThreshold())

    def is_gate_enabled(self, gate_name: str) -> bool:
        if gate_name not in self._enabled_gates:
            return False
        threshold = self._thresholds.get(gate_name)
        return threshold.enabled if threshold else True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled_gates": self._enabled_gates,
            "excluded_patterns": self._excluded_patterns,
            "secret_patterns": self._secret_patterns,
            "entropy_threshold": self._entropy_threshold,
            "max_file_size_mb": self._max_file_size_mb,
            "gate_timeout_seconds": self._gate_timeout_seconds,
            "max_workers": self._max_workers,
            "database_path": self._database_path,
            "fail_on_critical": self._fail_on_critical,
            "fail_on_high": self._fail_on_high,
            "output_dir": self._output_dir,
            "ai_provider": self._ai_provider,
            "ai_model": self._ai_model,
            "ai_enabled": self.is_ai_enabled,
            "thresholds": {
                name: t.to_dict() for name, t in self._thresholds.items()
            },
        }
