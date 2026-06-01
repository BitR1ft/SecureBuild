"""SecureBuild CI/CD Security Gate - Engine Package"""

from __future__ import annotations

from typing import TYPE_CHECKING

# Import only the leaf modules that don't create circular dependencies
from engine.config import SecureBuildConfig, GateThreshold
from engine.exceptions import (
    APITimeoutError,
    ConfigValidationError,
    GateExecutionError,
    InvalidRepoError,
    ReportGenerationError,
    ScoringError,
)
from engine.models import Finding, GateResult, RemediationSuggestion, RiskScore, RunResult
from engine.utils import (
    calculate_shannon_entropy,
    generate_run_id,
    get_commit_hash,
    get_current_branch,
    get_file_hash,
    get_repo_name,
    is_binary_file,
    is_git_repo,
    normalize_severity,
    safe_read_file,
    validate_repo_path,
)

# Lazy imports for modules that depend on gates.base (circular import avoidance)
if TYPE_CHECKING:
    from engine.db import DatabaseManager
    from engine.orchestrator import Orchestrator, RiskScorer
    from engine.runner import GateRunner, run_gates_parallel


def __getattr__(name: str) -> object:
    _lazy_imports = {
        "DatabaseManager": "engine.db",
        "Orchestrator": "engine.orchestrator",
        "RiskScorer": "engine.orchestrator",
        "GateRunner": "engine.runner",
        "run_gates_parallel": "engine.runner",
    }
    if name in _lazy_imports:
        import importlib
        module = importlib.import_module(_lazy_imports[name])
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Config
    "SecureBuildConfig",
    "GateThreshold",
    # Database
    "DatabaseManager",
    # Exceptions
    "APITimeoutError",
    "ConfigValidationError",
    "GateExecutionError",
    "InvalidRepoError",
    "ReportGenerationError",
    "ScoringError",
    # Models
    "Finding",
    "GateResult",
    "RemediationSuggestion",
    "RiskScore",
    "RunResult",
    # Orchestrator
    "Orchestrator",
    "RiskScorer",
    # Runner
    "GateRunner",
    "run_gates_parallel",
    # Utilities
    "calculate_shannon_entropy",
    "generate_run_id",
    "get_commit_hash",
    "get_current_branch",
    "get_file_hash",
    "get_repo_name",
    "is_binary_file",
    "is_git_repo",
    "normalize_severity",
    "safe_read_file",
    "validate_repo_path",
]
