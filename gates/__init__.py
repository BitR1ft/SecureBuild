"""SecureBuild CI/CD Security Gate - Gates Package"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gates.base import BaseGate
    from gates.cwe_map import (
        BANDIT_TO_CWE,
        CWE_DATABASE,
        CWEInfo,
        INTERNAL_RULE_TO_CWE,
        SEMGREP_TO_CWE,
        bandit_to_cwe,
        get_cwe_info,
        rule_to_cwe,
        semgrep_to_cwe,
    )
    from gates.entropy import calculate_entropy, is_high_entropy
    from gates.gate1_secrets import SecretsGate
    from gates.gate2_sast import SASTGate
    from gates.gate3_cve import CVEGate


def __getattr__(name: str) -> object:
    _lazy_imports = {
        "BaseGate": "gates.base",
        "SecretsGate": "gates.gate1_secrets",
        "SASTGate": "gates.gate2_sast",
        "CVEGate": "gates.gate3_cve",
        "calculate_entropy": "gates.entropy",
        "is_high_entropy": "gates.entropy",
        "CWE_DATABASE": "gates.cwe_map",
        "CWEInfo": "gates.cwe_map",
        "BANDIT_TO_CWE": "gates.cwe_map",
        "SEMGREP_TO_CWE": "gates.cwe_map",
        "INTERNAL_RULE_TO_CWE": "gates.cwe_map",
        "bandit_to_cwe": "gates.cwe_map",
        "semgrep_to_cwe": "gates.cwe_map",
        "rule_to_cwe": "gates.cwe_map",
        "get_cwe_info": "gates.cwe_map",
    }
    if name in _lazy_imports:
        import importlib
        module = importlib.import_module(_lazy_imports[name])
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BaseGate",
    "SecretsGate",
    "SASTGate",
    "CVEGate",
    "calculate_entropy",
    "is_high_entropy",
    "BANDIT_TO_CWE",
    "CWE_DATABASE",
    "CWEInfo",
    "INTERNAL_RULE_TO_CWE",
    "SEMGREP_TO_CWE",
    "bandit_to_cwe",
    "get_cwe_info",
    "rule_to_cwe",
    "semgrep_to_cwe",
]
