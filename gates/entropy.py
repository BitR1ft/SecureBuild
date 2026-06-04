"""SecureBuild CI/CD Security Gate - Entropy Calculator"""

from __future__ import annotations

from engine.utils import calculate_shannon_entropy as calculate_entropy  # noqa: F401


def is_high_entropy(
    data: str,
    threshold: float = 4.5,
    min_length: int = 20,
) -> bool:
    if len(data) < min_length:
        return False
    return calculate_entropy(data) > threshold
