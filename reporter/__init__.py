"""SecureBuild CI/CD Security Gate - Reporter Package"""

from __future__ import annotations

from reporter.renderer import (
    SEVERITY_COLORS,
    ReportRenderer,
    cvss_color,
    format_cvss,
    format_duration,
    get_grade,
    severity_badge,
    truncate_path,
)

__all__ = [
    # Renderer
    "ReportRenderer",
    "SEVERITY_COLORS",
    # Custom Jinja2 filters (exported for reuse)
    "cvss_color",
    "severity_badge",
    "format_cvss",
    "truncate_path",
    "format_duration",
    # Grade helper
    "get_grade",
]
