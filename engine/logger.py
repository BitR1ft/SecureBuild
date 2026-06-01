"""SecureBuild CI/CD Security Gate - Logging System"""

from __future__ import annotations

import json
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional


_LOG_DIR = os.environ.get("SECUREBUILD_LOG_DIR", "logs")
_LOG_FILE = os.environ.get("SECUREBUILD_LOG_FILE", "securebuild.log")
_MAX_LOG_BYTES = int(os.environ.get("SECUREBUILD_LOG_MAX_BYTES", 10 * 1024 * 1024))  # 10 MB
_MAX_LOG_BACKUPS = int(os.environ.get("SECUREBUILD_LOG_BACKUPS", 5))
_DEFAULT_LOG_LEVEL = os.environ.get("SECUREBUILD_LOG_LEVEL", "INFO").upper()

# Track whether the root configuration has been applied
_configured = False


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add contextual fields if present
        for field_name in ("gate", "repo", "run_id"):
            value = getattr(record, field_name, None)
            if value:
                log_entry[field_name] = value

        # Merge in any extra fields the caller provided
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            log_entry.update(record.extra_fields)

        # Include exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


class HumanReadableFormatter(logging.Formatter):
    """Formats log records as human-readable console output."""

    COLORS: Dict[str, str] = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[1;31m",  # Bold Red
    }
    RESET = "\033[0m"

    def __init__(self, use_color: bool = True) -> None:
        super().__init__()
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record, datefmt="%Y-%m-%d %H:%M:%S")
        level = record.levelname
        name = record.name

        # Build contextual suffix
        context_parts: list[str] = []
        for field_name in ("gate", "repo", "run_id"):
            value = getattr(record, field_name, None)
            if value:
                context_parts.append(f"{field_name}:{value}")
        context = f"[{'|'.join(context_parts)}] " if context_parts else ""

        message = record.getMessage()

        if self.use_color and sys.stderr.isatty():
            color = self.COLORS.get(level, "")
            formatted = (
                f"[{timestamp}] {color}{level:<8}{self.RESET} "
                f"{context}{message}"
            )
        else:
            formatted = f"[{timestamp}] {level:<8} {context}{message}"

        # Append exception info on new lines
        if record.exc_info and record.exc_info[0] is not None:
            formatted += "\n" + self.formatException(record.exc_info)

        return formatted


class SecureBuildLoggerAdapter(logging.LoggerAdapter):
    """Logger adapter that injects SecureBuild context into log records."""

    def process(
        self,
        msg: str,
        kwargs: Any,
    ) -> tuple[str, Any]:
        extra = kwargs.get("extra", {})
        if self.extra:
            merged = {**self.extra, **extra}
            # Store non-standard fields in extra_fields for JSON formatter
            standard_fields = {"gate", "repo", "run_id"}
            extra_fields = {
                k: v for k, v in merged.items() if k not in standard_fields
            }
            if extra_fields:
                merged["extra_fields"] = extra_fields
            kwargs["extra"] = merged
        return msg, kwargs


def _ensure_log_directory() -> Path:
    log_dir = Path(_LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def _configure_root_logger() -> None:
    global _configured
    if _configured:
        return
    _configured = True

    root = logging.getLogger("securebuild")
    root.setLevel(getattr(logging, _DEFAULT_LOG_LEVEL, logging.INFO))

    # Prevent duplicate handlers on re-configuration
    if root.handlers:
        return

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(HumanReadableFormatter(use_color=True))
    root.addHandler(console_handler)

    try:
        log_dir = _ensure_log_directory()
        log_path = log_dir / _LOG_FILE
        file_handler = RotatingFileHandler(
            str(log_path),
            maxBytes=_MAX_LOG_BYTES,
            backupCount=_MAX_LOG_BACKUPS,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(StructuredJsonFormatter())
        root.addHandler(file_handler)
    except (OSError, PermissionError):
        # If we can't create the log file, continue with console-only
        root.warning(
            "Could not create log file at %s/%s; using console-only logging",
            _LOG_DIR,
            _LOG_FILE,
        )


def get_logger(name: str, **default_context: Any) -> SecureBuildLoggerAdapter:
    _configure_root_logger()
    base_logger = logging.getLogger(f"securebuild.{name}")
    return SecureBuildLoggerAdapter(base_logger, extra=default_context or None)


def set_log_level(level: str) -> None:
    _configure_root_logger()
    numeric_level = getattr(logging, level.upper(), None)
    if isinstance(numeric_level, int):
        root = logging.getLogger("securebuild")
        root.setLevel(numeric_level)
    else:
        logging.getLogger("securebuild").warning(
            "Invalid log level: %s", level
        )
