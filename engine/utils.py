"""SecureBuild CI/CD Security Gate - Utility Functions"""

from __future__ import annotations

import hashlib
import math
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from engine.exceptions import InvalidRepoError


_BINARY_SIGNATURES: List[bytes] = [
    b"\x00",  # Null byte — common in binary files
    b"\xff\xd8\xff",  # JPEG
    b"\x89PNG",  # PNG
    b"GIF8",  # GIF
    b"PK\x03\x04",  # ZIP / JAR / DOCX
    b"\x1f\x8b",  # GZIP
    b"\x7fELF",  # ELF binary
    b"MZ",  # PE / EXE
    b"\xfd7zXZ",  # XZ
    b"BZ",  # BZIP2
]

# File extensions that are always considered binary
_BINARY_EXTENSIONS: set = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".wav", ".ogg",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".so", ".dylib", ".o", ".obj", ".a", ".lib",
    ".class", ".jar", ".war", ".pyc", ".pyo", ".nupkg", ".deb",
    ".rpm", ".dmg", ".iso", ".woff", ".woff2", ".ttf", ".eot",
    ".otf", ".sqlite", ".db",
}


def generate_run_id() -> str:
    date_prefix = datetime.now(timezone.utc).strftime("%Y%m%d")
    short_uuid = uuid.uuid4().hex[:8]
    return f"{date_prefix}-{short_uuid}"


def get_repo_name(repo_path: str) -> str:
    return Path(repo_path).resolve().name


def get_current_branch(repo_path: str) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise InvalidRepoError(
                repo_path,
                reason=f"git rev-parse failed: {result.stderr.strip()}",
            )
        return result.stdout.strip()
    except FileNotFoundError:
        raise InvalidRepoError(repo_path, reason="git is not installed or not on PATH")
    except subprocess.TimeoutExpired:
        raise InvalidRepoError(repo_path, reason="git command timed out")


def get_commit_hash(repo_path: str) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise InvalidRepoError(
                repo_path,
                reason=f"git rev-parse HEAD failed: {result.stderr.strip()}",
            )
        return result.stdout.strip()
    except FileNotFoundError:
        raise InvalidRepoError(repo_path, reason="git is not installed or not on PATH")
    except subprocess.TimeoutExpired:
        raise InvalidRepoError(repo_path, reason="git command timed out")


def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0

    length = len(data)
    if length == 0:
        return 0.0

    # Count character frequencies
    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    # Calculate entropy
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def is_binary_file(filepath: str) -> bool:
    path = Path(filepath)

    # Step 1: Check extension
    if path.suffix.lower() in _BINARY_EXTENSIONS:
        return True

    # Step 2: Check file content
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(8192)

        if not chunk:
            return False

        # Check for null bytes (strong indicator of binary content)
        if b"\x00" in chunk:
            return True

        # Check against known binary signatures
        for sig in _BINARY_SIGNATURES:
            if chunk.startswith(sig):
                return True

        # Heuristic: if a significant portion of bytes are outside
        # the printable ASCII range, consider it binary
        printable_count = sum(
            1 for b in chunk if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)
        )
        if len(chunk) > 0 and (printable_count / len(chunk)) < 0.85:
            return True

    except (OSError, PermissionError):
        # If we can't read the file, treat it as binary to skip it
        return True

    return False


def get_file_hash(filepath: str) -> str:
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, PermissionError):
        return ""


def is_git_repo(repo_path: str) -> bool:
    git_path = Path(repo_path) / ".git"
    return git_path.exists()


def validate_repo_path(repo_path: str) -> Path:
    path = Path(repo_path).resolve()

    if not path.exists():
        raise InvalidRepoError(str(path), reason="path does not exist")
    if not path.is_dir():
        raise InvalidRepoError(str(path), reason="path is not a directory")
    if not is_git_repo(str(path)):
        raise InvalidRepoError(
            str(path), reason="not a git repository (no .git directory found)"
        )

    import os as _os
    allowed_raw = _os.environ.get("SECUREBUILD_ALLOWED_PATHS", "")
    if allowed_raw:
        # Support both colon and semicolon separators
        sep = ";" if ";" in allowed_raw else ":"
        allowed_bases = [Path(p.strip()).resolve() for p in allowed_raw.split(sep) if p.strip()]
        in_allowed = any(
            _is_subpath(path, base) for base in allowed_bases
        )
        if not in_allowed:
            raise InvalidRepoError(
                str(path),
                reason=(
                    "path is outside the configured allowed base directories "
                    "(SECUREBUILD_ALLOWED_PATHS)"
                ),
            )

    return path


def _is_subpath(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def safe_read_file(filepath: str, max_size_bytes: int = 1_048_576) -> Optional[str]:
    try:
        path = Path(filepath)
        if not path.is_file():
            return None

        # Skip binary files
        if is_binary_file(filepath):
            return None

        # Check file size
        file_size = path.stat().st_size
        if file_size > max_size_bytes:
            return None

        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError, UnicodeDecodeError):
        return None


def normalize_severity(severity: str) -> str:
    normalized = severity.strip().lower()
    aliases = {
        "crit": "critical",
        "c": "critical",
        "urgent": "critical",
        "h": "high",
        "important": "high",
        "warning": "medium",
        "moderate": "medium",
        "m": "medium",
        "l": "low",
        "minor": "low",
        "informational": "info",
        "note": "info",
        "i": "info",
        "none": "info",
    }
    return aliases.get(normalized, normalized) if normalized in aliases else (
        normalized if normalized in {"critical", "high", "medium", "low", "info"} else "info"
    )
