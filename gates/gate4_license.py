"""SecureBuild CI/CD Security Gate - License Compliance Checker (Gate 4)"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from engine.config import SecureBuildConfig
from engine.logger import get_logger
from engine.models import Finding, GateResult
from gates.base import BaseGate


LICENSE_RISK: Dict[str, Tuple[str, float]] = {
    # Critical – strong copyleft, forces open-sourcing
    "AGPL-3.0": ("critical", 9.5),
    "AGPL-3.0-or-later": ("critical", 9.5),
    # High – copyleft
    "GPL-2.0": ("high", 7.5),
    "GPL-3.0": ("high", 7.5),
    "GPL-3.0-or-later": ("high", 7.5),
    "UNLICENSED": ("high", 7.5),
    # Medium – weak copyleft / partial restrictions
    "LGPL-2.1": ("medium", 5.0),
    "LGPL-3.0": ("medium", 5.0),
    "MPL-2.0": ("medium", 5.0),
    "EUPL-1.2": ("medium", 5.0),
    # Low – permissive
    "MIT": ("low", 2.0),
    "Apache-2.0": ("low", 2.0),
    "BSD-2-Clause": ("low", 2.0),
    "BSD-3-Clause": ("low", 2.0),
    "ISC": ("low", 2.0),
    "PSF": ("low", 2.0),
    "HPND": ("low", 2.0),
    "0BSD": ("low", 2.0),
    "Artistic-2.0": ("low", 2.0),
    "Zlib": ("low", 2.0),
    "PostgreSQL": ("low", 2.0),
    # Info – public-domain equivalent
    "Unlicense": ("info", 0.5),
    "CC0-1.0": ("info", 0.5),
}

# Mapping used when the normalised license string is not directly in
# LICENSE_RISK.  Keys are lower-cased, stripped forms.
_LICENSE_ALIASES: Dict[str, str] = {
    "mit license": "MIT",
    "mit": "MIT",
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "bsd-2": "BSD-2-Clause",
    "bsd 2 clause": "BSD-2-Clause",
    "simplified bsd": "BSD-2-Clause",
    "freebsd": "BSD-2-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd 3 clause": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "bsd": "BSD-3-Clause",
    "isc license": "ISC",
    "isc": "ISC",
    "python software foundation": "PSF",
    "psf license": "PSF",
    "psf-2.0": "PSF",
    "hpnd": "HPND",
    "historical permission notice and disclaimer": "HPND",
    "gpl-2": "GPL-2.0",
    "gnu gpl v2": "GPL-2.0",
    "gnu general public license v2": "GPL-2.0",
    "gnu general public license v2 (or later)": "GPL-2.0",
    "gpl-3": "GPL-3.0",
    "gnu gpl v3": "GPL-3.0",
    "gnu general public license v3": "GPL-3.0",
    "gnu general public license v3 (or later)": "GPL-3.0-or-later",
    "agpl-3": "AGPL-3.0",
    "gnu agpl v3": "AGPL-3.0",
    "gnu affero general public license v3": "AGPL-3.0",
    "gnu affero general public license v3 (or later)": "AGPL-3.0-or-later",
    "lgpl-2": "LGPL-2.1",
    "gnu lgpl v2.1": "LGPL-2.1",
    "gnu lesser general public license v2.1": "LGPL-2.1",
    "lgpl-3": "LGPL-3.0",
    "gnu lgpl v3": "LGPL-3.0",
    "gnu lesser general public license v3": "LGPL-3.0",
    "mozilla public license 2.0": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "eupl 1.2": "EUPL-1.2",
    "european union public licence 1.2": "EUPL-1.2",
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "cc0": "CC0-1.0",
    "cc0-1.0": "CC0-1.0",
    "creative commons zero v1.0 universal": "CC0-1.0",
    "unlicensed": "UNLICENSED",
    "proprietary": "UNLICENSED",
    "commercial": "UNLICENSED",
    "0bsd": "0BSD",
    "artistic-2": "Artistic-2.0",
    "artistic license 2.0": "Artistic-2.0",
    "zlib license": "Zlib",
    "postgresql license": "PostgreSQL",
}


PACKAGE_LICENSE_DB: Dict[str, str] = {
    # Python stdlib
    "python-stdlib": "PSF",
    # Common Python packages
    "requests": "Apache-2.0",
    "urllib3": "MIT",
    "chardet": "LGPL-2.1",
    "idna": "BSD-3-Clause",
    "certifi": "MPL-2.0",
    "flask": "BSD-3-Clause",
    "django": "BSD-3-Clause",
    "pillow": "HPND",
    "pyyaml": "MIT",
    "yaml": "MIT",
    "numpy": "BSD-3-Clause",
    "pandas": "BSD-3-Clause",
    "sqlalchemy": "MIT",
    "celery": "BSD-3-Clause",
    "redis": "MIT",
    "jinja2": "BSD-3-Clause",
    "markupsafe": "BSD-3-Clause",
    "click": "BSD-3-Clause",
    "itsdangerous": "BSD-3-Clause",
    "werkzeug": "BSD-3-Clause",
    "wtforms": "BSD-3-Clause",
    "flask-sqlalchemy": "BSD-3-Clause",
    "flask-login": "MIT",
    "flask-wtf": "BSD-3-Clause",
    "flask-cors": "MIT",
    "flask-restful": "BSD-3-Clause",
    "flask-migrate": "MIT",
    "flask-caching": "BSD-3-Clause",
    "flask-jwt-extended": "MIT",
    "pytest": "MIT",
    "sphinx": "MIT",
    "tox": "MIT",
    "virtualenv": "MIT",
    "pip": "MIT",
    "setuptools": "MIT",
    "wheel": "MIT",
    "black": "MIT",
    "isort": "MIT",
    "flake8": "MIT",
    "pylint": "GPL-2.0",
    "mypy": "MIT",
    "coverage": "Apache-2.0",
    "pytest-cov": "MIT",
    "pytest-mock": "MIT",
    "pytest-asyncio": "Apache-2.0",
    "httpx": "BSD-3-Clause",
    "aiohttp": "Apache-2.0",
    "fastapi": "MIT",
    "uvicorn": "BSD-3-Clause",
    "starlette": "BSD-3-Clause",
    "pydantic": "MIT",
    "gunicorn": "MIT",
    "scikit-learn": "BSD-3-Clause",
    "scipy": "BSD-3-Clause",
    "matplotlib": "PSF",
    "seaborn": "BSD-3-Clause",
    "plotly": "MIT",
    "boto3": "Apache-2.0",
    "botocore": "Apache-2.0",
    "google-api-python-client": "Apache-2.0",
    "google-cloud-storage": "Apache-2.0",
    "azure-storage-blob": "MIT",
    "psycopg2": "LGPL-3.0",
    "psycopg2-binary": "LGPL-3.0",
    "pymysql": "MIT",
    "mysql-connector-python": "GPL-2.0",
    "agithub": "AGPL-3.0",
    "cryptography": "Apache-2.0",
    "pyopenssl": "Apache-2.0",
    "paramiko": "LGPL-2.1",
    "fabric": "BSD-3-Clause",
    "ansible": "GPL-3.0",
    "docker": "Apache-2.0",
    "kubernetes": "Apache-2.0",
    "helm": "Apache-2.0",
    "tornado": "Apache-2.0",
    "twisted": "MIT",
    "scrapy": "BSD-3-Clause",
    "beautifulsoup4": "MIT",
    "lxml": "BSD-3-Clause",
    "selenium": "Apache-2.0",
    "playwright": "Apache-2.0",
    "requests-oauthlib": "ISC",
    "authlib": "BSD-3-Clause",
    "python-dateutil": "BSD-3-Clause",
    "pytz": "MIT",
    "six": "MIT",
    "tenacity": "Apache-2.0",
    "python-dotenv": "BSD-3-Clause",
    "marshmallow": "MIT",
    "alembic": "MIT",
    "structlog": "Apache-2.0",
    "celery-redbeat": "Apache-2.0",
    "django-rest-framework": "BSD-3-Clause",
    "djangorestframework": "BSD-3-Clause",
    # Node.js packages (common)
    "express": "MIT",
    "react": "MIT",
    "react-dom": "MIT",
    "vue": "MIT",
    "angular": "MIT",
    "next": "MIT",
    "typescript": "Apache-2.0",
    "webpack": "MIT",
    "babel": "MIT",
    "eslint": "MIT",
    "prettier": "MIT",
    "jest": "MIT",
    "mocha": "MIT",
    "lodash": "MIT",
    "axios": "MIT",
    "underscore": "MIT",
    "moment": "MIT",
    "dayjs": "MIT",
    "date-fns": "MIT",
    "uuid": "MIT",
    "chalk": "MIT",
    "commander": "MIT",
    "yargs": "MIT",
    "inquirer": "MIT",
    "dotenv": "BSD-2-Clause",
    "cors": "MIT",
    "helmet": "MIT",
    "mongoose": "Apache-2.0",
    "prisma": "Apache-2.0",
    "sequelize": "MIT",
    "knex": "MIT",
    "jsonwebtoken": "MIT",
    "passport": "MIT",
    "socket.io": "MIT",
    "ws": "MIT",
    "electron": "MIT",
    "tailwindcss": "MIT",
    "postcss": "MIT",
    "sass": "MIT",
    "less": "Apache-2.0",
    "styled-components": "MIT",
    "emotion": "MIT",
    "antd": "MIT",
    "material-ui": "MIT",
    "@mui/material": "MIT",
    "bootstrap": "MIT",
    "jquery": "MIT",
    "d3": "ISC",
    "three": "MIT",
    "chart.js": "MIT",
    "ramda": "MIT",
    "immutable": "MIT",
    "zod": "MIT",
    "joi": "BSD-3-Clause",
    "ajv": "MIT",
    "nodemon": "MIT",
    "concurrently": "MIT",
    "cross-env": "MIT",
    "rimraf": "ISC",
    "glob": "ISC",
    "fs-extra": "MIT",
    "semver": "ISC",
    "debug": "MIT",
    "winston": "MIT",
    "pino": "MIT",
    "bunyan": "MIT",
    "morgan": "MIT",
    "roarr": "MIT",
}


COPLYTELT_ALTERNATIVES: Dict[str, List[Tuple[str, str]]] = {
    "AGPL-3.0": [
        ("Use a client-server architecture that avoids AGPL propagation", ""),
        ("Consider a permissive-licensed alternative library", ""),
    ],
    "AGPL-3.0-or-later": [
        ("Use a client-server architecture that avoids AGPL propagation", ""),
        ("Consider a permissive-licensed alternative library", ""),
    ],
    "GPL-2.0": [
        ("mysql-connector-python → pymysql (MIT)", "pip install pymysql"),
        ("pylint → flake8 (MIT) or ruff (MIT)", "pip install flake8"),
    ],
    "GPL-3.0": [
        ("ansible → saltstack (Apache-2.0)", "pip install salt"),
    ],
    "LGPL-2.1": [
        ("paramiko → asyncssh (EPL-2.0 / LGPL-2.1 – evaluate)", "pip install asyncssh"),
    ],
    "LGPL-3.0": [
        ("psycopg2 → pg8000 (BSD-3-Clause)", "pip install pg8000"),
    ],
    "UNLICENSED": [
        ("Replace with an open-source alternative with a permissive license", ""),
        ("Obtain a commercial license from the vendor", ""),
    ],
}


class LicenseGate(BaseGate):
    """Checks dependency license compliance."""


    @property
    def name(self) -> str:
        return "license"

    @property
    def description(self) -> str:
        return "Checks dependency license compliance"


    def get_severity_map(self) -> Dict[str, str]:
        return {
            "license-copyleft-critical": "critical",
            "license-copyleft-high": "high",
            "license-weak-copyleft": "medium",
            "license-unknown": "medium",
            "license-unlicensed": "high",
            "license-permissive": "low",
            "license-public-domain": "info",
        }


    def run(self, repo_path: str) -> GateResult:
        try:
            return self._run_inner(repo_path)
        except Exception as exc:
            self.logger.error("License gate failed: %s", exc, exc_info=True)
            return GateResult(
                gate_name=self._gate_name,
                status="error",
                metadata={"error": str(exc)},
            )

    def _run_inner(self, repo_path: str) -> GateResult:
        root = Path(repo_path).resolve()
        findings: List[Finding] = []
        files_scanned = 0
        license_inventory: Dict[str, List[str]] = {}  # license → [packages]

        req_files = sorted(root.rglob("requirements.txt"))
        # Also check for requirements/*.txt
        req_files.extend(sorted(root.rglob("requirements/*.txt")))

        for req_file in req_files:
            rel_path = str(req_file.relative_to(root)).replace("\\", "/")
            self.logger.info("Scanning %s", rel_path)
            content = self._read_file(str(req_file))
            if content is None:
                continue
            files_scanned += 1
            deps = self._parse_requirements_txt(content)
            for dep_name, line_no in deps:
                lic, norm_lic = self._resolve_license(dep_name)
                self._record_package(
                    dep_name, lic, norm_lic, rel_path, line_no,
                    findings, license_inventory,
                )

        pkg_files = sorted(root.rglob("package.json"))
        for pkg_file in pkg_files:
            rel_path = str(pkg_file.relative_to(root)).replace("\\", "/")
            self.logger.info("Scanning %s", rel_path)
            content = self._read_file(str(pkg_file))
            if content is None:
                continue
            files_scanned += 1
            deps = self._parse_package_json(content)
            for dep_name, line_no in deps:
                lic, norm_lic = self._resolve_license(dep_name)
                self._record_package(
                    dep_name, lic, norm_lic, rel_path, line_no,
                    findings, license_inventory,
                )

        # Build metadata
        metadata: Dict[str, Any] = {
            "license_inventory": license_inventory,
            "total_packages": sum(len(v) for v in license_inventory.values()),
            "unique_licenses": list(license_inventory.keys()),
        }

        return self._build_gate_result(
            findings=findings,
            files_scanned=files_scanned,
            metadata=metadata,
        )


    @staticmethod
    def _parse_requirements_txt(content: str) -> List[Tuple[str, int]]:
        deps: List[Tuple[str, int]] = []
        for line_no, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            # Skip comments and blank lines
            if not line or line.startswith("#"):
                continue
            # Skip pip options
            if line.startswith("-") or line.startswith("--"):
                continue
            # Strip environment markers (e.g., ;python_version>="3.6")
            line = line.split(";")[0].strip()
            # Strip extras (e.g., package[extra1,extra2])
            line = re.sub(r"\[.*?\]", "", line)
            # Extract package name (up to version specifier)
            match = re.match(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)", line)
            if match:
                pkg_name = match.group(1).lower().replace("-", "-").replace("_", "-")
                deps.append((pkg_name, line_no))
        return deps

    @staticmethod
    def _parse_package_json(content: str) -> List[Tuple[str, int]]:
        deps: List[Tuple[str, int]] = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return deps

        dep_sections = [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ]

        for section in dep_sections:
            section_data = data.get(section, {})
            if not isinstance(section_data, dict):
                continue
            for pkg_name in section_data:
                # Normalise: strip @scope/ prefix for lookup
                normalised = pkg_name.lower()
                # Try to find approximate line number
                line_no = 0
                for i, line in enumerate(content.splitlines(), start=1):
                    if f'"{pkg_name}"' in line:
                        line_no = i
                        break
                deps.append((normalised, line_no))

        return deps


    def _resolve_license(self, package_name: str) -> Tuple[str, str]:
        # Strip @scope/ for scoped npm packages
        lookup_name = package_name
        if lookup_name.startswith("@"):
            lookup_name = lookup_name.split("/")[-1]

        raw_lic = PACKAGE_LICENSE_DB.get(lookup_name, "Unknown")
        norm_lic = self._normalize_license(raw_lic)
        return raw_lic, norm_lic

    @staticmethod
    def _normalize_license(raw: str) -> str:
        if not raw:
            return "Unknown"

        stripped = raw.strip()

        # Handle compound licenses: "MIT OR Apache-2.0" → pick least restrictive
        if " OR " in stripped:
            parts = [p.strip().strip("()") for p in stripped.split(" OR ")]
            # Normalise each part and pick the one with the lowest risk
            best = parts[0]
            best_score = LicenseGate._license_risk_rank(parts[0])
            for part in parts[1:]:
                score = LicenseGate._license_risk_rank(part)
                if score < best_score:
                    best = part
                    best_score = score
            return LicenseGate._normalize_license(best)

        # Handle AND: both apply → pick the most restrictive
        if " AND " in stripped:
            parts = [p.strip().strip("()") for p in stripped.split(" AND ")]
            worst = parts[0]
            worst_score = LicenseGate._license_risk_rank(parts[0])
            for part in parts[1:]:
                score = LicenseGate._license_risk_rank(part)
                if score > worst_score:
                    worst = part
                    worst_score = score
            return LicenseGate._normalize_license(worst)

        # Strip surrounding parentheses
        cleaned = stripped.strip("()")

        # Direct lookup
        if cleaned in LICENSE_RISK:
            return cleaned

        # Alias lookup (case-insensitive)
        lower = cleaned.lower().strip()
        if lower in _LICENSE_ALIASES:
            return _LICENSE_ALIASES[lower]

        # Try title-case match in LICENSE_RISK keys
        for key in LICENSE_RISK:
            if key.lower() == lower:
                return key

        return "Unknown"

    @staticmethod
    def _license_risk_rank(license_str: str) -> int:
        norm = LicenseGate._normalize_license(license_str)
        risk_info = LICENSE_RISK.get(norm)
        if risk_info is None:
            return 3  # Unknown → treat as medium
        severity, _ = risk_info
        rank_map = {"info": 0, "low": 1, "medium": 2, "high": 4, "critical": 5}
        return rank_map.get(severity, 3)


    def _record_package(
        self,
        package_name: str,
        raw_license: str,
        norm_license: str,
        file_path: str,
        line_no: int,
        findings: List[Finding],
        inventory: Dict[str, List[str]],
    ) -> None:
        # Update inventory
        inventory.setdefault(norm_license, []).append(package_name)

        risk_info = LICENSE_RISK.get(norm_license)
        if risk_info is None:
            # Unknown license
            severity, cvss = "medium", 5.0
            rule_id = "license-unknown"
            message = (
                f"Package '{package_name}' has an unknown license. "
                f"Manual review required."
            )
            fix = (
                f"Check the license for '{package_name}' manually. "
                f"If it is permissive, add it to your allow-list."
            )
        else:
            severity, cvss = risk_info
            if severity in ("critical", "high") and norm_license.startswith(("AGPL", "GPL")):
                rule_id = f"license-copyleft-{'critical' if severity == 'critical' else 'high'}"
            elif severity == "high" and norm_license == "UNLICENSED":
                rule_id = "license-unlicensed"
            elif severity == "medium":
                rule_id = "license-weak-copyleft"
            elif severity == "low":
                rule_id = "license-permissive"
            elif severity == "info":
                rule_id = "license-public-domain"
            else:
                rule_id = "license-unknown"

            message = (
                f"Package '{package_name}' is licensed under {norm_license} "
                f"(risk: {severity})."
            )

            # Build remediation
            fix = self._build_remediation(package_name, norm_license, severity)

        # Only create findings for non-permissive / non-info licenses
        # (Permissive "low" and "info" are acceptable — we record them
        # in the inventory but do not create findings to avoid noise.)
        if severity in ("critical", "high", "medium"):
            findings.append(
                self._create_finding(
                    file=file_path,
                    line=line_no,
                    message=message,
                    severity=severity,
                    cvss_score=cvss,
                    rule_id=rule_id,
                    cwe_id="CWE-1104",  # Use of Unmaintained Third Party Components
                    fix_suggestion=fix,
                    finding_type="compliance",
                    confidence="high" if norm_license != "Unknown" else "low",
                )
            )

    @staticmethod
    def _build_remediation(
        package_name: str,
        norm_license: str,
        severity: str,
    ) -> str:
        parts: List[str] = []

        alternatives = COPLYTELT_ALTERNATIVES.get(norm_license, [])
        if alternatives:
            for alt_desc, install_cmd in alternatives:
                parts.append(alt_desc)
                if install_cmd:
                    parts.append(f"  Install: {install_cmd}")
        elif severity == "medium":
            parts.append(
                f"Review the terms of {norm_license} to ensure compliance "
                f"with your project's licensing policy."
            )
        elif norm_license == "Unknown":
            parts.append(
                f"Manually verify the license for '{package_name}'. "
                f"Consider replacing it with a package that has a clear "
                f"permissive license."
            )

        if norm_license.startswith(("AGPL", "GPL")):
            parts.append(
                "WARNING: Copyleft licenses may require you to release "
                "your entire codebase under the same license. Consult "
                "your legal team before proceeding."
            )

        if not parts:
            parts.append(
                "Review the license to ensure it aligns with your "
                "project's licensing policy."
            )

        return " ".join(parts)
