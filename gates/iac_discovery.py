"""SecureBuild CI/CD Security Gate - IaC File Discovery"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

from engine.logger import get_logger

logger = get_logger("iac_discovery")


# Dockerfile: Dockerfile, Dockerfile.*, */Dockerfile, */Dockerfile.*
_DOCKERFILE_RE = re.compile(
    r"(^|/)Dockerfile(\.[\w.-]+)?$", re.IGNORECASE
)

# docker-compose: docker-compose.yml, docker-compose.yaml, compose.yml, compose.yaml
_COMPOSE_RE = re.compile(
    r"(^|/)(docker-)?compose\.(yml|yaml)$", re.IGNORECASE
)

# Terraform: *.tf, *.tf.json
_TERRAFORM_RE = re.compile(r"\.tf(\.json)?$", re.IGNORECASE)

# GitHub Actions workflows: .github/workflows/*.yml / *.yaml
_GITHUB_WORKFLOW_RE = re.compile(
    r"^\.github[/\\]workflows[/\\].+\.(yml|yaml)$", re.IGNORECASE
)

# Kubernetes manifests: files under k8s/, kubernetes/, kube/, manifests/,
# deploy/, deployment/ with .yml / .yaml / .json extensions
_K8S_DIR_RE = re.compile(
    r"(^|/)(k8s|kubernetes|kube|manifests|deploy|deployment)s?[/\\]",
    re.IGNORECASE,
)
_K8S_EXT_RE = re.compile(r"\.(yml|yaml|json)$", re.IGNORECASE)


def discover_iac_files(repo_path: str) -> Dict[str, List[str]]:
    root = Path(repo_path).resolve()

    categories: Dict[str, List[str]] = {
        "dockerfiles": [],
        "compose_files": [],
        "k8s_manifests": [],
        "github_workflows": [],
        "terraform": [],
    }

    if not root.is_dir():
        logger.warning("Repository path does not exist or is not a directory: %s", repo_path)
        return categories

    for filepath in root.rglob("*"):
        if not filepath.is_file():
            continue

        try:
            relative = filepath.relative_to(root)
        except ValueError:
            continue

        rel_str = str(relative).replace("\\", "/")

        # Skip hidden directories (except .github which is legitimate)
        parts = rel_str.split("/")
        if any(p.startswith(".") and p != ".github" for p in parts):
            continue

        # Skip common non-source directories
        skip_dirs = {"node_modules", "vendor", "__pycache__", ".tox", "dist", "build"}
        if skip_dirs.intersection(parts):
            continue

        if _DOCKERFILE_RE.search(rel_str):
            categories["dockerfiles"].append(rel_str)

        if _COMPOSE_RE.search(rel_str):
            categories["compose_files"].append(rel_str)

        if _GITHUB_WORKFLOW_RE.search(rel_str):
            categories["github_workflows"].append(rel_str)

        if _TERRAFORM_RE.search(rel_str):
            categories["terraform"].append(rel_str)

        # Kubernetes: must be in a k8s-like directory AND have a
        # manifest-like extension (yaml / json)
        if _K8S_DIR_RE.search(rel_str) and _K8S_EXT_RE.search(rel_str):
            categories["k8s_manifests"].append(rel_str)

    # Sort each list for deterministic output
    for key in categories:
        categories[key].sort()

    # Log summary
    logger.info(
        "IaC discovery complete – dockerfiles=%d, compose=%d, k8s=%d, "
        "workflows=%d, terraform=%d",
        len(categories["dockerfiles"]),
        len(categories["compose_files"]),
        len(categories["k8s_manifests"]),
        len(categories["github_workflows"]),
        len(categories["terraform"]),
    )

    return categories
