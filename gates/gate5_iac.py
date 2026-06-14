"""SecureBuild CI/CD Security Gate - Infrastructure-as-Code Security (Gate 5)"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from engine.config import SecureBuildConfig
from engine.logger import get_logger
from engine.models import Finding, GateResult
from gates.base import BaseGate
from gates.iac_discovery import discover_iac_files

# Conditional YAML import — the gate degrades gracefully without it
try:
    import yaml  # type: ignore

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


# CIS Benchmark mapping

CIS_DOCKER_MAP: Dict[str, str] = {
    "docker-root-user": "CIS Docker 4.1 - Ensure a USER instruction is set",
    "docker-latest-tag": "CIS Docker 4.6 - Ensure COPY is used instead of ADD",
    "docker-add-instead-copy": "CIS Docker 4.6 - Ensure COPY is used instead of ADD",
    "docker-missing-healthcheck": "CIS Docker 4.9 - Ensure HEALTHCHECK is defined",
    "docker-apt-upgrade": "CIS Docker 4.3 - Ensure packages are pinned",
    "docker-expose-ssh": "CIS Docker 4.5 - Ensure no insecure ports are exposed",
    "docker-secret-arg": "CIS Docker 4.10 - Ensure secrets are not passed as ARGs",
    "docker-unchained-run": "CIS Docker 4.8 - Ensure RUN commands are minimised",
    "docker-apt-no-install-recommends": "CIS Docker 4.3 - Ensure apt-get install uses --no-install-recommends",
    "docker-sudo": "CIS Docker 4.1 - Ensure a USER instruction is set (no sudo)",
    "docker-privileged": "CIS Docker 5.3 - Ensure privileged ports are not mapped",
    "docker-host-network": "CIS Docker 5.5 - Ensure host network is not used",
    "docker-socket-mount": "CIS Docker 5.8 - Ensure Docker socket is not mounted",
    "docker-no-resource-limits": "CIS Docker 5.10 - Ensure resource limits are set",
    "docker-hardcoded-env-secret": "CIS Docker 5.12 - Ensure sensitive data is not in env vars",
}


class IACGate(BaseGate):
    """Scans Infrastructure-as-Code files for security issues."""


    @property
    def name(self) -> str:
        return "iac"

    @property
    def description(self) -> str:
        return "Scans Infrastructure-as-Code files for security issues"


    def get_severity_map(self) -> Dict[str, str]:
        return {
            "docker-root-user": "critical",
            "docker-latest-tag": "medium",
            "docker-add-instead-copy": "medium",
            "docker-missing-healthcheck": "low",
            "docker-apt-upgrade": "low",
            "docker-expose-ssh": "high",
            "docker-secret-arg": "critical",
            "docker-unchained-run": "info",
            "docker-apt-no-install-recommends": "low",
            "docker-sudo": "high",
            "docker-privileged": "critical",
            "docker-host-network": "high",
            "docker-socket-mount": "critical",
            "docker-no-resource-limits": "medium",
            "docker-hardcoded-env-secret": "high",
            "k8s-run-as-root": "high",
            "k8s-missing-readonly-rootfs": "medium",
            "k8s-missing-resource-limits": "medium",
            "k8s-host-pid": "high",
            "k8s-host-network": "high",
            "k8s-image-latest": "medium",
            "gha-pull-request-target-checkout": "high",
            "gha-hardcoded-secret": "critical",
            "gha-unpinned-action": "medium",
        }


    def run(self, repo_path: str) -> GateResult:
        try:
            return self._run_inner(repo_path)
        except Exception as exc:
            self.logger.error("IaC gate failed: %s", exc, exc_info=True)
            return GateResult(
                gate_name=self._gate_name,
                status="error",
                metadata={"error": str(exc)},
            )

    def _run_inner(self, repo_path: str) -> GateResult:
        root = Path(repo_path).resolve()
        findings: List[Finding] = []
        files_scanned = 0

        # Discover IaC files
        iac_files = discover_iac_files(repo_path)
        self.logger.info(
            "IaC files discovered: %d dockerfiles, %d compose, %d k8s, "
            "%d workflows, %d terraform",
            len(iac_files["dockerfiles"]),
            len(iac_files["compose_files"]),
            len(iac_files["k8s_manifests"]),
            len(iac_files["github_workflows"]),
            len(iac_files["terraform"]),
        )

        for rel_path in iac_files["dockerfiles"]:
            abs_path = root / rel_path
            content = self._read_file(str(abs_path))
            if content is None:
                continue
            files_scanned += 1
            findings.extend(self._scan_dockerfile(content, rel_path))

        if _YAML_AVAILABLE:
            for rel_path in iac_files["compose_files"]:
                abs_path = root / rel_path
                content = self._read_file(str(abs_path))
                if content is None:
                    continue
                files_scanned += 1
                findings.extend(self._scan_compose(content, rel_path))
        else:
            self.logger.warning(
                "PyYAML not installed; skipping docker-compose scan"
            )

        if _YAML_AVAILABLE:
            for rel_path in iac_files["k8s_manifests"]:
                abs_path = root / rel_path
                content = self._read_file(str(abs_path))
                if content is None:
                    continue
                files_scanned += 1
                findings.extend(self._scan_k8s(content, rel_path))
        else:
            self.logger.warning(
                "PyYAML not installed; skipping Kubernetes manifest scan"
            )

        if _YAML_AVAILABLE:
            for rel_path in iac_files["github_workflows"]:
                abs_path = root / rel_path
                content = self._read_file(str(abs_path))
                if content is None:
                    continue
                files_scanned += 1
                findings.extend(self._scan_github_workflow(content, rel_path))
        else:
            self.logger.warning(
                "PyYAML not installed; skipping GitHub Actions scan"
            )

        # Build metadata
        metadata: Dict[str, Any] = {
            "iac_files": iac_files,
            "yaml_available": _YAML_AVAILABLE,
        }

        return self._build_gate_result(
            findings=findings,
            files_scanned=files_scanned,
            metadata=metadata,
        )

    # Dockerfile Scanner

    def _scan_dockerfile(
        self, content: str, file_path: str
    ) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        has_user = False
        run_count = 0
        has_healthcheck = False

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            upper = line.upper()

            # Skip comments
            if line.startswith("#"):
                continue

            # Track USER instruction
            if upper.startswith("USER "):
                has_user = True

            # Track HEALTHCHECK
            if upper.startswith("HEALTHCHECK "):
                has_healthcheck = True

            # FROM with :latest tag
            if upper.startswith("FROM "):
                # Extract image reference
                from_parts = line.split()
                if len(from_parts) >= 2:
                    image_ref = from_parts[1]
                    if image_ref.endswith(":latest") or (
                        ":" not in image_ref.split("@")[0]
                        and not image_ref.startswith("scratch")
                    ):
                        # If there's no tag at all and it's not scratch, that's implicitly latest
                        if image_ref.endswith(":latest"):
                            findings.append(
                                self._make_docker_finding(
                                    file_path, line_no,
                                    "docker-latest-tag",
                                    "FROM instruction uses ':latest' tag which leads to "
                                    "non-reproducible builds.",
                                    5.5,
                                    "Pin the image version: FROM python:3.12-slim "
                                    "instead of FROM python:latest",
                                )
                            )

            # ADD instead of COPY
            if upper.startswith("ADD "):
                findings.append(
                    self._make_docker_finding(
                        file_path, line_no,
                        "docker-add-instead-copy",
                        "ADD instruction used instead of COPY. ADD can fetch "
                        "remote URLs and extract archives, which may introduce "
                        "unexpected behaviour.",
                        5.0,
                        "Replace ADD with COPY unless you need the extra features "
                        "of ADD:\n  COPY . /app  # instead of ADD . /app",
                    )
                )

            # EXPOSE port 22 (SSH)
            if upper.startswith("EXPOSE "):
                expose_parts = line.split()
                for port_spec in expose_parts[1:]:
                    port_num = port_spec.split("/")[0]
                    if port_num == "22":
                        findings.append(
                            self._make_docker_finding(
                                file_path, line_no,
                                "docker-expose-ssh",
                                "SSH port (22) exposed in Dockerfile. Running SSH "
                                "inside containers is an anti-pattern and increases "
                                "attack surface.",
                                7.5,
                                "Remove EXPOSE 22. Use 'docker exec' or 'docker "
                                "attach' for debugging instead of SSH.",
                            )
                        )

            # Secrets as ARG
            if upper.startswith("ARG "):
                arg_line = line[4:].strip()
                # Check for common secret-related ARG names
                secret_patterns = [
                    r"(?i)(password|passwd|secret|token|key|api.?key|access.?key|"
                    r"private.?key|auth|credential)",
                ]
                for pattern in secret_patterns:
                    if re.search(pattern, arg_line):
                        findings.append(
                            self._make_docker_finding(
                                file_path, line_no,
                                "docker-secret-arg",
                                f"Secret-like value passed as ARG: '{arg_line}'. "
                                f"Build args are visible in 'docker history' and "
                                f"can leak secrets.",
                                9.1,
                                "Use Docker secrets or build-time secret mounts "
                                "instead:\n  RUN --mount=type=secret,id=mysecret "
                                "cat /run/secrets/mysecret",
                            )
                        )
                        break

            # apt-get upgrade
            if re.search(r"apt-get\s+upgrade", line):
                findings.append(
                    self._make_docker_finding(
                        file_path, line_no,
                        "docker-apt-upgrade",
                        "apt-get upgrade used in Dockerfile. This makes builds "
                        "non-reproducible as packages may change between builds.",
                        2.5,
                        "Pin package versions instead:\n  RUN apt-get update && "
                        "apt-get install -y package=1.2.3",
                    )
                )

            if re.search(r"apt-get\s+install", line) and \
               "--no-install-recommends" not in line:
                findings.append(
                    self._make_docker_finding(
                        file_path, line_no,
                        "docker-apt-no-install-recommends",
                        "apt-get install without --no-install-recommends. This "
                        "installs unnecessary recommended packages, increasing "
                        "image size and attack surface.",
                        2.0,
                        "Add --no-install-recommends:\n  RUN apt-get update && "
                        "apt-get install -y --no-install-recommends package",
                    )
                )

            # Using sudo
            if re.search(r"\bsudo\b", line):
                findings.append(
                    self._make_docker_finding(
                        file_path, line_no,
                        "docker-sudo",
                        "sudo used in Dockerfile. This may indicate running as "
                        "root when a non-root USER should be set instead.",
                        7.0,
                        "Set a non-root USER and remove sudo:\n  USER appuser",
                    )
                )

            # Count RUN instructions (for unchained check)
            if upper.startswith("RUN "):
                run_count += 1

        # After iterating all lines — structural checks

        # Running as root (no USER instruction)
        if not has_user:
            findings.append(
                self._make_docker_finding(
                    file_path, 0,
                    "docker-root-user",
                    "No USER instruction found. Container will run as root by "
                    "default, increasing the impact of container escape "
                    "vulnerabilities.",
                    9.8,
                    "Add a non-root USER instruction:\n  RUN adduser --disabled-password appuser\n"
                    "  USER appuser",
                )
            )

        # Missing HEALTHCHECK
        if not has_healthcheck:
            findings.append(
                self._make_docker_finding(
                    file_path, 0,
                    "docker-missing-healthcheck",
                    "No HEALTHCHECK instruction found. Without a health check, "
                    "the orchestrator cannot determine if the container is "
                    "functioning correctly.",
                    3.0,
                    "Add a HEALTHCHECK instruction:\n  HEALTHCHECK --interval=30s "
                    "CMD curl -f http://localhost:8080/health || exit 1",
                )
            )

        # Un-chained RUN commands (informational)
        if run_count > 3:
            findings.append(
                self._make_docker_finding(
                    file_path, 0,
                    "docker-unchained-run",
                    f"{run_count} separate RUN instructions found. Each RUN "
                    f"creates a new layer, increasing image size. Consider "
                    f"chaining commands with && .",
                    1.0,
                    "Chain RUN commands to reduce layers:\n  RUN apt-get update "
                    "&& apt-get install -y package && rm -rf /var/lib/apt/lists/*",
                )
            )

        return findings

    def _make_docker_finding(
        self,
        file_path: str,
        line_no: int,
        rule_id: str,
        message: str,
        cvss_score: float,
        fix_suggestion: str,
    ) -> Finding:
        severity_map = self.get_severity_map()
        severity = severity_map.get(rule_id, "medium")
        cis_ref = CIS_DOCKER_MAP.get(rule_id, "")

        full_message = message
        if cis_ref:
            full_message += f" [{cis_ref}]"

        return self._create_finding(
            file=file_path,
            line=line_no,
            message=full_message,
            severity=severity,
            cvss_score=cvss_score,
            rule_id=rule_id,
            cwe_id="CWE-1032",  # Security Configuration
            fix_suggestion=fix_suggestion,
            finding_type="misconfiguration",
            confidence="high",
        )

    # docker-compose Scanner

    def _scan_compose(
        self, content: str, file_path: str
    ) -> List[Finding]:
        findings: List[Finding] = []

        if not _YAML_AVAILABLE:
            self.logger.warning(
                "PyYAML not available; cannot parse %s", file_path
            )
            return findings

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            self.logger.warning("Failed to parse %s: %s", file_path, exc)
            return findings

        if not isinstance(data, dict):
            return findings

        services = data.get("services", {})
        if not isinstance(services, dict):
            return findings

        for svc_name, svc_config in services.items():
            if not isinstance(svc_config, dict):
                continue

            # privileged: true
            if svc_config.get("privileged") is True:
                findings.append(
                    self._make_compose_finding(
                        file_path, 0,
                        "docker-privileged",
                        f"Service '{svc_name}' has privileged: true. This "
                        f"grants the container almost all host capabilities.",
                        9.8,
                        "Remove privileged: true and add only the specific "
                        "capabilities needed:\n  cap_add:\n    - SYS_PTRACE",
                    )
                )

            # network_mode: host
            if svc_config.get("network_mode") == "host":
                findings.append(
                    self._make_compose_finding(
                        file_path, 0,
                        "docker-host-network",
                        f"Service '{svc_name}' uses network_mode: host. This "
                        f"removes network isolation between the container and "
                        f"the host.",
                        7.5,
                        "Use port mapping instead:\n  ports:\n    - '8080:80'",
                    )
                )

            # Docker socket mount
            volumes = svc_config.get("volumes", [])
            if isinstance(volumes, list):
                for vol in volumes:
                    vol_str = str(vol)
                    if "/var/run/docker.sock" in vol_str:
                        findings.append(
                            self._make_compose_finding(
                                file_path, 0,
                                "docker-socket-mount",
                                f"Service '{svc_name}' mounts the Docker socket. "
                                f"This grants full control over the Docker daemon.",
                                9.5,
                                "Remove the Docker socket mount. If needed, use "
                                "a secure alternative like Docker socket proxy.",
                            )
                        )
                        break  # One finding per service

            # Missing resource limits
            deploy = svc_config.get("deploy", {})
            if not isinstance(deploy, dict):
                deploy = {}
            resources = deploy.get("resources", {})
            has_limits = (
                isinstance(resources, dict)
                and ("limits" in resources or "reservations" in resources)
            )
            if not has_limits:
                # Also check for mem_limit / cpus (compose v2 syntax)
                if "mem_limit" not in svc_config and "cpus" not in svc_config:
                    findings.append(
                        self._make_compose_finding(
                            file_path, 0,
                            "docker-no-resource-limits",
                            f"Service '{svc_name}' has no resource limits. "
                            f"Unlimited containers can consume all host "
                            f"resources, causing DoS.",
                            5.5,
                            "Add resource limits:\n  deploy:\n    resources:\n"
                            "      limits:\n        cpus: '0.50'\n        "
                            "memory: 512M",
                        )
                    )

            # Hardcoded environment secrets
            environment = svc_config.get("environment", {})
            if isinstance(environment, dict):
                self._check_env_secrets(
                    environment, svc_name, file_path, findings
                )
            elif isinstance(environment, list):
                for env_item in environment:
                    if isinstance(env_item, str) and "=" in env_item:
                        key, _, value = env_item.partition("=")
                        env_dict = {key.strip(): value.strip()}
                        self._check_env_secrets(
                            env_dict, svc_name, file_path, findings
                        )

        return findings

    def _check_env_secrets(
        self,
        env_dict: Dict[str, Any],
        svc_name: str,
        file_path: str,
        findings: List[Finding],
    ) -> None:
        secret_key_patterns = [
            r"(?i)^(password|passwd|secret|token|api.?key|access.?key|"
            r"private.?key|auth|credential|database_url)$",
        ]

        for key, value in env_dict.items():
            if not isinstance(value, str) or not value:
                continue
            # Skip obviously-non-secret values (empty, placeholders)
            if value in ("${", "${}", "changeme", "TODO", ""):
                continue
            for pattern in secret_key_patterns:
                if re.search(pattern, key):
                    # Check if the value looks like a real secret
                    # (not a variable reference like ${VAR})
                    if not value.startswith("${") and not value.startswith("$("):
                        findings.append(
                            self._make_compose_finding(
                                file_path, 0,
                                "docker-hardcoded-env-secret",
                                f"Service '{svc_name}' has a hardcoded secret in "
                                f"environment variable '{key}'. Secrets in "
                                f"compose files can be committed to version "
                                f"control.",
                                8.0,
                                f"Use Docker secrets or environment variable "
                                f"references:\n  {key}: ${{{key.upper()}}}\n"
                                f"  # Pass via .env file or CI/CD secrets",
                            )
                        )
                    break

    def _make_compose_finding(
        self,
        file_path: str,
        line_no: int,
        rule_id: str,
        message: str,
        cvss_score: float,
        fix_suggestion: str,
    ) -> Finding:
        severity_map = self.get_severity_map()
        severity = severity_map.get(rule_id, "medium")
        cis_ref = CIS_DOCKER_MAP.get(rule_id, "")

        full_message = message
        if cis_ref:
            full_message += f" [{cis_ref}]"

        return self._create_finding(
            file=file_path,
            line=line_no,
            message=full_message,
            severity=severity,
            cvss_score=cvss_score,
            rule_id=rule_id,
            cwe_id="CWE-1032",
            fix_suggestion=fix_suggestion,
            finding_type="misconfiguration",
            confidence="high",
        )

    # Kubernetes Manifest Scanner

    def _scan_k8s(
        self, content: str, file_path: str
    ) -> List[Finding]:
        findings: List[Finding] = []

        if not _YAML_AVAILABLE:
            return findings

        # A single YAML file may contain multiple documents
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError as exc:
            self.logger.warning("Failed to parse %s: %s", file_path, exc)
            return findings

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            # Walk all containers in the document
            containers = self._extract_k8s_containers(doc)
            for container in containers:
                self._check_k8s_container(
                    container, file_path, findings
                )

            # Check pod-level security context
            self._check_k8s_pod_security(doc, file_path, findings)

        return findings

    @staticmethod
    def _extract_k8s_containers(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
        containers: List[Dict[str, Any]] = []

        # Try spec.template.spec first (Deployment, etc.)
        spec = doc.get("spec", {})
        template_spec = {}
        if isinstance(spec, dict):
            template = spec.get("template", {})
            if isinstance(template, dict):
                template_spec = template.get("spec", {})

        # Also check top-level spec (Pod, etc.)
        for src in (spec, template_spec):
            if not isinstance(src, dict):
                continue
            for key in ("containers", "initContainers"):
                c_list = src.get(key, [])
                if isinstance(c_list, list):
                    for c in c_list:
                        if isinstance(c, dict):
                            containers.append(c)

        return containers

    def _check_k8s_container(
        self,
        container: Dict[str, Any],
        file_path: str,
        findings: List[Finding],
    ) -> None:
        container_name = container.get("name", "unnamed")

        # runAsUser: 0
        security_ctx = container.get("securityContext", {})
        if isinstance(security_ctx, dict):
            if security_ctx.get("runAsUser") == 0:
                findings.append(
                    self._create_finding(
                        file=file_path,
                        line=0,
                        message=f"Container '{container_name}' runs as root "
                        f"(runAsUser: 0). This increases the impact of "
                        f"container escape vulnerabilities.",
                        severity="high",
                        cvss_score=8.0,
                        rule_id="k8s-run-as-root",
                        cwe_id="CWE-250",
                        fix_suggestion="Set runAsUser to a non-zero UID:\n"
                        "  securityContext:\n    runAsUser: 1000",
                        finding_type="misconfiguration",
                        confidence="high",
                    )
                )

            # Missing readOnlyRootFilesystem
            if not security_ctx.get("readOnlyRootFilesystem"):
                findings.append(
                    self._create_finding(
                        file=file_path,
                        line=0,
                        message=f"Container '{container_name}' does not set "
                        f"readOnlyRootFilesystem. A writable root filesystem "
                        f"allows attackers to modify the filesystem.",
                        severity="medium",
                        cvss_score=5.0,
                        rule_id="k8s-missing-readonly-rootfs",
                        cwe_id="CWE-1032",
                        fix_suggestion="Add readOnlyRootFilesystem:\n"
                        "  securityContext:\n    readOnlyRootFilesystem: true",
                        finding_type="misconfiguration",
                        confidence="high",
                    )
                )

        # Missing resource limits
        resources = container.get("resources", {})
        if not isinstance(resources, dict) or "limits" not in resources:
            findings.append(
                self._create_finding(
                    file=file_path,
                    line=0,
                    message=f"Container '{container_name}' has no resource "
                    f"limits. Unbounded containers can cause resource "
                    f"exhaustion and DoS.",
                    severity="medium",
                    cvss_score=5.5,
                    rule_id="k8s-missing-resource-limits",
                    cwe_id="CWE-770",
                    fix_suggestion="Add resource limits:\n"
                    "  resources:\n    limits:\n      cpu: '500m'\n"
                    "      memory: '512Mi'",
                    finding_type="misconfiguration",
                    confidence="high",
                )
            )

        # image using :latest
        image = container.get("image", "")
        if isinstance(image, str):
            if image.endswith(":latest") or (
                ":" not in image and "@" not in image and image
            ):
                findings.append(
                    self._create_finding(
                        file=file_path,
                        line=0,
                        message=f"Container '{container_name}' uses ':latest' "
                        f"image tag '{image}'. This leads to non-reproducible "
                        f"deployments.",
                        severity="medium",
                        cvss_score=5.5,
                        rule_id="k8s-image-latest",
                        cwe_id="CWE-1032",
                        fix_suggestion="Pin the image version:\n"
                        f"  image: {image.split(':')[0].split('@')[0]}:1.2.3",
                        finding_type="misconfiguration",
                        confidence="high",
                    )
                )

    def _check_k8s_pod_security(
        self,
        doc: Dict[str, Any],
        file_path: str,
        findings: List[Finding],
    ) -> None:
        # Navigate to pod spec
        spec = doc.get("spec", {})
        if isinstance(spec, dict):
            template = spec.get("template", {})
            if isinstance(template, dict):
                pod_spec = template.get("spec", {})
            else:
                pod_spec = spec
        else:
            return

        if not isinstance(pod_spec, dict):
            return

        # hostPID: true
        if pod_spec.get("hostPID") is True:
            findings.append(
                self._create_finding(
                    file=file_path,
                    line=0,
                    message="Pod uses hostPID: true. This allows the pod to "
                    "see all processes on the host, breaking process isolation.",
                    severity="high",
                    cvss_score=7.5,
                    rule_id="k8s-host-pid",
                    cwe_id="CWE-250",
                    fix_suggestion="Remove hostPID: true from the pod spec.",
                    finding_type="misconfiguration",
                    confidence="high",
                )
            )

        # hostNetwork: true
        if pod_spec.get("hostNetwork") is True:
            findings.append(
                self._create_finding(
                    file=file_path,
                    line=0,
                    message="Pod uses hostNetwork: true. This removes network "
                    "isolation between the pod and the host.",
                    severity="high",
                    cvss_score=7.5,
                    rule_id="k8s-host-network",
                    cwe_id="CWE-1032",
                    fix_suggestion="Remove hostNetwork: true and use "
                    "containerPort + service instead.",
                    finding_type="misconfiguration",
                    confidence="high",
                )
            )

    # GitHub Actions Workflow Scanner

    def _scan_github_workflow(
        self, content: str, file_path: str
    ) -> List[Finding]:
        findings: List[Finding] = []

        if not _YAML_AVAILABLE:
            return findings

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            self.logger.warning("Failed to parse %s: %s", file_path, exc)
            return findings

        if not isinstance(data, dict):
            return findings

        # Check triggers
        on_spec = data.get("on", data.get(True, {}))  # YAML parses 'on' as True
        has_pull_request_target = False
        if isinstance(on_spec, dict):
            if "pull_request_target" in on_spec:
                has_pull_request_target = True
        elif isinstance(on_spec, list):
            if "pull_request_target" in on_spec:
                has_pull_request_target = True

        # Check jobs
        jobs = data.get("jobs", {})
        if not isinstance(jobs, dict):
            return findings

        for job_name, job_config in jobs.items():
            if not isinstance(job_config, dict):
                continue

            if has_pull_request_target:
                steps = job_config.get("steps", [])
                if isinstance(steps, list):
                    for step in steps:
                        if not isinstance(step, dict):
                            continue
                        uses = step.get("uses", "")
                        if isinstance(uses, str) and "actions/checkout" in uses:
                            findings.append(
                                self._create_finding(
                                    file=file_path,
                                    line=0,
                                    message=f"Job '{job_name}' uses "
                                    f"pull_request_target with actions/checkout. "
                                    f"This can allow attackers to steal secrets "
                                    f"via malicious PRs.",
                                    severity="high",
                                    cvss_score=8.0,
                                    rule_id="gha-pull-request-target-checkout",
                                    cwe_id="CWE-863",
                                    fix_suggestion="Avoid checking out the PR "
                                    "code on pull_request_target. If you must, "
                                    "use:\n  uses: actions/checkout@v4\n"
                                    "  ref: ${{ github.event.pull_request.head.sha }}",
                                    finding_type="misconfiguration",
                                    confidence="high",
                                )
                            )
                            break  # One finding per job

            # Check job-level env
            job_env = job_config.get("env", {})
            if isinstance(job_env, dict):
                self._check_gha_env(
                    job_env, job_name, file_path, findings
                )

            # Check step-level env
            steps = job_config.get("steps", [])
            if isinstance(steps, list):
                for step in steps:
                    if not isinstance(step, dict):
                        continue
                    step_env = step.get("env", {})
                    if isinstance(step_env, dict):
                        self._check_gha_env(
                            step_env, job_name, file_path, findings
                        )

                    uses = step.get("uses", "")
                    if isinstance(uses, str) and uses:
                        # Check if using @main / @master / @v1 (not a SHA)
                        if "@" in uses:
                            _, _, ref = uses.partition("@")
                            # A SHA is 40 hex chars (or 7+ short SHA)
                            if not re.match(r"^[0-9a-f]{7,40}$", ref):
                                # It's a branch/tag, not a SHA
                                if ref in ("main", "master") or \
                                   re.match(r"^v\d+$", ref):
                                    findings.append(
                                        self._create_finding(
                                            file=file_path,
                                            line=0,
                                            message=f"Action '{uses}' uses an "
                                            f"unpinned version reference '@{ref}'. "
                                            f"This is vulnerable to tag mutation "
                                            f"attacks.",
                                            severity="medium",
                                            cvss_score=6.0,
                                            rule_id="gha-unpinned-action",
                                            cwe_id="CWE-829",
                                            fix_suggestion="Pin actions to a "
                                            "full commit SHA:\n"
                                            f"  uses: {uses.split('@')[0]}"
                                            "@a12b3c4d5e6f..."
                                            "  # Replace with actual SHA",
                                            finding_type="misconfiguration",
                                            confidence="medium",
                                        )
                                    )

        return findings

    def _check_gha_env(
        self,
        env_dict: Dict[str, Any],
        job_name: str,
        file_path: str,
        findings: List[Finding],
    ) -> None:
        secret_key_patterns = [
            r"(?i)^(password|passwd|secret|token|api.?key|access.?key|"
            r"private.?key|auth|credential|database_url|db_password)$",
        ]

        for key, value in env_dict.items():
            if not isinstance(value, str) or not value:
                continue
            # Skip GitHub Actions expressions and secrets references
            if value.startswith("${{") and value.endswith("}}"):
                # If it references secrets.*, it's fine
                if "secrets." in value:
                    continue
            # Skip variable references
            if value.startswith("${{") or value.startswith("$("):
                continue
            # Skip short / placeholder values
            if len(value) < 6:
                continue

            for pattern in secret_key_patterns:
                if re.search(pattern, key):
                    findings.append(
                        self._create_finding(
                            file=file_path,
                            line=0,
                            message=f"Job '{job_name}' has a hardcoded secret "
                            f"in env variable '{key}'. Secrets should be "
                            f"referenced via GitHub Secrets, not committed.",
                            severity="critical",
                            cvss_score=9.0,
                            rule_id="gha-hardcoded-secret",
                            cwe_id="CWE-798",
                            fix_suggestion=f"Replace with a GitHub Secret "
                            f"reference:\n  {key}: ${{{{ secrets.{key.upper()} }}}}",
                            finding_type="secret",
                            confidence="high",
                        )
                    )
                    break
