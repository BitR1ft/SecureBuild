"""SecureBuild CI/CD Security Gate - Parallel Gate Runner"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from typing import Dict, List, Optional, Type

from engine.config import SecureBuildConfig
from engine.exceptions import GateExecutionError
from engine.logger import get_logger
from engine.models import GateResult
from gates.base import BaseGate

logger = get_logger("runner")


class GateRunner:
    """Runs security gates in parallel with timeout and error handling."""

    def __init__(
        self,
        config: SecureBuildConfig,
        gate_classes: Optional[Dict[str, Type[BaseGate]]] = None,
    ) -> None:
        self.config = config
        self.gate_classes: Dict[str, Type[BaseGate]] = gate_classes or {}

    def register_gate(self, name: str, gate_class: Type[BaseGate]) -> None:
        self.gate_classes[name] = gate_class
        logger.info("Registered gate: %s", name)

    def _execute_gate(
        self, gate_name: str, gate_class: Type[BaseGate], repo_path: str
    ) -> GateResult:
        start_time = time.monotonic()
        try:
            gate_instance = gate_class(config=self.config)
            logger.info(
                "Starting gate: %s",
                gate_name,
                extra={"gate": gate_name},
            )
            result = gate_instance.run(repo_path)
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            result.duration_ms = elapsed_ms
            logger.info(
                "Gate %s completed: status=%s, findings=%d, duration=%dms",
                gate_name,
                result.status,
                result.findings_count,
                elapsed_ms,
                extra={"gate": gate_name},
            )
            return result

        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            logger.error(
                "Gate %s failed with error: %s",
                gate_name,
                str(exc),
                extra={"gate": gate_name},
            )
            return GateResult(
                gate_name=gate_name,
                status="error",
                findings=[],
                duration_ms=elapsed_ms,
                metadata={"error": str(exc), "error_type": type(exc).__name__},
            )

    def run_all(self, repo_path: str) -> List[GateResult]:
        # Determine which gates to run
        enabled_gates = {
            name: cls
            for name, cls in self.gate_classes.items()
            if self.config.is_gate_enabled(name)
        }

        if not enabled_gates:
            logger.warning("No enabled gates to run")
            return []

        max_workers = min(self.config.max_workers, len(enabled_gates))
        timeout_seconds = self.config.gate_timeout_seconds

        logger.info(
            "Running %d gates with %d workers (timeout=%ds)",
            len(enabled_gates),
            max_workers,
            timeout_seconds,
        )

        results: List[GateResult] = []
        futures = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all gates
            for gate_name, gate_class in enabled_gates.items():
                future = executor.submit(
                    self._execute_gate, gate_name, gate_class, repo_path
                )
                futures[future] = gate_name

            # Collect results as they complete, with timeout
            for future in as_completed(futures, timeout=timeout_seconds + 30):
                gate_name = futures[future]
                try:
                    # Each future's inner function handles its own timeout,
                    # but we also set a safety margin here
                    result = future.result(timeout=timeout_seconds)
                    results.append(result)
                except TimeoutError:
                    logger.error(
                        "Gate %s timed out after %ds",
                        gate_name,
                        timeout_seconds,
                        extra={"gate": gate_name},
                    )
                    results.append(
                        GateResult(
                            gate_name=gate_name,
                            status="error",
                            findings=[],
                            duration_ms=timeout_seconds * 1000,
                            metadata={
                                "error": f"Timeout after {timeout_seconds}s",
                                "error_type": "TimeoutError",
                            },
                        )
                    )
                except Exception as exc:
                    logger.error(
                        "Gate %s raised unexpected error: %s",
                        gate_name,
                        str(exc),
                        extra={"gate": gate_name},
                    )
                    results.append(
                        GateResult(
                            gate_name=gate_name,
                            status="error",
                            findings=[],
                            metadata={
                                "error": str(exc),
                                "error_type": type(exc).__name__,
                            },
                        )
                    )

        # Log summary
        passed = sum(1 for r in results if r.status == "pass")
        failed = sum(1 for r in results if r.status == "fail")
        errored = sum(1 for r in results if r.status == "error")
        total_findings = sum(r.findings_count for r in results)

        logger.info(
            "All gates complete: %d passed, %d failed, %d errored, %d total findings",
            passed,
            failed,
            errored,
            total_findings,
        )

        return results

    def run_single(self, gate_name: str, repo_path: str) -> GateResult:
        if gate_name not in self.gate_classes:
            raise GateExecutionError(
                gate_name=gate_name,
                message=f"Gate '{gate_name}' is not registered",
            )

        gate_class = self.gate_classes[gate_name]
        return self._execute_gate(gate_name, gate_class, repo_path)


def run_gates_parallel(
    repo_path: str,
    config: SecureBuildConfig,
    gate_classes: Optional[Dict[str, Type[BaseGate]]] = None,
) -> List[GateResult]:
    runner = GateRunner(config=config, gate_classes=gate_classes)
    return runner.run_all(repo_path)
