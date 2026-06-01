"""SecureBuild CI/CD Security Gate - Custom Exceptions"""


class GateExecutionError(Exception):
    """Raised when a security gate fails during execution."""

    def __init__(
        self,
        gate_name: str,
        message: str = "",
        original_error: Exception | None = None,
        details: dict | None = None,
    ) -> None:
        self.gate_name = gate_name
        self.original_error = original_error
        self.details = details or {}
        if not message and original_error:
            message = str(original_error)
        full_message = f"Gate '{gate_name}' execution failed: {message}"
        super().__init__(full_message)


class APITimeoutError(Exception):
    """Raised when an external API call exceeds the allowed timeout."""

    def __init__(
        self,
        service: str,
        timeout_seconds: float = 0.0,
        message: str = "",
    ) -> None:
        self.service = service
        self.timeout_seconds = timeout_seconds
        if not message:
            message = (
                f"API call to '{service}' timed out after "
                f"{timeout_seconds:.1f} seconds"
            )
        super().__init__(message)


class InvalidRepoError(Exception):
    """Raised when the provided repository path is invalid or inaccessible."""

    def __init__(self, repo_path: str, reason: str = "") -> None:
        self.repo_path = repo_path
        self.reason = reason
        message = f"Invalid repository at '{repo_path}'"
        if reason:
            message += f": {reason}"
        super().__init__(message)


class ScoringError(Exception):
    """Raised when the risk scoring engine encounters an error."""

    def __init__(
        self,
        metric: str = "",
        message: str = "",
        original_error: Exception | None = None,
    ) -> None:
        self.metric = metric
        self.original_error = original_error
        if not message and original_error:
            message = str(original_error)
        full_message = "Scoring error"
        if metric:
            full_message += f" in metric '{metric}'"
        if message:
            full_message += f": {message}"
        super().__init__(full_message)


class ConfigValidationError(Exception):
    """Raised when the configuration file contains invalid or missing values."""

    def __init__(
        self,
        field: str = "",
        value: object = None,
        constraint: str = "",
        message: str = "",
    ) -> None:
        self.field = field
        self.value = value
        self.constraint = constraint
        if not message:
            parts = ["Configuration validation failed"]
            if field:
                parts.append(f"for field '{field}'")
            if value is not None:
                parts.append(f"(got: {value!r})")
            if constraint:
                parts.append(f"- {constraint}")
            message = " ".join(parts)
        super().__init__(message)


class ReportGenerationError(Exception):
    """Raised when report generation fails for a completed run."""

    def __init__(
        self,
        report_type: str = "",
        run_id: str = "",
        message: str = "",
        original_error: Exception | None = None,
    ) -> None:
        self.report_type = report_type
        self.run_id = run_id
        self.original_error = original_error
        if not message and original_error:
            message = str(original_error)
        full_message = "Report generation failed"
        if report_type:
            full_message += f" for '{report_type}' report"
        if run_id:
            full_message += f" (run_id={run_id})"
        if message:
            full_message += f": {message}"
        super().__init__(full_message)
