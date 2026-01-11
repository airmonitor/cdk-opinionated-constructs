"""
Security audit tests using pip-audit to detect known vulnerabilities.

This module provides functional, composable security audit utilities using pip-audit
against installed packages. Refactored for Python 3.13+ with functional programming
principles, high cohesion, and low coupling.

Current Date: 2026-01-11 (Europe/Warsaw)
"""

from __future__ import annotations

import json
import subprocess  # noqa: S404  # nosec B404
import sys

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum, auto
from pathlib import Path
from typing import Final, NoReturn, Self

import pytest


class AuditStatus(StrEnum):
    """Enumeration of possible audit result statuses."""

    SUCCESS = auto()
    VULNERABILITIES_FOUND = auto()
    PARSE_ERROR = auto()
    TIMEOUT = auto()
    NOT_INSTALLED = auto()
    EXECUTION_ERROR = auto()


@dataclass(frozen=True, slots=True)
class AuditConfig:
    """Immutable configuration for pip-audit execution.

    Attributes:
        ignored_vulns: Sequence of CVE IDs to ignore during audit.
        timeout_seconds: Maximum execution time in seconds.
        output_format: Output format for pip-audit (json recommended).
        disable_spinner: Whether to disable progress spinner.
    """

    ignored_vulns: tuple[str, ...] = ("CVE-2025-53000",)
    timeout_seconds: int = 120
    output_format: str = "json"
    disable_spinner: bool = True

    def to_args(self) -> list[str]:
        """Convert configuration to pip-audit command-line arguments.

        Returns:
            List of command-line arguments for pip-audit.
        """
        args: list[str] = [
            f"--format={self.output_format}",
        ]
        if self.disable_spinner:
            args.append("--progress-spinner=off")
        args.extend(f"--ignore-vuln={vuln}" for vuln in self.ignored_vulns)
        return args


@dataclass(frozen=True, slots=True)
class VulnerablePackage:
    """Immutable representation of a vulnerable package.

    Attributes:
        name: Package name.
        version: Installed version.
        vulnerabilities: Tuple of vulnerability identifiers.
    """

    name: str
    version: str
    vulnerabilities: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: dict) -> Self | None:
        """Create VulnerablePackage from pip-audit JSON dict.

        Args:
            data: Dictionary containing package vulnerability data.

        Returns:
            VulnerablePackage instance if vulnerabilities exist, None otherwise.
        """
        if not (vulns := data.get("vulns")):
            return None
        return cls(
            name=data.get("name", "unknown"),
            version=data.get("version", "unknown"),
            vulnerabilities=tuple(v.get("id", "unknown") for v in vulns),
        )


@dataclass(frozen=True, slots=True)
class AuditResult:
    """Immutable result of a pip-audit execution.

    Attributes:
        status: The audit status.
        vulnerable_packages: Tuple of vulnerable packages found.
        raw_output: Raw stdout from pip-audit.
        error_output: Raw stderr from pip-audit.
        return_code: Process return code.
    """

    status: AuditStatus
    vulnerable_packages: tuple[VulnerablePackage, ...] = field(default_factory=tuple)
    raw_output: str = ""
    error_output: str = ""
    return_code: int = 0

    @property
    def is_success(self) -> bool:
        """Check if audit completed without vulnerabilities."""
        return self.status == AuditStatus.SUCCESS

    @property
    def vulnerability_count(self) -> int:
        """Get total number of vulnerable packages."""
        return len(self.vulnerable_packages)

    def format_vulnerabilities(self) -> str:
        """Format vulnerable packages as JSON string.

        Returns:
            JSON-formatted string of vulnerable packages.
        """
        if not self.vulnerable_packages:
            return "[]"
        packages_data = [
            {
                "name": pkg.name,
                "version": pkg.version,
                "vulns": list(pkg.vulnerabilities),
            }
            for pkg in self.vulnerable_packages
        ]
        return json.dumps(packages_data, indent=2)


# =============================================================================
# Pure Functions for Audit Execution
# =============================================================================


def build_audit_command(
    python_executable: str,
    config: AuditConfig,
) -> list[str]:
    """Build the pip-audit command with all arguments.

    Pure function that constructs command arguments.

    Args:
        python_executable: Path to Python interpreter.
        config: Audit configuration.

    Returns:
        Complete command as list of strings.
    """
    return [python_executable, "-m", "pip_audit", *config.to_args()]


def parse_audit_output(stdout: str) -> tuple[VulnerablePackage, ...]:
    """Parse pip-audit JSON output into VulnerablePackage instances.

    Pure function for parsing audit results.

    Args:
        stdout: Raw JSON output from pip-audit.

    Returns:
        Tuple of VulnerablePackage instances.

    Raises:
        json.JSONDecodeError: If stdout is not valid JSON.
    """
    audit_data: dict = json.loads(stdout)
    dependencies: list[dict] = audit_data.get("dependencies", [])

    # Use generator expression with filter for efficiency
    return tuple(pkg for dep in dependencies if (pkg := VulnerablePackage.from_dict(dep)) is not None)


def classify_audit_result(
    return_code: int,
    stdout: str,
    stderr: str,
) -> AuditResult:
    """Classify subprocess result into typed AuditResult.

    Pure function using pattern matching for clean control flow.

    Args:
        return_code: Process return code.
        stdout: Standard output.
        stderr: Standard error.

    Returns:
        Classified AuditResult with appropriate status.
    """
    combined_output: str = f"{stdout}\n{stderr}".lower()

    match return_code:
        case 0:
            return AuditResult(
                status=AuditStatus.SUCCESS,
                raw_output=stdout,
                error_output=stderr,
                return_code=return_code,
            )
        case _ if "vulnerabilities found" in combined_output or '"dependencies"' in stdout:
            # Attempt to parse vulnerabilities
            try:
                vulnerable_packages = parse_audit_output(stdout)
                status = AuditStatus.VULNERABILITIES_FOUND if vulnerable_packages else AuditStatus.SUCCESS
                return AuditResult(
                    status=status,
                    vulnerable_packages=vulnerable_packages,
                    raw_output=stdout,
                    error_output=stderr,
                    return_code=return_code,
                )
            except json.JSONDecodeError:
                return AuditResult(
                    status=AuditStatus.PARSE_ERROR,
                    raw_output=stdout,
                    error_output=stderr,
                    return_code=return_code,
                )
        case _:
            return AuditResult(
                status=AuditStatus.EXECUTION_ERROR,
                raw_output=stdout,
                error_output=stderr,
                return_code=return_code,
            )


def execute_subprocess(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: int = 120,
) -> AuditResult:
    """Execute subprocess and return typed result.

    Handles all subprocess exceptions and converts to AuditResult.

    Args:
        command: Command and arguments to execute.
        cwd: Working directory for subprocess.
        timeout: Timeout in seconds.

    Returns:
        AuditResult with appropriate status.
    """
    try:
        result = subprocess.run(  # noqa: S603  # nosec S603 B603
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,  # We handle return codes manually
        )
        return classify_audit_result(
            result.returncode,
            result.stdout,
            result.stderr,
        )
    except subprocess.TimeoutExpired:
        return AuditResult(
            status=AuditStatus.TIMEOUT,
            error_output=f"Command timed out after {timeout} seconds",
        )
    except FileNotFoundError:
        return AuditResult(
            status=AuditStatus.NOT_INSTALLED,
            error_output="pip-audit not installed or not accessible",
        )


# =============================================================================
# Higher-Order Functions for Test Composition
# =============================================================================


def create_failure_message(result: AuditResult, config: AuditConfig) -> str:
    """Create formatted failure message based on audit result.

    Pure function for message generation.

    Args:
        result: The audit result.
        config: The audit configuration used.

    Returns:
        Formatted failure message string.
    """
    ignored_vulns_args: str = " ".join(f"--ignore-vuln {v}" for v in config.ignored_vulns)
    manual_command: Final[str] = f"./venv/bin/python -m pip_audit {ignored_vulns_args} --skip-editable"

    match result.status:
        case AuditStatus.VULNERABILITIES_FOUND:
            return (
                f"pip-audit detected {result.vulnerability_count} vulnerable package(s)!\n\n"
                f"Vulnerable packages:\n{result.format_vulnerabilities()}\n\n"
                f"Please review and update vulnerable packages.\n"
                f"Run manually with: {manual_command}"
            )
        case AuditStatus.PARSE_ERROR:
            return (
                f"pip-audit detected security vulnerabilities!\n\n"
                f"Output:\n{result.raw_output}\n\n"
                f"Please review and update vulnerable packages.\n"
                f"Run manually with: {manual_command}"
            )
        case AuditStatus.TIMEOUT:
            return f"pip-audit command timed out after {config.timeout_seconds} seconds"
        case AuditStatus.NOT_INSTALLED:
            return "pip-audit not installed or not accessible"
        case AuditStatus.EXECUTION_ERROR:
            combined: str = f"{result.raw_output}\n{result.error_output}".strip()
            return f"pip-audit failed to run properly:\n\nReturn code: {result.return_code}\nOutput: {combined}\n"
        case _:
            return f"Unexpected audit status: {result.status}"


def run_audit(
    config: AuditConfig,
    project_root: Path,
) -> AuditResult:
    """Execute pip-audit with given configuration.

    Composed function that builds command and executes audit.

    Args:
        config: Audit configuration.
        project_root: Project root directory.

    Returns:
        AuditResult from the audit execution.
    """
    command: list[str] = build_audit_command(sys.executable, config)
    return execute_subprocess(command, cwd=project_root, timeout=config.timeout_seconds)


def handle_audit_result(
    result: AuditResult,
    config: AuditConfig,
    fail_handler: Callable[[str], NoReturn],
) -> None:
    """Handle audit result, calling fail_handler if not successful.

    Higher-order function for flexible failure handling.

    Args:
        result: The audit result to handle.
        config: The audit configuration used.
        fail_handler: Function to call on failure (e.g., pytest.fail).
    """
    if not result.is_success:
        fail_handler(create_failure_message(result, config))


def check_pip_audit_version() -> AuditResult:
    """Check if pip-audit is installed and functional.

    Pure function for version verification.

    Returns:
        AuditResult indicating installation status.
    """
    result = execute_subprocess(
        [sys.executable, "-m", "pip_audit", "--version"],
        timeout=10,
    )

    # Additional validation for version output
    if result.status == AuditStatus.SUCCESS and "pip-audit" not in result.raw_output.lower():
        return AuditResult(
            status=AuditStatus.EXECUTION_ERROR,
            raw_output=result.raw_output,
            error_output="pip-audit version output unexpected",
            return_code=result.return_code,
        )
    return result


# =============================================================================
# Default Configuration (Module-Level Constant)
# =============================================================================

DEFAULT_CONFIG: Final[AuditConfig] = AuditConfig()


# =============================================================================
# Pytest Test Functions
# =============================================================================


def test_pip_audit_no_vulnerabilities() -> None:
    """
    Run pip-audit to check for known security vulnerabilities.

    This test will fail if any vulnerabilities are detected in the installed packages.

    Note: CVE-2025-53000 (nbconvert Windows vulnerability) is ignored as it only affects
    Windows platforms and is a known acceptable risk for this project.

    To run this test specifically:
        pytest pip_audit_checker.py::test_pip_audit_no_vulnerabilities -v
    """
    project_root: Path = Path(__file__).parent.parent.parent
    result: AuditResult = run_audit(DEFAULT_CONFIG, project_root)

    # Use partial application for cleaner handler injection
    handle_audit_result(result, DEFAULT_CONFIG, pytest.fail)

    # Explicit success verification
    if not result.is_success:
        pytest.fail("pip-audit should return success when no vulnerabilities are found")


def test_pip_audit_runs_successfully() -> None:
    """
    Verify that pip-audit can run successfully (even if vulnerabilities are found).

    This is a smoke test to ensure pip-audit is properly installed and functional.
    """
    result: AuditResult = check_pip_audit_version()

    match result.status:
        case AuditStatus.SUCCESS:
            pass  # pip-audit is installed and functional
        case AuditStatus.NOT_INSTALLED:
            pytest.fail("pip-audit not installed")
        case AuditStatus.TIMEOUT:
            pytest.fail("pip-audit --version timed out")
        case _:
            pytest.fail(f"pip-audit --version failed: {result.error_output}")


# =============================================================================
# CLI Entry Point
# =============================================================================


def main() -> None:
    """Command-line entry point for manual execution."""
    print("Using pip-audit to find vulnerable packages")
    print(f"Configuration: {DEFAULT_CONFIG}")

    project_root: Path = Path(__file__).parent.parent.parent
    result: AuditResult = run_audit(DEFAULT_CONFIG, project_root)

    match result.status:
        case AuditStatus.SUCCESS:
            print("✓ No vulnerabilities found")
        case AuditStatus.VULNERABILITIES_FOUND:
            print(f"✗ Found {result.vulnerability_count} vulnerable package(s):")
            print(result.format_vulnerabilities())
            sys.exit(1)
        case _:
            print(f"✗ Audit failed: {create_failure_message(result, DEFAULT_CONFIG)}")
            sys.exit(1)

    # Version check
    version_result: AuditResult = check_pip_audit_version()
    if version_result.is_success:
        print(f"✓ pip-audit version: {version_result.raw_output.strip()}")
    else:
        print("✗ pip-audit version check failed")
        sys.exit(1)

    print("pip-audit finished successfully")


if __name__ == "__main__":
    main()
