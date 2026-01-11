"""Unit tests for pip_audit_checker module.

Tests cover all dataclasses, pure functions, and higher-order functions
for the pip-audit security audit functionality.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - subprocess used for type hints/mocking only
import sys

from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, create_autospec

import pytest

# Add the source directory to path to avoid the aws_cdk import from utils/__init__.py
sys.path.insert(
    0, str(Path(__file__).parent.parent.parent / "cdk_opinionated_constructs" / "utils" / "pip_audit_files")
)

from pip_audit_checker import (
    AuditConfig,
    AuditResult,
    AuditStatus,
    VulnerablePackage,
    build_audit_command,
    check_pip_audit_version,
    classify_audit_result,
    create_failure_message,
    execute_subprocess,
    handle_audit_result,
    parse_audit_output,
    run_audit,
)

# =============================================================================
# Tests for AuditStatus Enum
# =============================================================================


def test_audit_status_has_all_expected_values():
    """Test AuditStatus enum contains all expected values."""
    expected_statuses = {
        "SUCCESS",
        "VULNERABILITIES_FOUND",
        "PARSE_ERROR",
        "TIMEOUT",
        "NOT_INSTALLED",
        "EXECUTION_ERROR",
    }
    actual_statuses = {status.name for status in AuditStatus}
    assert actual_statuses == expected_statuses


def test_audit_status_is_string_enum():
    """Test AuditStatus is a string enum with correct values."""
    assert isinstance(AuditStatus.SUCCESS, str)
    assert AuditStatus.SUCCESS == "success"


# =============================================================================
# Tests for AuditConfig Dataclass
# =============================================================================


def test_audit_config_default_values():
    """Test AuditConfig has correct default values."""
    config = AuditConfig()
    assert config.ignored_vulns == ("CVE-2025-53000",)
    assert config.timeout_seconds == 120
    assert config.output_format == "json"
    assert config.disable_spinner is True


def test_audit_config_custom_values():
    """Test AuditConfig with custom values."""
    config = AuditConfig(
        ignored_vulns=("CVE-2024-0001", "CVE-2024-0002"),
        timeout_seconds=60,
        output_format="columns",
        disable_spinner=False,
    )
    assert config.ignored_vulns == ("CVE-2024-0001", "CVE-2024-0002")
    assert config.timeout_seconds == 60
    assert config.output_format == "columns"
    assert config.disable_spinner is False


def test_audit_config_is_frozen():
    """Test AuditConfig is immutable."""
    config = AuditConfig()
    with pytest.raises(AttributeError):
        config.timeout_seconds = 60  # type: ignore[misc]


def test_audit_config_to_args_with_default_config():
    """Test to_args with default configuration."""
    config = AuditConfig()
    args = config.to_args()
    assert "--format=json" in args
    assert "--progress-spinner=off" in args
    assert "--ignore-vuln=CVE-2025-53000" in args


def test_audit_config_to_args_with_spinner_enabled():
    """Test to_args with spinner enabled."""
    config = AuditConfig(disable_spinner=False)
    args = config.to_args()
    assert "--progress-spinner=off" not in args


def test_audit_config_to_args_with_multiple_ignored_vulns():
    """Test to_args with multiple ignored vulnerabilities."""
    config = AuditConfig(ignored_vulns=("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"))
    args = config.to_args()
    assert "--ignore-vuln=CVE-2024-0001" in args
    assert "--ignore-vuln=CVE-2024-0002" in args
    assert "--ignore-vuln=CVE-2024-0003" in args


def test_audit_config_to_args_with_no_ignored_vulns():
    """Test to_args with no ignored vulnerabilities."""
    config = AuditConfig(ignored_vulns=())
    args = config.to_args()
    assert not any(arg.startswith("--ignore-vuln=") for arg in args)


def test_audit_config_to_args_with_different_output_format():
    """Test to_args with different output format."""
    config = AuditConfig(output_format="columns")
    args = config.to_args()
    assert "--format=columns" in args


# =============================================================================
# Tests for VulnerablePackage Dataclass
# =============================================================================


def test_vulnerable_package_creation():
    """Test VulnerablePackage creation with basic values."""
    pkg = VulnerablePackage(
        name="requests",
        version="2.25.0",
        vulnerabilities=("CVE-2024-0001", "CVE-2024-0002"),
    )
    assert pkg.name == "requests"
    assert pkg.version == "2.25.0"
    assert pkg.vulnerabilities == ("CVE-2024-0001", "CVE-2024-0002")


def test_vulnerable_package_is_frozen():
    """Test VulnerablePackage is immutable."""
    pkg = VulnerablePackage(name="test", version="1.0", vulnerabilities=())
    with pytest.raises(AttributeError):
        pkg.name = "other"  # type: ignore[misc]


def test_vulnerable_package_from_dict_with_vulnerabilities():
    """Test from_dict with vulnerabilities present."""
    data = {
        "name": "django",
        "version": "3.2.0",
        "vulns": [
            {"id": "CVE-2024-0001", "description": "XSS vulnerability"},
            {"id": "CVE-2024-0002", "description": "SQL injection"},
        ],
    }
    pkg = VulnerablePackage.from_dict(data)
    assert pkg is not None
    assert pkg.name == "django"
    assert pkg.version == "3.2.0"
    assert pkg.vulnerabilities == ("CVE-2024-0001", "CVE-2024-0002")


def test_vulnerable_package_from_dict_without_vulnerabilities_returns_none():
    """Test from_dict returns None when no vulnerabilities."""
    data = {"name": "safe-package", "version": "1.0.0", "vulns": []}
    pkg = VulnerablePackage.from_dict(data)
    assert pkg is None


def test_vulnerable_package_from_dict_missing_vulns_key_returns_none():
    """Test from_dict returns None when vulns key is missing."""
    data = {"name": "safe-package", "version": "1.0.0"}
    pkg = VulnerablePackage.from_dict(data)
    assert pkg is None


def test_vulnerable_package_from_dict_with_missing_name_uses_default():
    """Test from_dict uses default name when missing."""
    data = {"version": "1.0.0", "vulns": [{"id": "CVE-2024-0001"}]}
    pkg = VulnerablePackage.from_dict(data)
    assert pkg is not None
    assert pkg.name == "unknown"


def test_vulnerable_package_from_dict_with_missing_version_uses_default():
    """Test from_dict uses default version when missing."""
    data = {"name": "test-pkg", "vulns": [{"id": "CVE-2024-0001"}]}
    pkg = VulnerablePackage.from_dict(data)
    assert pkg is not None
    assert pkg.version == "unknown"


def test_vulnerable_package_from_dict_with_missing_vuln_id_uses_default():
    """Test from_dict uses default vuln ID when missing."""
    data = {"name": "test-pkg", "version": "1.0", "vulns": [{"description": "no id"}]}
    pkg = VulnerablePackage.from_dict(data)
    assert pkg is not None
    assert pkg.vulnerabilities == ("unknown",)


# =============================================================================
# Tests for AuditResult Dataclass
# =============================================================================


def test_audit_result_default_values():
    """Test AuditResult has correct default values."""
    result = AuditResult(status=AuditStatus.SUCCESS)
    assert result.status == AuditStatus.SUCCESS
    assert result.vulnerable_packages == ()
    assert result.raw_output == ""
    assert result.error_output == ""
    assert result.return_code == 0


def test_audit_result_with_vulnerabilities():
    """Test AuditResult with vulnerability data."""
    pkg = VulnerablePackage(name="test", version="1.0", vulnerabilities=("CVE-001",))
    result = AuditResult(
        status=AuditStatus.VULNERABILITIES_FOUND,
        vulnerable_packages=(pkg,),
        raw_output='{"dependencies": []}',
        return_code=1,
    )
    assert result.status == AuditStatus.VULNERABILITIES_FOUND
    assert len(result.vulnerable_packages) == 1
    assert result.return_code == 1


def test_audit_result_is_frozen():
    """Test AuditResult is immutable."""
    result = AuditResult(status=AuditStatus.SUCCESS)
    with pytest.raises(AttributeError):
        result.status = AuditStatus.TIMEOUT  # type: ignore[misc]


def test_audit_result_is_success_returns_true_for_success_status():
    """Test is_success returns True for SUCCESS status."""
    result = AuditResult(status=AuditStatus.SUCCESS)
    assert result.is_success is True


@pytest.mark.parametrize(
    "status",
    [
        AuditStatus.VULNERABILITIES_FOUND,
        AuditStatus.PARSE_ERROR,
        AuditStatus.TIMEOUT,
        AuditStatus.NOT_INSTALLED,
        AuditStatus.EXECUTION_ERROR,
    ],
)
def test_audit_result_is_success_returns_false_for_non_success_status(status: AuditStatus):
    """Test is_success returns False for non-SUCCESS statuses."""
    result = AuditResult(status=status)
    assert result.is_success is False


def test_audit_result_vulnerability_count_with_no_vulnerabilities():
    """Test vulnerability_count returns 0 when no vulnerabilities."""
    result = AuditResult(status=AuditStatus.SUCCESS)
    assert result.vulnerability_count == 0


def test_audit_result_vulnerability_count_with_vulnerabilities():
    """Test vulnerability_count returns correct count."""
    packages = tuple(VulnerablePackage(name=f"pkg{i}", version="1.0", vulnerabilities=("CVE-001",)) for i in range(5))
    result = AuditResult(status=AuditStatus.VULNERABILITIES_FOUND, vulnerable_packages=packages)
    assert result.vulnerability_count == 5


def test_audit_result_format_vulnerabilities_empty():
    """Test format_vulnerabilities returns empty JSON array when no vulnerabilities."""
    result = AuditResult(status=AuditStatus.SUCCESS)
    assert result.format_vulnerabilities() == "[]"


def test_audit_result_format_vulnerabilities_with_packages():
    """Test format_vulnerabilities returns correct JSON."""
    packages = (
        VulnerablePackage(name="pkg1", version="1.0", vulnerabilities=("CVE-001", "CVE-002")),
        VulnerablePackage(name="pkg2", version="2.0", vulnerabilities=("CVE-003",)),
    )
    result = AuditResult(status=AuditStatus.VULNERABILITIES_FOUND, vulnerable_packages=packages)
    formatted = result.format_vulnerabilities()
    parsed = json.loads(formatted)
    assert len(parsed) == 2
    assert parsed[0]["name"] == "pkg1"
    assert parsed[0]["version"] == "1.0"
    assert parsed[0]["vulns"] == ["CVE-001", "CVE-002"]
    assert parsed[1]["name"] == "pkg2"


# =============================================================================
# Tests for build_audit_command Function
# =============================================================================


def test_build_audit_command_basic():
    """Test build_audit_command creates correct basic command."""
    config = AuditConfig()
    cmd = build_audit_command("/usr/bin/python", config)
    assert cmd[0] == "/usr/bin/python"
    assert cmd[1] == "-m"
    assert cmd[2] == "pip_audit"
    assert "--format=json" in cmd


def test_build_audit_command_includes_all_config_args():
    """Test build_audit_command includes all config arguments."""
    config = AuditConfig(
        ignored_vulns=("CVE-001", "CVE-002"),
        output_format="json",
        disable_spinner=True,
    )
    cmd = build_audit_command("/path/to/python", config)
    assert "--ignore-vuln=CVE-001" in cmd
    assert "--ignore-vuln=CVE-002" in cmd
    assert "--progress-spinner=off" in cmd


def test_build_audit_command_without_spinner_off():
    """Test build_audit_command without spinner disabled."""
    config = AuditConfig(disable_spinner=False, ignored_vulns=())
    cmd = build_audit_command("/usr/bin/python", config)
    assert "--progress-spinner=off" not in cmd


# =============================================================================
# Tests for parse_audit_output Function
# =============================================================================


def test_parse_audit_output_with_vulnerabilities():
    """Test parse_audit_output with vulnerabilities present."""
    output = json.dumps({
        "dependencies": [
            {
                "name": "requests",
                "version": "2.25.0",
                "vulns": [{"id": "CVE-2024-0001"}, {"id": "CVE-2024-0002"}],
            },
            {"name": "safe-pkg", "version": "1.0.0", "vulns": []},
            {
                "name": "django",
                "version": "3.2.0",
                "vulns": [{"id": "CVE-2024-0003"}],
            },
        ]
    })
    packages = parse_audit_output(output)
    assert len(packages) == 2
    assert packages[0].name == "requests"
    assert packages[0].vulnerabilities == ("CVE-2024-0001", "CVE-2024-0002")
    assert packages[1].name == "django"


def test_parse_audit_output_no_vulnerabilities():
    """Test parse_audit_output with no vulnerabilities."""
    output = json.dumps({
        "dependencies": [
            {"name": "pkg1", "version": "1.0.0", "vulns": []},
            {"name": "pkg2", "version": "2.0.0", "vulns": []},
        ]
    })
    packages = parse_audit_output(output)
    assert packages == ()


def test_parse_audit_output_empty_dependencies():
    """Test parse_audit_output with empty dependencies."""
    output = json.dumps({"dependencies": []})
    packages = parse_audit_output(output)
    assert packages == ()


def test_parse_audit_output_missing_dependencies_key():
    """Test parse_audit_output with missing dependencies key."""
    output = json.dumps({"other_key": "value"})
    packages = parse_audit_output(output)
    assert packages == ()


def test_parse_audit_output_invalid_json_raises_error():
    """Test parse_audit_output raises JSONDecodeError for invalid JSON."""
    with pytest.raises(json.JSONDecodeError):
        parse_audit_output("not valid json")


def test_parse_audit_output_empty_string_raises_error():
    """Test parse_audit_output raises JSONDecodeError for empty string."""
    with pytest.raises(json.JSONDecodeError):
        parse_audit_output("")


# =============================================================================
# Tests for classify_audit_result Function
# =============================================================================


def test_classify_audit_result_success_return_code_zero():
    """Test classify_audit_result returns SUCCESS for return code 0."""
    result = classify_audit_result(0, "some output", "")
    assert result.status == AuditStatus.SUCCESS
    assert result.raw_output == "some output"
    assert result.return_code == 0


def test_classify_audit_result_vulnerabilities_found_in_output():
    """Test classify_audit_result detects vulnerabilities in output."""
    stdout = json.dumps({
        "dependencies": [
            {"name": "pkg", "version": "1.0", "vulns": [{"id": "CVE-001"}]},
        ]
    })
    result = classify_audit_result(1, stdout, "vulnerabilities found")
    assert result.status == AuditStatus.VULNERABILITIES_FOUND
    assert result.vulnerability_count == 1


def test_classify_audit_result_dependencies_key_triggers_parsing():
    """Test classify_audit_result parses when dependencies key present."""
    stdout = json.dumps({
        "dependencies": [
            {"name": "pkg", "version": "1.0", "vulns": [{"id": "CVE-001"}]},
        ]
    })
    result = classify_audit_result(1, stdout, "")
    assert result.status == AuditStatus.VULNERABILITIES_FOUND


def test_classify_audit_result_dependencies_but_no_vulns_returns_success():
    """Test classify_audit_result returns SUCCESS when no vulnerabilities."""
    stdout = json.dumps({"dependencies": [{"name": "pkg", "version": "1.0", "vulns": []}]})
    result = classify_audit_result(1, stdout, "")
    assert result.status == AuditStatus.SUCCESS


def test_classify_audit_result_parse_error_on_invalid_json():
    """Test classify_audit_result returns PARSE_ERROR for invalid JSON."""
    result = classify_audit_result(1, "not json", "vulnerabilities found")
    assert result.status == AuditStatus.PARSE_ERROR


def test_classify_audit_result_execution_error_on_unknown_failure():
    """Test classify_audit_result returns EXECUTION_ERROR for unknown failures."""
    result = classify_audit_result(2, "unknown error", "some stderr")
    assert result.status == AuditStatus.EXECUTION_ERROR
    assert result.return_code == 2


# =============================================================================
# Tests for execute_subprocess Function
# =============================================================================


@mock.patch("pip_audit_checker.subprocess.run")
def test_execute_subprocess_success(mock_run: MagicMock):
    """Test execute_subprocess returns SUCCESS on successful execution."""
    mock_result = create_autospec(subprocess.CompletedProcess, instance=True)
    mock_result.returncode = 0
    mock_result.stdout = "success output"
    mock_result.stderr = ""
    mock_run.return_value = mock_result

    result = execute_subprocess(["echo", "test"])

    assert result.status == AuditStatus.SUCCESS
    assert result.raw_output == "success output"
    mock_run.assert_called_once()


@mock.patch("pip_audit_checker.subprocess.run")
def test_execute_subprocess_with_cwd(mock_run: MagicMock):
    """Test execute_subprocess passes cwd to subprocess.run."""
    mock_result = create_autospec(subprocess.CompletedProcess, instance=True)
    mock_result.returncode = 0
    mock_result.stdout = ""
    mock_result.stderr = ""
    mock_run.return_value = mock_result

    execute_subprocess(["cmd"], cwd=Path("/some/path"))

    call_kwargs = mock_run.call_args.kwargs
    assert call_kwargs["cwd"] == Path("/some/path")


@mock.patch("pip_audit_checker.subprocess.run")
def test_execute_subprocess_timeout(mock_run: MagicMock):
    """Test execute_subprocess returns TIMEOUT on TimeoutExpired."""
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=30)

    result = execute_subprocess(["test"], timeout=30)

    assert result.status == AuditStatus.TIMEOUT
    assert "timed out after 30 seconds" in result.error_output


@mock.patch("pip_audit_checker.subprocess.run")
def test_execute_subprocess_file_not_found(mock_run: MagicMock):
    """Test execute_subprocess returns NOT_INSTALLED on FileNotFoundError."""
    mock_run.side_effect = FileNotFoundError()

    result = execute_subprocess(["nonexistent"])

    assert result.status == AuditStatus.NOT_INSTALLED
    assert "not installed" in result.error_output


@mock.patch("pip_audit_checker.subprocess.run")
def test_execute_subprocess_passes_timeout_to_run(mock_run: MagicMock):
    """Test execute_subprocess passes timeout to subprocess.run."""
    mock_result = create_autospec(subprocess.CompletedProcess, instance=True)
    mock_result.returncode = 0
    mock_result.stdout = ""
    mock_result.stderr = ""
    mock_run.return_value = mock_result

    execute_subprocess(["cmd"], timeout=60)

    call_kwargs = mock_run.call_args.kwargs
    assert call_kwargs["timeout"] == 60


# =============================================================================
# Tests for create_failure_message Function
# =============================================================================


def test_create_failure_message_vulnerabilities_found():
    """Test create_failure_message for VULNERABILITIES_FOUND status."""
    packages = (VulnerablePackage(name="pkg", version="1.0", vulnerabilities=("CVE-001",)),)
    result = AuditResult(status=AuditStatus.VULNERABILITIES_FOUND, vulnerable_packages=packages)
    config = AuditConfig(ignored_vulns=("CVE-IGNORED",))

    message = create_failure_message(result, config)

    assert "1 vulnerable package(s)" in message
    assert "CVE-001" in message
    assert "--ignore-vuln CVE-IGNORED" in message
    assert "pip_audit" in message


def test_create_failure_message_parse_error():
    """Test create_failure_message for PARSE_ERROR status."""
    result = AuditResult(status=AuditStatus.PARSE_ERROR, raw_output="invalid output")
    config = AuditConfig()

    message = create_failure_message(result, config)

    assert "security vulnerabilities" in message
    assert "invalid output" in message


def test_create_failure_message_timeout():
    """Test create_failure_message for TIMEOUT status."""
    result = AuditResult(status=AuditStatus.TIMEOUT)
    config = AuditConfig(timeout_seconds=60)

    message = create_failure_message(result, config)

    assert "timed out" in message
    assert "60 seconds" in message


def test_create_failure_message_not_installed():
    """Test create_failure_message for NOT_INSTALLED status."""
    result = AuditResult(status=AuditStatus.NOT_INSTALLED)
    config = AuditConfig()

    message = create_failure_message(result, config)

    assert "not installed" in message


def test_create_failure_message_execution_error():
    """Test create_failure_message for EXECUTION_ERROR status."""
    result = AuditResult(
        status=AuditStatus.EXECUTION_ERROR,
        raw_output="stdout error",
        error_output="stderr error",
        return_code=127,
    )
    config = AuditConfig()

    message = create_failure_message(result, config)

    assert "failed to run properly" in message
    assert "127" in message
    assert "stdout error" in message
    assert "stderr error" in message


def test_create_failure_message_unexpected_status():
    """Test create_failure_message for unexpected status."""
    result = AuditResult(status=AuditStatus.SUCCESS)  # Unexpected for failure message
    config = AuditConfig()

    message = create_failure_message(result, config)

    assert "Unexpected audit status" in message


# =============================================================================
# Tests for handle_audit_result Function
# =============================================================================


def test_handle_audit_result_success_does_not_call_fail_handler():
    """Test handle_audit_result does not call fail_handler on success."""
    result = AuditResult(status=AuditStatus.SUCCESS)
    config = AuditConfig()
    fail_handler = MagicMock()

    handle_audit_result(result, config, fail_handler)

    fail_handler.assert_not_called()


def test_handle_audit_result_failure_calls_fail_handler():
    """Test handle_audit_result calls fail_handler on failure."""
    result = AuditResult(status=AuditStatus.VULNERABILITIES_FOUND)
    config = AuditConfig()

    def fail_handler(msg: str) -> None:
        raise AssertionError(msg)

    with pytest.raises(AssertionError, match="vulnerable"):
        handle_audit_result(result, config, fail_handler)


@pytest.mark.parametrize(
    "status",
    [
        AuditStatus.VULNERABILITIES_FOUND,
        AuditStatus.PARSE_ERROR,
        AuditStatus.TIMEOUT,
        AuditStatus.NOT_INSTALLED,
        AuditStatus.EXECUTION_ERROR,
    ],
)
def test_handle_audit_result_all_failure_statuses_call_handler(status: AuditStatus):
    """Test handle_audit_result calls handler for all failure statuses."""
    result = AuditResult(status=status)
    config = AuditConfig()
    fail_handler = MagicMock()

    # Since fail_handler should be NoReturn, but mock doesn't raise
    # The function will simply call the handler
    handle_audit_result(result, config, fail_handler)

    fail_handler.assert_called_once()


# =============================================================================
# Tests for run_audit Function
# =============================================================================


@mock.patch("pip_audit_checker.execute_subprocess")
def test_run_audit_calls_execute_subprocess(mock_execute: MagicMock):
    """Test run_audit calls execute_subprocess correctly."""
    mock_execute.return_value = AuditResult(status=AuditStatus.SUCCESS)
    config = AuditConfig(timeout_seconds=60)
    project_root = Path("/project")

    result = run_audit(config, project_root)

    assert result.status == AuditStatus.SUCCESS
    mock_execute.assert_called_once()
    call_kwargs = mock_execute.call_args.kwargs
    assert call_kwargs["cwd"] == project_root
    assert call_kwargs["timeout"] == 60


@mock.patch("pip_audit_checker.execute_subprocess")
def test_run_audit_uses_sys_executable(mock_execute: MagicMock):
    """Test run_audit uses sys.executable."""
    mock_execute.return_value = AuditResult(status=AuditStatus.SUCCESS)
    config = AuditConfig()

    run_audit(config, Path("/project"))

    command = mock_execute.call_args.args[0]
    # First element should be sys.executable
    assert command[1] == "-m"
    assert command[2] == "pip_audit"


# =============================================================================
# Tests for check_pip_audit_version Function
# =============================================================================


@mock.patch("pip_audit_checker.execute_subprocess")
def test_check_pip_audit_version_success(mock_execute: MagicMock):
    """Test check_pip_audit_version returns SUCCESS with valid version."""
    mock_execute.return_value = AuditResult(
        status=AuditStatus.SUCCESS,
        raw_output="pip-audit 2.7.0",
    )

    result = check_pip_audit_version()

    assert result.status == AuditStatus.SUCCESS
    mock_execute.assert_called_once()
    command = mock_execute.call_args.args[0]
    assert "--version" in command


@mock.patch("pip_audit_checker.execute_subprocess")
def test_check_pip_audit_version_unexpected_output(mock_execute: MagicMock):
    """Test check_pip_audit_version returns EXECUTION_ERROR on unexpected output."""
    mock_execute.return_value = AuditResult(
        status=AuditStatus.SUCCESS,
        raw_output="unexpected output without version info",
    )

    result = check_pip_audit_version()

    assert result.status == AuditStatus.EXECUTION_ERROR
    assert "unexpected" in result.error_output.lower()


@mock.patch("pip_audit_checker.execute_subprocess")
def test_check_pip_audit_version_not_installed(mock_execute: MagicMock):
    """Test check_pip_audit_version returns NOT_INSTALLED when not installed."""
    mock_execute.return_value = AuditResult(
        status=AuditStatus.NOT_INSTALLED,
        error_output="pip-audit not installed",
    )

    result = check_pip_audit_version()

    assert result.status == AuditStatus.NOT_INSTALLED


@mock.patch("pip_audit_checker.execute_subprocess")
def test_check_pip_audit_version_uses_short_timeout(mock_execute: MagicMock):
    """Test check_pip_audit_version uses short timeout."""
    mock_execute.return_value = AuditResult(status=AuditStatus.SUCCESS, raw_output="pip-audit 2.7.0")

    check_pip_audit_version()

    call_kwargs = mock_execute.call_args.kwargs
    assert call_kwargs["timeout"] == 10


# =============================================================================
# Integration-style Tests for Combined Functionality
# =============================================================================


def test_integration_full_flow_with_no_vulnerabilities():
    """Test complete audit flow with clean result."""
    stdout = json.dumps({"dependencies": [{"name": "safe-pkg", "version": "1.0", "vulns": []}]})
    result = classify_audit_result(0, stdout, "")

    assert result.is_success
    assert result.vulnerability_count == 0

    config = AuditConfig()
    fail_handler = MagicMock()
    handle_audit_result(result, config, fail_handler)
    fail_handler.assert_not_called()


def test_integration_full_flow_with_vulnerabilities():
    """Test complete audit flow with vulnerabilities detected."""
    stdout = json.dumps({
        "dependencies": [
            {
                "name": "vulnerable-pkg",
                "version": "1.0",
                "vulns": [{"id": "CVE-2024-0001"}],
            }
        ]
    })
    result = classify_audit_result(1, stdout, "vulnerabilities found")

    assert not result.is_success
    assert result.vulnerability_count == 1
    assert result.vulnerable_packages[0].name == "vulnerable-pkg"

    config = AuditConfig()
    message = create_failure_message(result, config)
    assert "CVE-2024-0001" in message
    assert "vulnerable-pkg" in message


def test_integration_config_to_command_round_trip():
    """Test that config correctly translates to command arguments."""
    config = AuditConfig(
        ignored_vulns=("CVE-A", "CVE-B"),
        output_format="json",
        disable_spinner=True,
    )
    cmd = build_audit_command("/usr/bin/python", config)

    assert "/usr/bin/python" in cmd
    assert "-m" in cmd
    assert "pip_audit" in cmd
    assert "--format=json" in cmd
    assert "--progress-spinner=off" in cmd
    assert "--ignore-vuln=CVE-A" in cmd
    assert "--ignore-vuln=CVE-B" in cmd


def test_integration_multiple_vulnerabilities_formatting():
    """Test formatting of multiple vulnerabilities from multiple packages."""
    packages = (
        VulnerablePackage(name="pkg1", version="1.0", vulnerabilities=("CVE-001", "CVE-002")),
        VulnerablePackage(name="pkg2", version="2.0", vulnerabilities=("CVE-003",)),
        VulnerablePackage(name="pkg3", version="3.0", vulnerabilities=("CVE-004", "CVE-005", "CVE-006")),
    )
    result = AuditResult(status=AuditStatus.VULNERABILITIES_FOUND, vulnerable_packages=packages)

    formatted = result.format_vulnerabilities()
    parsed = json.loads(formatted)

    assert len(parsed) == 3
    total_vulns = sum(len(p["vulns"]) for p in parsed)
    assert total_vulns == 6
