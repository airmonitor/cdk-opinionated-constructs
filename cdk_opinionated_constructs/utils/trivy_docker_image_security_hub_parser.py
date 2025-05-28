"""
Trivy Docker Image Security Hub Parser

This tool parses Trivy vulnerability scan results and imports them into AWS Security Hub.
It supports Trivy JSON format (SchemaVersion 2).

Generated with: trivy image --timeout 60m --no-progress -f json -o results.json --severity HIGH,CRITICAL <image>
"""

import datetime
import json
import re

from pathlib import Path

import boto3
import click


class TrivySecurityHubConfig:
    def __init__(self, aws_account: str, aws_region: str, project_name: str, container_name: str, container_tag: str):
        """
        Parameters:
            self (object): The current TrivySecurityHubConfig instance
            aws_account (str): AWS account ID where Security Hub findings will be reported
            aws_region (str): AWS region where Security Hub service is running
            project_name (str): Name of the project for identifying findings source
            container_name (str): Name of the container being scanned
            container_tag (str): Tag/version of the container being scanned

        Functionality:
            Initializes a TrivySecurityHubConfig object with AWS credentials and container details.
            Creates boto3 clients for AWS STS and Security Hub services.
            Stores configuration parameters needed for creating and importing security findings.

        """
        self.sts = boto3.client("sts", region_name=aws_region)
        self.security_hub = boto3.client("securityhub", region_name=aws_region)
        self.aws_account = aws_account
        self.aws_region = aws_region
        self.project_name = project_name
        self.container_name = container_name
        self.container_tag = container_tag


class VulnerabilityParser:
    @staticmethod
    def parse_severity(severity: str) -> tuple[int, int]:
        """
        Parameters:
            severity (str): String representing vulnerability severity level (LOW, MEDIUM, HIGH, CRITICAL)

        Functionality:
            Maps vulnerability severity levels to corresponding numeric values for
            product and normalized severity scores
            Used for standardizing severity reporting in Security Hub findings

        Returns:
            tuple[int, int]: A tuple containing (product_severity, normalized_severity)
            - First value: Product severity score (1-9)
            - Second value: Normalized severity score (10-90)
            Returns (0,0) for unknown severity levels

        """
        severity_mapping = {"LOW": (1, 10), "MEDIUM": (4, 40), "HIGH": (7, 70), "CRITICAL": (9, 90)}
        return severity_mapping.get(severity, (0, 0))

    @staticmethod
    def truncate_description(description: str, max_length: int = 1021) -> str:
        """
        Parameters:
            description (str): The full vulnerability description text to be truncated
            max_length (int): Maximum allowed length of the description, defaults to 1021 characters

        Functionality:
            Ensures description text fits within Security Hub character limits
            Adds '..' suffix to truncated descriptions while preserving max length constraint

        Returns:
            str: Truncated description if original exceeds max_length, otherwise original description

        """
        return (description[:max_length] + "..") if len(description) > max_length else description


class SecurityHubFindingBuilder:
    def __init__(self, config: TrivySecurityHubConfig):
        self.config = config

    def _build_resource(self, vulnerability: dict, image_info: dict) -> dict:
        """
        Parameters:
            vulnerability (dict): Dictionary containing vulnerability information
            image_info (dict): Dictionary containing image metadata information

        Functionality:
            Constructs a standardized AWS Security Hub resource object for a container vulnerability
            Formats container and vulnerability details according to Security Hub's expected schema
            Combines configuration data with vulnerability information

        Returns:
            dict: A formatted resource dictionary containing:
                - Basic resource identifiers (Type, Id, Partition, Region)
                - Container details with image name
                - Vulnerability details under 'Other' including CVE information and package versions
        """
        # Ensure we have a valid ImageId or use a fallback
        image_id = image_info.get("ImageID", "")
        if not image_id:
            # Use digest from RepoDigests if available
            repo_digests = image_info.get("RepoDigests", [])
            if repo_digests and "@sha256:" in repo_digests[0]:
                image_id = repo_digests[0].split("@sha256:")[1]
            else:
                # Fallback to a timestamp-based ID if no proper ID is available
                image_id = f"unknown-{datetime.datetime.now().timestamp()}"  # noqa: DTZ005

        pkg_name = vulnerability.get("PkgName", "unknown")
        installed_version = vulnerability.get("InstalledVersion", "unknown")
        fixed_version = vulnerability.get("FixedVersion", "unknown")

        return {
            "Type": "Container",
            "Id": f"{self.config.container_name}:{self.config.container_tag}",
            "Partition": "aws",
            "Region": self.config.aws_region,
            "Details": {
                "Container": {
                    "ImageName": f"{self.config.container_name}:{self.config.container_tag}",
                    "ImageId": image_id,
                },
                "Other": {
                    "CVE ID": vulnerability.get("VulnerabilityID", "unknown"),
                    "CVE Title": vulnerability.get("Title", "unknown"),
                    "Installed Package": f"{pkg_name} {installed_version}",
                    "Patched Package": f"{pkg_name} {fixed_version}",
                },
            },
        }

    def create_finding(self, vulnerability: dict, image_info: dict) -> dict:
        """
        Parameters:
            vulnerability (dict): Dictionary containing vulnerability details
            image_info (dict): Dictionary containing image metadata information

        Functionality:
            Creates a standardized AWS Security Hub finding from a Trivy vulnerability scan result
            Formats the finding according to AWS Security Hub's required schema
            Generates timestamps and severity scores
            Builds resource details using internal _build_resource method

        Returns:
            dict: A formatted Security Hub finding containing:
                - Standard AWS Security Hub fields (SchemaVersion, Id, ProductArn, etc.)
                - Severity scores (Product and Normalized)
                - Vulnerability details (Title, Description, Remediation)
                - Resource information about the affected container
                - Metadata about the finding source and state
        """

        iso8601_time = datetime.datetime.now(datetime.UTC).isoformat()
        product_sev, normalized_sev = VulnerabilityParser.parse_severity(vulnerability.get("Severity", "UNKNOWN"))
        vuln_id = vulnerability.get("VulnerabilityID", "unknown")
        description = vulnerability.get("Description", "No description available")
        references = vulnerability.get("References", ["https://nvd.nist.gov/"])

        return {
            "SchemaVersion": "2018-10-08",
            "Id": f"{self.config.container_name}:{self.config.container_tag}/{vuln_id}",
            "ProductArn": f"arn:aws:securityhub:{self.config.aws_region}::product/aquasecurity/aquasecurity",
            "GeneratorId": self.config.project_name,
            "AwsAccountId": self.config.aws_account,
            "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
            "CreatedAt": iso8601_time,
            "UpdatedAt": iso8601_time,
            "Severity": {"Product": product_sev, "Normalized": normalized_sev},
            "Title": f"Trivy found a vulnerability to {vuln_id} in container {self.config.container_name}",
            "Description": VulnerabilityParser.truncate_description(description),
            "Remediation": {
                "Recommendation": {
                    "Text": "More information on this vulnerability is provided in the hyperlink",
                    "Url": references[0] if references else "https://nvd.nist.gov/",
                }
            },
            "ProductFields": {"Product Name": "Trivy"},
            "Resources": [self._build_resource(vulnerability, image_info)],
            "RecordState": "ACTIVE",
        }

    def create_no_vulnerabilities_finding(self, image_info: dict) -> dict:
        """
        Parameters:
            image_info (dict): Dictionary containing image metadata information

        Functionality:
            Creates a standardized AWS Security Hub finding indicating no vulnerabilities were found
            Used when a scan completes successfully but no vulnerabilities are detected

        Returns:
            dict: A formatted Security Hub finding with informational severity
        """
        iso8601_time = datetime.datetime.now(datetime.UTC).isoformat()

        # Ensure we have a valid ImageId or use a fallback
        image_id = image_info.get("ImageID", "")
        if not image_id:
            # Use digest from RepoDigests if available
            repo_digests = image_info.get("RepoDigests", [])
            if repo_digests and "@sha256:" in repo_digests[0]:
                image_id = repo_digests[0].split("@sha256:")[1]
            else:
                # Fallback to a timestamp-based ID if no proper ID is available
                image_id = f"unknown-{datetime.datetime.now().timestamp()}"  # noqa: DTZ005

        return {
            "SchemaVersion": "2018-10-08",
            "Id": f"{self.config.container_name}:{self.config.container_tag}/no-vulnerabilities",
            "ProductArn": f"arn:aws:securityhub:{self.config.aws_region}::product/aquasecurity/aquasecurity",
            "GeneratorId": self.config.project_name,
            "AwsAccountId": self.config.aws_account,
            "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
            "CreatedAt": iso8601_time,
            "UpdatedAt": iso8601_time,
            "Severity": {"Product": 0, "Normalized": 0},
            "Title": f"No vulnerabilities found in container {self.config.container_name}:{self.config.container_tag}",
            "Description": "Trivy security scan completed successfully with no vulnerabilities detected.",
            "ProductFields": {"Product Name": "Trivy"},
            "Resources": [
                {
                    "Type": "Container",
                    "Id": f"{self.config.container_name}:{self.config.container_tag}",
                    "Partition": "aws",
                    "Region": self.config.aws_region,
                    "Details": {
                        "Container": {
                            "ImageName": f"{self.config.container_name}:{self.config.container_tag}",
                            "ImageId": image_id,
                        }
                    },
                }
            ],
            "RecordState": "ACTIVE",
        }


def validate_security_hub_response(response: dict) -> bool:
    """
    Parameters:
        response (dict): AWS Security Hub API response dictionary containing:
            - ResponseMetadata: Dictionary with HTTP status information
            - SuccessCount: Number of successfully imported findings
            - FailedCount: Number of failed finding imports
            - FailedFindings: List of findings that failed to import (optional)

    Functionality:
        Validates the response from AWS Security Hub batch import operation
        Checks HTTP status code for successful API call
        Verifies successful import of findings
        Prints warning messages for any failed imports

    Returns:
        bool: True if all validations pass (successful import with no failures),
            False if any validation fails (HTTP error, import failures, or no imports)
    """

    # Check HTTP status code
    if response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
        print(f"Error: HTTP Status Code {response['ResponseMetadata']['HTTPStatusCode']}")
        return False

    # Check success and failure counts
    success_count = response.get("SuccessCount", 0)
    failed_count = response.get("FailedCount", 0)

    if failed_count > 0:
        print(f"Warning: {failed_count} findings failed to import")
        if response.get("FailedFindings"):
            print("Failed findings:", response["FailedFindings"])
        return False

    if success_count == 0:
        print("Warning: No findings were imported")
        return False

    return True


def extract_container_info(artifact_name: str) -> tuple[str, str]:
    """
    Parameters:
        artifact_name (str): The full artifact name from Trivy scan results

    Functionality:
        Extracts container name and tag from the artifact name
        Handles various formats of container references

    Returns:
        tuple[str, str]: A tuple containing (container_name, container_tag)
    """
    # Try to match ECR repository pattern
    ecr_pattern = r"([^/]+\.dkr\.ecr\.[^/]+\.amazonaws\.com/[^:]+):(.+)"
    match = re.match(ecr_pattern, artifact_name)

    if match:
        return match.group(1), match.group(2)

    # Try standard docker image pattern (name:tag)
    std_pattern = r"([^:]+):(.+)"
    match = re.match(std_pattern, artifact_name)

    if match:
        return match.group(1), match.group(2)

    # If no pattern matches, return the whole string as name and "latest" as tag
    return artifact_name, "latest"


@click.command()
@click.option("--aws-account", required=True, help="AWS Account ID")
@click.option("--aws-region", required=True, help="AWS Region")
@click.option("--project-name", required=True, help="Project name")
@click.option("--container-name", help="Container name (optional, will be extracted from results if not provided)")
@click.option("--container-tag", help="Container tag (optional, will be extracted from results if not provided)")
@click.option(
    "--results-file",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
    help="Path to the Trivy results JSON file",
)
def main(  # noqa: PLR0912
    aws_account: str, aws_region: str, project_name: str, container_name: str, container_tag: str, results_file: str
):
    """
    Parameters:
        aws_account (str): AWS Account ID where Security Hub findings will be reported
        aws_region (str): AWS region where Security Hub service is running
        project_name (str): Name of the project for identifying findings source
        container_name (str): Name of the container being scanned (optional)
        container_tag (str): Tag/version of the container being scanned (optional)
        results_file (str): Path to the Trivy scan results JSON file

    Functionality:
        - Creates a TrivySecurityHubConfig instance with AWS and container details
        - Initializes a SecurityHubFindingBuilder with the config
        - Reads and parses Trivy JSON scan results from the specified file
        - For each vulnerability found:
            - Creates a Security Hub finding
            - Attempts to import the finding into Security Hub
            - Validates the import response
            - Prints success/failure status for each finding
        - If no vulnerabilities are found, creates an informational finding
        - Raises exceptions if any errors occur during processing

    Returns:
        None
    """

    results_path = Path(results_file)
    with results_path.open() as json_file:
        data = json.load(json_file)

        # Extract container info from Trivy format
        if not container_name or not container_tag:
            artifact_name = data.get("ArtifactName", "")
            extracted_name, extracted_tag = extract_container_info(artifact_name)
            container_name = container_name or extracted_name
            container_tag = container_tag or extracted_tag

        config = TrivySecurityHubConfig(
            aws_account=aws_account,
            aws_region=aws_region,
            project_name=project_name,
            container_name=container_name,
            container_tag=container_tag,
        )
        finding_builder = SecurityHubFindingBuilder(config)

        # Extract image metadata from Trivy format
        image_info = data.get("Metadata", {})
        if "ImageConfig" in image_info:
            # Add any relevant fields from ImageConfig to the top level
            for key in ["ImageID", "RepoTags", "RepoDigests"]:
                if key not in image_info and key in image_info.get("ImageConfig", {}):
                    image_info[key] = image_info["ImageConfig"][key]

        # Track if we found any vulnerabilities
        vulnerabilities_found = False

        # Process vulnerabilities from Trivy format
        for result in data.get("Results", []):
            vulnerabilities = result.get("Vulnerabilities", [])
            if not vulnerabilities:
                continue

            vulnerabilities_found = True
            for vulnerability in vulnerabilities:
                try:
                    finding = finding_builder.create_finding(vulnerability, image_info)
                    response = config.security_hub.batch_import_findings(Findings=[finding])
                    if not validate_security_hub_response(response):
                        print(
                            f"Failed to import finding for vulnerability "
                            f"{vulnerability.get('VulnerabilityID', 'unknown')}"
                        )
                    else:
                        print(
                            f"Successfully imported finding for vulnerability "
                            f"{vulnerability.get('VulnerabilityID', 'unknown')}"
                        )
                except Exception as e:
                    print(f"Error processing vulnerability: {e}")
                    raise

        # If no vulnerabilities were found, send an informational finding
        if not vulnerabilities_found:
            try:
                print("No vulnerabilities found in scan results, sending informational finding")
                finding = finding_builder.create_no_vulnerabilities_finding(image_info)
                response = config.security_hub.batch_import_findings(Findings=[finding])
                if not validate_security_hub_response(response):
                    print("Failed to import informational finding")
                else:
                    print("Successfully imported informational finding")
            except Exception as e:
                print(f"Error sending informational finding: {e}")
                raise


if __name__ == "__main__":
    main()
