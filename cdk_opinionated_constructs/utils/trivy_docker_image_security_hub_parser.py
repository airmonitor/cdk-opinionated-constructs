import datetime
import json

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
        self.sts = boto3.client("sts")
        self.security_hub = boto3.client("securityhub")
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

    def _build_resource(self, vulnerability: dict) -> dict:
        """
        Parameters:
            vulnerability (dict): Dictionary containing vulnerability information with keys:
                - VulnerabilityID: Unique identifier for the CVE
                - Title: Title/name of the vulnerability
                - PkgName: Name of the affected package
                - InstalledVersion: Currently installed version of the package
                - FixedVersion: Version of the package that contains the fix

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

        return {
            "Type": "Container",
            "Id": f"{self.config.container_name}:{self.config.container_tag}",
            "Partition": "aws",
            "Region": self.config.aws_region,
            "Details": {
                "Container": {"ImageName": f"{self.config.container_name}:{self.config.container_tag}"},
                "Other": {
                    "CVE ID": vulnerability["VulnerabilityID"],
                    "CVE Title": vulnerability["Title"],
                    "Installed Package": f"{vulnerability['PkgName']} {vulnerability['InstalledVersion']}",
                    "Patched Package": f"{vulnerability['PkgName']} {vulnerability['FixedVersion']}",
                },
            },
        }

    def create_finding(self, vulnerability: dict) -> dict:
        """
        Parameters:
            vulnerability (dict): Dictionary containing vulnerability details with keys:
                - VulnerabilityID: Unique identifier for the vulnerability
                - Severity: Severity level of the vulnerability (LOW, MEDIUM, HIGH, CRITICAL)
                - Description: Detailed description of the vulnerability
                - References: List of reference URLs with more information
                - Title: Title/name of the vulnerability

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
        product_sev, normalized_sev = VulnerabilityParser.parse_severity(vulnerability["Severity"])

        return {
            "SchemaVersion": "2018-10-08",
            "Id": f"{self.config.container_name}:{self.config.container_tag}/{vulnerability['VulnerabilityID']}",
            "ProductArn": f"arn:aws:securityhub:{self.config.aws_region}::product/aquasecurity/aquasecurity",
            "GeneratorId": self.config.project_name,
            "AwsAccountId": self.config.aws_account,
            "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
            "CreatedAt": iso8601_time,
            "UpdatedAt": iso8601_time,
            "Severity": {"Product": product_sev, "Normalized": normalized_sev},
            "Title": f"Trivy found a vulnerability to {vulnerability['VulnerabilityID']} "
            f"in container {self.config.container_name}",
            "Description": VulnerabilityParser.truncate_description(vulnerability["Description"]),
            "Remediation": {
                "Recommendation": {
                    "Text": "More information on this vulnerability is provided in the hyperlink",
                    "Url": vulnerability["References"][0],
                }
            },
            "ProductFields": {"Product Name": "Trivy"},
            "Resources": [self._build_resource(vulnerability)],
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


@click.command()
@click.option("--aws-account", required=True, help="AWS Account ID")
@click.option("--aws-region", required=True, help="AWS Region")
@click.option("--project-name", required=True, help="Project name")
@click.option("--container-name", required=True, help="Container name")
@click.option("--container-tag", required=True, help="Container tag")
@click.option(
    "--results-file",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
    help="Path to the Trivy results JSON file",
)
def main(
    aws_account: str, aws_region: str, project_name: str, container_name: str, container_tag: str, results_file: str
):
    """
    Parameters:
        aws_account (str): AWS Account ID where Security Hub findings will be reported
        aws_region (str): AWS region where Security Hub service is running
        project_name (str): Name of the project for identifying findings source
        container_name (str): Name of the container being scanned
        container_tag (str): Tag/version of the container being scanned
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
        - Exits early if no vulnerabilities are found
        - Raises exceptions if any errors occur during processing

    Returns:
        None
    """

    config = TrivySecurityHubConfig(
        aws_account=aws_account,
        aws_region=aws_region,
        project_name=project_name,
        container_name=container_name,
        container_tag=container_tag,
    )
    finding_builder = SecurityHubFindingBuilder(config)

    results_path = Path(results_file)
    with results_path.open() as json_file:
        data = json.load(json_file)
        for result in data["Results"]:
            vulnerabilities = result.get("Vulnerabilities", [])
            if not vulnerabilities:
                continue
            for vulnerability in vulnerabilities:
                try:
                    finding = finding_builder.create_finding(vulnerability)
                    response = config.security_hub.batch_import_findings(Findings=[finding])
                    if not validate_security_hub_response(response):
                        print(f"Failed to import finding for vulnerability {vulnerability['VulnerabilityID']}")
                    else:
                        print(f"Successfully imported finding for vulnerability {vulnerability['VulnerabilityID']}")
                except Exception as e:
                    print(e)
                    raise


if __name__ == "__main__":
    main()
