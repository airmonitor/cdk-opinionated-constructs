import sys

from datetime import UTC, datetime, timedelta

import boto3

from botocore.config import Config


def create_cloudwatch_client(region_name):
    """Creates a Boto3 CloudWatch client for the given region.

    Parameters:

    - region_name: The AWS region name.

    Returns:
        The CloudWatch client instance.
    """

    boto3_config = Config(region_name=region_name)
    return boto3.client("cloudwatch", config=boto3_config)


def get_metric_statistics(client, namespace, metric_name, function_name, start_time, end_time):
    """Fetches CloudWatch metric statistics for a Lambda function.

    Parameters:

    - client: The Boto3 CloudWatch client.
    - namespace: The namespace for the metric.
    - metric_name: The name of the CloudWatch metric.
    - function_name: The name of the Lambda function.
    - start_time: The start time for the query.
    - end_time: The end time for the query.

    Returns:
        The list of datapoints returned by CloudWatch.
    """

    response = client.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=[{"Name": "FunctionName", "Value": function_name}],
        StartTime=start_time,
        EndTime=end_time,
        Period=300,  # 5-minute intervals
        Statistics=["Sum"],
    )
    return response.get("Datapoints", [])


def print_metric_data(datapoints):
    """Prints CloudWatch metric data for a Lambda function and checks for
    unsuccessful invocations.

    Parameters:

    - datapoints: The list of CloudWatch datapoints.

    It sorts the datapoints by timestamp and prints each one.

    It checks the Sum value - if greater than 0, the Lambda failed to invoke successfully.
    If 0, the AWS Lambda invoked correctly.

    Exits with status code 1 for failure, 0 for success.
    """

    if not datapoints:
        print("No datapoints found")
        sys.exit(1)

    datapoints.sort(key=lambda x: x["Timestamp"])

    for datapoint in datapoints:
        timestamp = datapoint["Timestamp"]
        value = datapoint["Sum"]
        print(f"Timestamp: {timestamp}, Value: {value}")

        if value > 0:
            print("Lambda was invoked incorrectly")
            sys.exit(1)
        else:
            print("Lambda was invoked correctly")
            sys.exit(0)


def main():
    """The main function to fetch and print Lambda error metric data.

    It requires two command line arguments - the function name and AWS region.

    It creates a CloudWatch client for the given region.

    It gets the datapoints for the Lambda Errors metric over the last 25 minutes.

    It prints the datapoints and checks if the Lambda invoked unsuccessfully.

    Parameters:

    - None
    """

    if len(sys.argv) != 3:
        print("Usage: python script.py <function_name> <aws_region>")
        sys.exit(1)

    function_name = sys.argv[1]
    aws_region = sys.argv[2]

    cloudwatch = create_cloudwatch_client(aws_region)

    end_time = datetime.now(UTC)
    start_time = end_time - timedelta(minutes=25)

    datapoints = get_metric_statistics(cloudwatch, "AWS/Lambda", "Errors", function_name, start_time, end_time)

    print_metric_data(datapoints)


if __name__ == "__main__":
    main()
