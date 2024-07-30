import operator
import sys

from datetime import UTC, datetime, timedelta

import boto3

from botocore.config import Config
from tenacity import retry, stop_after_delay, wait_fixed


def create_cloudwatch_client(region_name):
    """Creates a Boto3 CloudWatch client for the given region.

    Parameters:

    - region_name: The AWS region name.

    Returns:
        The CloudWatch client instance.
    """

    boto3_config = Config(region_name=region_name)
    return boto3.client("cloudwatch", config=boto3_config)


def get_metric_statistics(
    *,
    client: boto3.client,
    namespace: str,
    metric_name: str,
    function_name: str,
    start_time: datetime,
    end_time: datetime,
):
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
    successful invocations.

    Parameters:

    - datapoints: The list of CloudWatch datapoints.

    It sorts the datapoints by timestamp and prints each one.

    It checks the Sum value - if greater than 0, the Lambda was invoked successfully.
    If 0, the Lambda failed to invoke.

    Exits with status code 0 for success, 1 for failure.
    """

    if not datapoints:
        print("No datapoints found")
        sys.exit(1)

    datapoints.sort(key=operator.itemgetter("Timestamp"))

    for datapoint in datapoints:
        timestamp = datapoint["Timestamp"]
        value = datapoint["Sum"]
        print(f"Timestamp: {timestamp}, Value: {value}")

        if value > 0:
            print("Lambda was invoked correctly")
            sys.exit(0)
        else:
            print("Lambda was invoked incorrectly")
            sys.exit(1)


@retry(stop=stop_after_delay(300), wait=wait_fixed(10))
def get_metric_statistics_with_retry(*args, **kwargs):
    """
    Parameters:
        *args: Variable length argument list to be passed to the get_metric_statistics function.
        **kwargs: Arbitrary keyword arguments to be passed to the get_metric_statistics function.

    Functionality:
        Calls the get_metric_statistics function with the provided arguments and retries the operation
        if no datapoints are found. The function uses the @retry decorator to implement the retry logic.

    Returns:
        list: A list of datapoints returned by the get_metric_statistics function.

    Raises:
        ValueError: If no datapoints are found after retrying.
    """

    datapoints = get_metric_statistics(*args, **kwargs)
    if not datapoints:
        raise ValueError("No datapoints found")
    return datapoints


def main(time_delta_minutes=10):
    """The main function to fetch and print Lambda invocation metric data.

    It requires two command line arguments - the function name and AWS region.

    It creates a CloudWatch client for the given region.

    It gets the datapoints for the Lambda Invocations metric over the last 25 minutes.

    It prints the datapoints and checks if the Lambda was invoked successfully.

    Parameters:

    - None
    """

    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python script.py <function_name> <aws_region> [time_delta_minutes]")
        sys.exit(1)

    function_name = sys.argv[1]
    aws_region = sys.argv[2]

    if len(sys.argv) == 4:
        time_delta_minutes = int(sys.argv[3])

    cloudwatch = create_cloudwatch_client(aws_region)

    end_time = datetime.now(UTC)
    start_time = end_time - timedelta(minutes=time_delta_minutes)

    try:
        datapoints = get_metric_statistics_with_retry(
            client=cloudwatch,
            namespace="AWS/Lambda",
            metric_name="Invocations",
            function_name=function_name,
            start_time=start_time,
            end_time=end_time,
        )
        print_metric_data(datapoints)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
