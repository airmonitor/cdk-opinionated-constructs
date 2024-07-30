import operator
import sys

from datetime import UTC, datetime, timedelta

import boto3

from botocore.config import Config
from tenacity import retry, stop_after_delay, wait_fixed


def create_cloudwatch_client(region_name):
    """Creates a Boto3 CloudWatch client for the given region."""
    boto3_config = Config(region_name=region_name)
    return boto3.client("cloudwatch", config=boto3_config)


def get_metric_statistics(client, namespace, metric_name, state_machine_arn, start_time, end_time):
    """Fetches CloudWatch metric statistics for a Step Functions state
    machine."""
    response = client.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=[{"Name": "StateMachineArn", "Value": state_machine_arn}],
        StartTime=start_time,
        EndTime=end_time,
        Period=300,  # 5-minute intervals
        Statistics=["Sum"],
    )
    return response.get("Datapoints", [])


def print_metric_data(datapoints):
    """Prints CloudWatch metric data for a Step Functions state machine and
    checks for unsuccessful executions."""
    if not datapoints:
        print("No datapoints found")
        sys.exit(1)

    datapoints.sort(key=operator.itemgetter("Timestamp"))

    for datapoint in datapoints:
        timestamp = datapoint["Timestamp"]
        value = datapoint["Sum"]
        print(f"Timestamp: {timestamp}, Value: {value}")

        if value > 0:
            print("Step Functions execution failed")
            sys.exit(1)
        else:
            print("Step Functions execution succeeded")
            sys.exit(0)


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
    """The main function to fetch and print Step Functions error metric
    data."""
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python script.py <function_name> <aws_region> [time_delta_minutes]")
        sys.exit(1)

    state_machine_arn = sys.argv[1]
    aws_region = sys.argv[2]

    if len(sys.argv) == 4:
        time_delta_minutes = int(sys.argv[3])

    cloudwatch = create_cloudwatch_client(aws_region)

    end_time = datetime.now(UTC)
    start_time = end_time - timedelta(minutes=time_delta_minutes)

    for execution_type in ("ExecutionsFailed", "ExecutionsTimedOut", "ExecutionsAborted"):
        metric_name = execution_type
        try:
            datapoints = get_metric_statistics_with_retry(
                cloudwatch, "AWS/States", metric_name, state_machine_arn, start_time, end_time
            )
            print_metric_data(datapoints)
        except ValueError as e:
            print(f"Error for {metric_name}: {e}")
            continue


if __name__ == "__main__":
    main()
