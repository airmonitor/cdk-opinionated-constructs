import operator
import sys

from datetime import UTC, datetime, timedelta

import boto3

from botocore.config import Config


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


def main():
    """The main function to fetch and print Step Functions error metric
    data."""
    if len(sys.argv) != 3:
        print("Usage: python script.py <state_machine_arn> <aws_region>")
        sys.exit(1)

    state_machine_arn = sys.argv[1]
    aws_region = sys.argv[2]

    cloudwatch = create_cloudwatch_client(aws_region)

    end_time = datetime.now(UTC)
    start_time = end_time - timedelta(minutes=10)

    for execution_type in ("ExecutionsFailed", "ExecutionsTimedOut", "ExecutionsAborted"):
        metric_name = execution_type
        datapoints = get_metric_statistics(
            cloudwatch, "AWS/States", metric_name, state_machine_arn, start_time, end_time
        )
        print_metric_data(datapoints)


if __name__ == "__main__":
    main()
