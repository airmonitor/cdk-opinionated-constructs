import operator
import sys

from datetime import UTC, datetime, timedelta

import boto3

from botocore.config import Config


def create_cloudwatch_client(region_name):
    """Creates a Boto3 CloudWatch client for the given region."""
    boto3_config = Config(region_name=region_name)
    return boto3.client("cloudwatch", config=boto3_config)


def get_metric_statistics(
    *,
    client: boto3.client,
    namespace: str,
    metric_name: str,
    state_machine_arn: str,
    start_time: datetime,
    end_time: datetime,
):
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
    checks for successful executions."""
    if not datapoints:
        print("No datapoints found")
        sys.exit(1)

    datapoints.sort(key=operator.itemgetter("Timestamp"))

    for datapoint in datapoints:
        timestamp = datapoint["Timestamp"]
        value = datapoint["Sum"]
        print(f"Timestamp: {timestamp}, Value: {value}")

        if value > 0:
            print("Step Functions state machine was executed successfully")
            sys.exit(0)
        else:
            print("Step Functions state machine execution failed")
            sys.exit(1)


def main(time_delta_minutes=10):
    """The main function to fetch and print Step Functions execution metric
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

    datapoints = get_metric_statistics(
        client=cloudwatch,
        namespace="AWS/States",
        metric_name="ExecutionsSucceeded",
        state_machine_arn=state_machine_arn,
        start_time=start_time,
        end_time=end_time,
    )

    print_metric_data(datapoints)


if __name__ == "__main__":
    main()
