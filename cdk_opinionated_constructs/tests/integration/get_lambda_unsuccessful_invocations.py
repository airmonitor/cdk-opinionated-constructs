import sys

from datetime import UTC, datetime, timedelta

import boto3

from botocore.config import Config

aws_region = sys.argv[2]
boto3_config = Config(region_name=aws_region)

cloudwatch = boto3.client("cloudwatch", config=boto3_config)

# Specify the metric details
metric_name = "Errors"
namespace = "AWS/Lambda"
function_name = sys.argv[1]

# Calculate the start and end times for the metric query
end_time = datetime.now(UTC)
start_time = end_time - timedelta(minutes=25)

# Get the metric statistics
response = cloudwatch.get_metric_statistics(
    Namespace=namespace,
    MetricName=metric_name,
    Dimensions=[{"Name": "FunctionName", "Value": function_name}],
    StartTime=start_time,
    EndTime=end_time,
    Period=300,  # 5-minute intervals
    Statistics=["Sum"],
)

# Extract the metric data points
datapoints = response["Datapoints"]

# Sort the datapoints by timestamp
datapoints.sort(key=lambda x: x["Timestamp"])

# Print the metric data
if datapoints:
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
else:
    print("No datapoints found")
    sys.exit(1)
