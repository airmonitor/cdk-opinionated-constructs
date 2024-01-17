"""Test AWS Lambda function construct."""

import aws_cdk.aws_kms as kms
import aws_cdk.aws_lambda as lmb
import cdk_monitoring_constructs as cdk_monitoring

from aws_cdk import Duration, Stack

from cdk_opinionated_constructs.sns import SNSTopic


class TestAWSPythonLambdaFunctionStackMonitoring(Stack):
    """Create monitoring resources for PRS.

    This includes:
    * AWS CW Dashboard
    * Metrics
    * Alarms
    * Subscription to an SNS topic
    * similar
    """

    def __init__(self, scope, name, env, props):  # noqa: ARG002
        super().__init__(scope, name)
        lmb_function: lmb.Function | lmb.IFunction = props["lmb_function"]

        kms_key = kms.Key(self, id="kms_key", enable_key_rotation=True)

        sns_construct = SNSTopic(self, id="alarm_topic")
        alarm_topic = sns_construct.create_sns_topic(topic_name="alarm_topic", master_key=kms_key)

        documentation = "https://https://github.com/airmonitor/cdk-opinionated-constructs/blob/main/README.md"

        monitoring = cdk_monitoring.MonitoringFacade(
            self,
            id="monitoring_facade",
            alarm_factory_defaults=cdk_monitoring.AlarmFactoryDefaults(
                action=cdk_monitoring.SnsAlarmActionStrategy(on_alarm_topic=alarm_topic),  # type: ignore
                alarm_name_prefix=f'{props["service_name"]}',
                actions_enabled=True,
            ),
        )

        monitoring.add_large_header("Lambda").monitor_lambda_function(
            lambda_function=lmb_function,
            lambda_insights_enabled=True,
            rate_computation_method=cdk_monitoring.RateComputationMethod.PER_SECOND,
            add_concurrent_executions_count_alarm={
                "Critical": cdk_monitoring.RunningTaskCountThreshold(
                    datapoints_to_alarm=1,
                    documentation_link=documentation,
                    evaluation_periods=1,
                    fill_alarm_range=True,
                    period=Duration.seconds(10),
                    max_running_tasks=190,
                ),
                "Warning": cdk_monitoring.RunningTaskCountThreshold(
                    datapoints_to_alarm=1,
                    documentation_link=documentation,
                    evaluation_periods=1,
                    fill_alarm_range=True,
                    period=Duration.seconds(10),
                    max_running_tasks=180,
                ),
            },
            add_fault_count_alarm={
                "Critical": cdk_monitoring.ErrorCountThreshold(
                    datapoints_to_alarm=1,
                    documentation_link=documentation,
                    evaluation_periods=1,
                    period=Duration.minutes(1),
                    max_error_count=1,
                )
            },
            add_throttles_count_alarm={
                "Critical": cdk_monitoring.ErrorCountThreshold(
                    datapoints_to_alarm=1,
                    documentation_link=documentation,
                    evaluation_periods=1,
                    period=Duration.minutes(1),
                    max_error_count=1,
                )
            },
            add_latency_p99_alarm={
                "Critical": cdk_monitoring.LatencyThreshold(
                    datapoints_to_alarm=1,
                    documentation_link=documentation,
                    evaluation_periods=1,
                    period=Duration.minutes(1),
                    max_latency=Duration.seconds(round(lmb_function.timeout.to_seconds() * 0.99)),
                )
            },
        )
