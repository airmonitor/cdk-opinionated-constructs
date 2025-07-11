"""Opinionated CDK construct to create AWS WAFv2.

Security parameters, logging are set by default
"""

from typing import Any, Literal

import aws_cdk as cdk
import aws_cdk.aws_wafv2 as wafv2

from aws_cdk import aws_logs as logs
from constructs import Construct


class WAFv2(Construct):
    """Implement a v2 WAF where logs are sent to the AWS CloudWatch logs."""

    def __init__(self, scope: Construct, construct_id: str) -> None:
        super().__init__(scope, construct_id)

    @staticmethod
    def __aws_account_takeover_prevention(aws_account_takeover_prevention):
        """Creates a WAF rule to enable AWS account takeover prevention.

        Parameters:

        - aws_account_takeover_prevention: Dictionary containing:

          - login_path: The login page path
          - password_field: Password field identifier
          - username_field: Username field identifier

        It creates a rule to use the AWSManagedRulesATPRuleSet managed rule set.

        This is configured with the provided login path, password, and username fields.

        It enables CloudWatch metrics and sampled request logging.

        Returns the rule property to add to the WAF WebACL.
        """

        return wafv2.CfnWebACL.RuleProperty(
            name="AWS-AWSManagedRulesATPRuleSet",
            priority=6,
            override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
            statement=wafv2.CfnWebACL.StatementProperty(
                managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name="AWSManagedRulesATPRuleSet",
                    vendor_name="AWS",
                    managed_rule_group_configs=[
                        wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                            login_path=aws_account_takeover_prevention["login_path"],
                        ),
                        wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                            password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                identifier=aws_account_takeover_prevention["password_field"]
                            ),
                        ),
                        wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                            payload_type="FORM_ENCODED",
                        ),
                        wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                            username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                identifier=aws_account_takeover_prevention["username_field"]
                            ),
                        ),
                    ],
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="AWS-AWSManagedRulesATPRuleSet",
                sampled_requests_enabled=True,
            ),
        )

    @staticmethod
    def __aws_sqli_rule():
        """Creates a WAF rule to enable AWS managed SQL injection protection.

        It creates a rule to use the AWSManagedRulesSQLiRuleSet managed
        rule set.

        This enables protection against SQL injection attacks.

        It enables CloudWatch metrics and sampled request logging.

        Returns the rule property to add to the WAF WebACL.
        """

        return wafv2.CfnWebACL.RuleProperty(
            name="AWS-AWSManagedRulesSQLiRuleSet",
            priority=5,
            override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
            statement=wafv2.CfnWebACL.StatementProperty(
                managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name="AWSManagedRulesSQLiRuleSet",
                    vendor_name="AWS",
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="AWS-AWSManagedRulesSQLiRuleSet",
                sampled_requests_enabled=True,
            ),
        )

    @staticmethod
    def __aws_bad_inputs_rule():
        """Creates a WAF rule to block known bad inputs.

        It creates a rule using the AWSManagedRulesKnownBadInputsRuleSet
        managed rule set.

        This protects against input-based attacks like XSS, SQLi, etc.

        It enables CloudWatch metrics and sampled request logging.

        Returns the rule property to add to the WAF WebACL.
        """

        return wafv2.CfnWebACL.RuleProperty(
            name="AWS-AWSManagedRulesKnownBadInputsRuleSet",
            priority=4,
            override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
            statement=wafv2.CfnWebACL.StatementProperty(
                managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name="AWSManagedRulesKnownBadInputsRuleSet",
                    vendor_name="AWS",
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="AWS-AWSManagedRulesKnownBadInputsRuleSet",
                sampled_requests_enabled=True,
            ),
        )

    @staticmethod
    def __rate_list(rate_value: int):
        """Creates a WAF rate-based rule to limit requests per IP.

        Parameters:

        - rate_value: The maximum requests per 5 minutes per IP.

        It creates a rule to limit requests per IP based on the rate value.

        Requests exceeding the limit will be blocked.

        It enables CloudWatch metrics and sampled request logging.

        Returns the rule property to add to the WAF WebACL.
        """

        return wafv2.CfnWebACL.RuleProperty(
            name=f"Custom-RateLimit{rate_value}",
            priority=1,
            action=wafv2.CfnWebACL.RuleActionProperty(block=wafv2.CfnWebACL.BlockActionProperty()),
            statement=wafv2.CfnWebACL.StatementProperty(
                rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                    aggregate_key_type="IP",
                    limit=rate_value,
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name=f"Custom-RateLimit{rate_value}",
                sampled_requests_enabled=True,
            ),
        )

    @staticmethod
    def __aws_ip_reputation_list():
        """Creates a WAF rule to block requests from known malicious IPs.

        It creates a rule using the
        AWSManagedRulesAmazonIpReputationList managed rule set.

        This blocks requests from known malicious IP addresses.

        It runs with the highest priority to block bad IPs early.

        It enables CloudWatch metrics and sampled request logging.

        Returns the rule property to add to the WAF WebACL.
        """

        return wafv2.CfnWebACL.RuleProperty(
            name="AWS-AWSManagedRulesAmazonIpReputationList",
            priority=0,
            override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
            statement=wafv2.CfnWebACL.StatementProperty(
                managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name="AWSManagedRulesAmazonIpReputationList",
                    vendor_name="AWS",
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="AWS-AWSManagedRulesAmazonIpReputationList",
                sampled_requests_enabled=True,
            ),
        )

    @staticmethod
    def __aws_common_rule(aws_common_excluded_rules):
        """Creates a WAF rule using the AWSManagedRulesCommonRuleSet.

        Parameters:

        - aws_common_excluded_rules: List of rule names to exclude from the common rule set.

        It creates a rule using the AWSManagedRulesCommonRuleSet managed rule group.

        This enables a broad set of common protections like XSS, protocol violations, etc.

        It excludes any rules specified in the aws_common_excluded_rules list.

        This allows customizing the enabled protections.

        It enables CloudWatch metrics and sampled request logging.

        Returns the rule property to add to the WAF WebACL.
        """

        return wafv2.CfnWebACL.RuleProperty(
            name="AWS-AWSManagedRulesCommonRuleSet",
            priority=2,
            override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
            statement=wafv2.CfnWebACL.StatementProperty(
                managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                    excluded_rules=aws_common_excluded_rules,
                    name="AWSManagedRulesCommonRuleSet",
                    vendor_name="AWS",
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="AWS-AWSManagedRulesCommonRuleSet",
                sampled_requests_enabled=True,
            ),
        )

    @staticmethod
    def __aws_anonymous_list():
        """Creates a WAF rule to block requests from anonymous proxy servers.

        It creates a rule using the AWSManagedRulesAnonymousIpList
        managed rule set.

        This blocks requests from known anonymous proxy servers.

        It enables CloudWatch metrics and sampled request logging.

        Returns the rule property to add to the WAF WebACL.
        """

        return wafv2.CfnWebACL.RuleProperty(
            name="AWS-AWSManagedRulesAnonymousIpList",
            priority=3,
            override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
            statement=wafv2.CfnWebACL.StatementProperty(
                managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name="AWSManagedRulesAnonymousIpList",
                    vendor_name="AWS",
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="AWS-AWSManagedRulesAnonymousIpList",
                sampled_requests_enabled=True,
            ),
        )

    @staticmethod
    def __aws_bot_control_rule(count: bool = False):  # noqa: FBT001, FBT002
        if count:
            override_action = wafv2.CfnWebACL.OverrideActionProperty(count={})
        else:
            override_action = wafv2.CfnWebACL.OverrideActionProperty(none={})

        return wafv2.CfnWebACL.RuleProperty(
            name="AWS-AWSManagedRulesBotControlRuleSet",
            priority=7,
            override_action=override_action,
            statement=wafv2.CfnWebACL.StatementProperty(
                managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name="AWSManagedRulesBotControlRuleSet",
                    vendor_name="AWS",
                    managed_rule_group_configs=[
                        wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                            aws_managed_rules_bot_control_rule_set=wafv2.CfnWebACL.AWSManagedRulesBotControlRuleSetProperty(
                                inspection_level="COMMON"
                            )
                        )
                    ],
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="AWS-AWSManagedRulesBotControlRuleSet",
                sampled_requests_enabled=True,
            ),
        )

    @staticmethod
    def __aws_php_application_rule(count: bool = False):  # noqa: FBT001, FBT002
        if count:
            override_action = wafv2.CfnWebACL.OverrideActionProperty(count={})
        else:
            override_action = wafv2.CfnWebACL.OverrideActionProperty(none={})

        return wafv2.CfnWebACL.RuleProperty(
            name="AWS-AWSManagedRulesPHPRuleSet",
            priority=7,
            override_action=override_action,
            statement=wafv2.CfnWebACL.StatementProperty(
                managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name="AWSManagedRulesPHPRuleSet",
                    vendor_name="AWS",
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="AWS-AWSManagedRulesPHPRuleSet",
                sampled_requests_enabled=True,
            ),
        )

    @staticmethod
    def __aws_posix_operating_system_rule(count: bool = False):  # noqa: FBT001, FBT002
        if count:
            override_action = wafv2.CfnWebACL.OverrideActionProperty(count={})
        else:
            override_action = wafv2.CfnWebACL.OverrideActionProperty(none={})

        return wafv2.CfnWebACL.RuleProperty(
            name="AWS-AWSManagedRulesUnixRuleSet",
            priority=8,
            override_action=override_action,
            statement=wafv2.CfnWebACL.StatementProperty(
                managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name="AWSManagedRulesUnixRuleSet",
                    vendor_name="AWS",
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="AWS-AWSManagedRulesUnixRuleSet",
                sampled_requests_enabled=True,
            ),
        )

    def web_acl(
        self,
        name: str,
        rate_value: int | None,
        aws_common_rule: bool = True,  # noqa: FBT001, FBT002
        aws_common_rule_ignore_list: list | None = None,
        aws_anony_list: bool = False,  # noqa: FBT001, FBT002
        aws_bad_inputs_rule: bool = False,  # noqa: FBT001, FBT002
        aws_sqli_rule: bool = False,  # noqa: FBT001, FBT002
        aws_account_takeover_prevention: bool | dict[Any, Any] = False,  # noqa: FBT001, FBT002
        aws_bot_control_rule: bool = False,  # noqa: FBT001, FBT002
        aws_bot_control_count: bool = False,  # noqa: FBT001, FBT002
        aws_php_application_rule: bool = False,  # noqa: FBT001, FBT002
        aws_posix_operating_system_rule: bool = False,  # noqa: FBT001, FBT002
        waf_scope: Literal["REGIONAL", "CLOUDFRONT"] = "REGIONAL",
    ) -> wafv2.CfnWebACL:
        """
        Parameters:
            self (WAFv2): The current WAFv2 construct object
            name (str): The name for the Web ACL
            rate_value (int | None): Rate limit value for rate-based rule; None to disable rate limiting
            aws_common_rule (bool): Whether to enable AWS Common Rule Set (default: True)
            aws_common_rule_ignore_list (list | None): List of rule names to exclude from Common Rule Set
            aws_anony_list (bool): Whether to enable Anonymous IP List rule (default: False)
            aws_bad_inputs_rule (bool): Whether to enable Known Bad Inputs rule (default: False)
            aws_sqli_rule (bool): Whether to enable SQL Injection rule (default: False)
            aws_account_takeover_prevention (bool | dict[Any, Any]): Account takeover prevention configuration;
            False to disable or dict with configuration (default: False)
            aws_bot_control_rule (bool): Whether to enable Bot Control rule (default: False)
            aws_bot_control_count (bool): Whether Bot Control rule should count instead of block (default: False)
            aws_php_application_rule (bool): Whether to enable PHP Application rule (default: False)
            aws_posix_operating_system_rule (bool): Whether to enable POSIX Operating System rule (default: False)
            waf_scope (Literal["REGIONAL", "CLOUDFRONT"]): Scope of the
            Web ACL - REGIONAL for ALB/API Gateway or CLOUDFRONT for CloudFront (default: "REGIONAL")

        Functionality:
            Creates and configures an AWS WAFv2 Web ACL with customizable rule sets for web application protection.
            Automatically includes IP reputation list rule and conditionally adds other
            security rules based on parameters.
            Builds a comprehensive rule set including rate limiting, common attack patterns, anonymous IP blocking,
            bad input detection, SQL injection protection, account takeover prevention, bot control, and
            application-specific rules.
            Configures CloudWatch metrics and sampled request logging for monitoring and analysis.

        Returns:
            wafv2.CfnWebACL: A configured WAFv2 Web ACL CloudFormation resource with the specified rules and settings
        """

        # 0. Reputation List. The first rule is enabled by default
        aws_ip_rep_list = self.__aws_ip_reputation_list()
        waf_rules = [aws_ip_rep_list]

        if rate_value:
            # 1. Custom Rate Limit
            rate_list = self.__rate_list(rate_value)
            waf_rules.append(rate_list)

        # 2. Common Rule
        aws_common_excluded_rules = None
        if aws_common_rule_ignore_list:
            aws_common_excluded_rules = [
                wafv2.CfnWebACL.ExcludedRuleProperty(name=rule_name) for rule_name in aws_common_rule_ignore_list
            ]
        if aws_common_rule:
            aws_common_rule = self.__aws_common_rule(aws_common_excluded_rules)
            waf_rules.append(aws_common_rule)

        if aws_anony_list:
            # 3. AnonymousIpList
            aws_anony_list = self.__aws_anonymous_list()
            waf_rules.append(aws_anony_list)

        if aws_bad_inputs_rule:
            # 4. Known Bad Inputs Rule
            aws_bad_inputs_rule = self.__aws_bad_inputs_rule()
            waf_rules.append(aws_bad_inputs_rule)

        if aws_sqli_rule:
            # 5. SQLi Rule
            aws_sqli_rule = self.__aws_sqli_rule()
            waf_rules.append(aws_sqli_rule)

        if aws_account_takeover_prevention:
            # 6. Account takeover prevention
            aws_account_takeover_prevention_rule = self.__aws_account_takeover_prevention(
                aws_account_takeover_prevention
            )
            waf_rules.append(aws_account_takeover_prevention_rule)

        if aws_bot_control_rule:
            # 7. Bot Control Rule
            if aws_bot_control_count:
                aws_bot_control_rule = self.__aws_bot_control_rule(count=True)
            else:
                aws_bot_control_rule = self.__aws_bot_control_rule()
            waf_rules.append(aws_bot_control_rule)

        if aws_php_application_rule:
            # 8. PHP Application Rule
            aws_php_application_rule = self.__aws_php_application_rule()
            waf_rules.append(aws_php_application_rule)

        if aws_posix_operating_system_rule:
            # 9. POSIX Operating System Rule
            aws_posix_operating_system_rule = self.__aws_posix_operating_system_rule()
            waf_rules.append(aws_posix_operating_system_rule)

        return wafv2.CfnWebACL(
            self,
            "WAF ACL",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            scope=waf_scope,
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True, metric_name="web-acl", sampled_requests_enabled=True
            ),
            name=name,
            rules=waf_rules,
        )

    def web_acl_association(self, resource_arn, web_acl_arn: str) -> wafv2.CfnWebACLAssociation:
        """Associates a WAF WebACL with a resource.

        Parameters:

        - resource_arn: ARN of the resource to associate the WebACL with.
        - web_acl_arn: ARN of the WebACL to associate.

        Creates an association between the WebACL and the resource.

        This applies the WebACL rules to the resource.

        Returns the CfnWebACLAssociation.
        """

        return wafv2.CfnWebACLAssociation(self, "ACLAssociation", resource_arn=resource_arn, web_acl_arn=web_acl_arn)

    def web_acl_log(self, web_acl_arn: str, log_group_name: str) -> wafv2.CfnLoggingConfiguration:
        """Creates a WAF logging configuration to send logs to CloudWatch Logs.

        Parameters:

        - web_acl_arn: ARN of the WAF WebACL to enable logging for.
        - log_group_name: Name of the CloudWatch Logs group to send logs to.

        It creates a CloudWatch Logs group with 1-week retention.

        It configures the WAF WebACL to send logs to the Logs group.

        Returns the CfnLoggingConfiguration to enable logging.
        """

        log_group = logs.LogGroup(
            self,
            id="web_acl_log_group",
            log_group_name=log_group_name,
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        return wafv2.CfnLoggingConfiguration(
            self,
            id="web_acl_cfn_log_configuration",
            log_destination_configs=[
                cdk.Stack.of(self).format_arn(
                    arn_format=cdk.ArnFormat.COLON_RESOURCE_NAME,
                    service="logs",
                    resource="log-group",
                    resource_name=log_group.log_group_name,
                )
            ],
            resource_arn=web_acl_arn,
        )
