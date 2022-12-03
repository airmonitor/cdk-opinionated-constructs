# -*- coding: utf-8 -*-
"""Opinionated CDK construct to create AWS WAFv2.

Security parameters, logging are set by default
"""
from constructs import Construct
import aws_cdk as cdk
import aws_cdk.aws_wafv2 as wafv2
from aws_cdk import aws_logs as logs

from typing import Optional, Any, Dict, Literal, Union


class WAFv2(Construct):
    """Implement a v2 WAF where logs are sent to the AWS CloudWatch logs."""

    # pylint: disable=W0235
    def __init__(self, scope: Construct, construct_id: str) -> None:
        super().__init__(scope, construct_id)

    def web_acl(
        self,
        name: str,
        rate_value: Union[int, None],
        aws_common_rule: bool = True,
        aws_common_rule_ignore_list: Optional[list] = None,
        aws_anony_list: bool = False,
        aws_bad_inputs_rule: bool = False,
        aws_sqli_rule: bool = False,
        aws_account_takeover_prevention: Union[bool, Dict[Any, Any]] = False,
        waf_scope: Literal["REGIONAL", "CLOUDFRONT"] = "REGIONAL",
    ) -> wafv2.CfnWebACL:
        """Create AWS WAF with opinionated default rules.

        The minimal configuration will create WAF ACL with aws_reputation_list

        :param aws_common_rule_ignore_list: List of strings that contain rules to be ignored.
        :param aws_account_takeover_prevention: The definition for account takeover prevention rule
        :param aws_sqli_rule: The WAF managed rule by AWS AWS-AWSManagedRulesSQLiRuleSet
        :param aws_bad_inputs_rule: The WAF managed rule by AWS AWS-AWSManagedRulesKnownBadInputsRuleSet
        :param aws_anony_list: The WAF managed rule by AWS AWS-AWSManagedRulesAnonymousIpList
        :param aws_common_rule: The WAF managed rule by AWS AWS-AWSManagedRulesCommonRuleSet
        :param rate_value: The number of packets per seconds for custom rate limiting
        :param waf_scope: The WAF scope, it could be regional for API GW, Cognito and ALB or
        CLOUDFRONT for cloudfront distributions
        :param name: Then name of WAF ACL
        :return:
        """

        # 0. Reputation List
        aws_ip_rep_list = wafv2.CfnWebACL.RuleProperty(
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
        waf_rules = [aws_ip_rep_list]

        if rate_value:
            # 1. Custom Rate Limit
            rate_list = wafv2.CfnWebACL.RuleProperty(
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

            waf_rules.append(rate_list)

        # 2. Common Rule
        aws_common_excluded_rules = None
        if aws_common_rule_ignore_list:
            aws_common_excluded_rules = [
                wafv2.CfnWebACL.ExcludedRuleProperty(name=rule_name) for rule_name in aws_common_rule_ignore_list
            ]
        if aws_common_rule:
            aws_common_rule = wafv2.CfnWebACL.RuleProperty(
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
            waf_rules.append(aws_common_rule)

        if aws_anony_list:
            # 3. AnonymousIpList
            aws_anony_list = wafv2.CfnWebACL.RuleProperty(
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
            waf_rules.append(aws_anony_list)

        if aws_bad_inputs_rule:
            # 4. Known Bad Inputs Rule
            aws_bad_inputs_rule = wafv2.CfnWebACL.RuleProperty(
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
            waf_rules.append(aws_bad_inputs_rule)

        if aws_sqli_rule:
            # 5. SQLi Rule
            aws_sqli_rule = wafv2.CfnWebACL.RuleProperty(
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
            waf_rules.append(aws_sqli_rule)

        if aws_account_takeover_prevention:
            # 6. Account takeover prevention
            aws_account_takeover_prevention_rule = wafv2.CfnWebACL.RuleProperty(
                name="AWS-AWSManagedRulesATPRuleSet",
                priority=6,
                override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                statement=wafv2.CfnWebACL.StatementProperty(
                    managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                        name="AWSManagedRulesATPRuleSet",
                        vendor_name="AWS",
                        managed_rule_group_configs=[
                            wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                login_path=aws_account_takeover_prevention["login_path"],  # type: ignore
                            ),
                            wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                password_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier=aws_account_takeover_prevention["password_field"]  # type: ignore
                                ),
                            ),
                            wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                payload_type="FORM_ENCODED",
                            ),
                            wafv2.CfnWebACL.ManagedRuleGroupConfigProperty(
                                username_field=wafv2.CfnWebACL.FieldIdentifierProperty(
                                    identifier=aws_account_takeover_prevention["username_field"]  # type: ignore
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
            waf_rules.append(aws_account_takeover_prevention_rule)

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
        """Associate AWS Resource with WAF.

        :param resource_arn: The ARN of resource that will be protected by WAF
        :param web_acl_arn: The WEB Application Access Control List ARN
        :return: wafv2.CfnWebACLAssociation
        """
        return wafv2.CfnWebACLAssociation(self, "ACLAssociation", resource_arn=resource_arn, web_acl_arn=web_acl_arn)

    def web_acl_log(self, web_acl_arn: str, log_group_name: str) -> wafv2.CfnLoggingConfiguration:
        """Configure provided log group as a target for WAF log destination.

        :param web_acl_arn: The WEB Application Access Control List ARN
        :param log_group_name: The name of log group
        :return: AWS CDK wafv2.CfnLoggingConfiguration
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
