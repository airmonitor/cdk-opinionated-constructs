# -*- coding: utf-8 -*-
"""Opinionated CDK construct to create Network load balancer.

Security parameters are set by default
"""
from constructs import Construct
import aws_cdk.aws_elasticloadbalancingv2 as albv2
import aws_cdk.aws_events_targets as albv2_targets
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_certificatemanager as certificate_manager


class NetworkLoadBalancer(Construct):
    """Create Network LB."""

    # pylint: disable=W0235
    def __init__(self, scope: Construct, construct_id: str):
        """

        :param scope:
        :param construct_id:
        """
        super().__init__(scope, construct_id)

    def create_nlb(self, load_balancer_name: str, vpc: ec2.Vpc) -> albv2.NetworkLoadBalancer:
        """Create Public Network Load Balancer.

        :param load_balancer_name: The name of Network Load Balancer
        :param vpc: CDK construct for VPC
        :return: CDK construct for Network Load Balancer
        """
        return albv2.NetworkLoadBalancer(
            self,
            id=f"{load_balancer_name}-load-balancer",
            cross_zone_enabled=True,
            internet_facing=True,
            load_balancer_name=load_balancer_name,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )

    @staticmethod
    def add_connections(
        nlb: albv2.NetworkLoadBalancer, certificates: list[certificate_manager.ICertificate], ports: list
    ):
        """Create NLB listener and target.

        :param nlb: The CDK construct for Network Load Balancer
        :param certificates: List of certificates from AWS Certificate Manager
        :param ports: List of dictionaries that contain connection details

        Example usage:
        add_connections(
            nlb=imported_network_load_balancer,
            certificates=[],
            ports=[
                {
                    "front_end_port": 6001,
                    "front_end_protocol": albv2.Protocol.UDP,
                    "targets": [service],
                    "back_end_port": 6001,
                    "back_end_protocol": albv2.Protocol.UDP,
                },
            ]
        )
        """
        for port_definition in ports:
            front_end_protocol: albv2.Protocol = port_definition["front_end_protocol"]
            front_end_port: int = port_definition["front_end_port"]

            if certificates:
                listener = nlb.add_listener(
                    id=f"{front_end_protocol}-{front_end_port}",
                    port=front_end_port,
                    protocol=front_end_protocol,
                    certificates=certificates,
                    ssl_policy=port_definition.get("ssl_policy"),
                )

            else:
                listener = nlb.add_listener(
                    id=f"{front_end_protocol}-{front_end_port}", port=front_end_port, protocol=front_end_protocol
                )

            back_end_protocol: albv2.Protocol = port_definition["back_end_protocol"]
            back_end_port: int = port_definition["back_end_port"]
            targets: list[albv2_targets] = port_definition["targets"]
            if port_definition.get("target_type") == "alb":
                target = listener.add_targets(
                    id=f"{back_end_protocol}-{back_end_port}",
                    targets=targets,
                    port=back_end_port,
                    preserve_client_ip=True,
                    health_check=albv2.HealthCheck(
                        enabled=True,
                        protocol=albv2.Protocol.HTTPS,
                        port=str(back_end_port),
                        path=port_definition.get("health_check_path", "/"),
                    ),
                )
            else:
                target = listener.add_targets(
                    id=f"{back_end_protocol}-{back_end_port}",
                    targets=targets,
                    port=back_end_port,
                    preserve_client_ip=True,
                )
                target.set_attribute("deregistration_delay.connection_termination.enabled", "true")

            if port_definition.get("stickiness"):
                target.set_attribute("stickiness.enabled", "true")
