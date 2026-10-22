"""CloudFormation template for the POV's two ZPA App Connectors on AWS, in the shape of the demo kit's zia_aws.py.

`pov-kit zpa template` writes it for this POV. The customer (or the SE in the customer's account) uploads it in the
CloudFormation console; deleting the stack removes everything it made.

The stack: two instances of Zscaler's App Connector image (the AMI from the customer's AWS Marketplace subscription,
entered as a parameter) in a subnet the customer chooses, a security group with no inbound ports, and an SSM role for
console access without SSH. First boot writes the provisioning key to /opt/zscaler/var/provision_key and starts the
zpa-connector service, the documented Linux enrollment steps.

The provisioning key is a stack parameter marked NoEcho, so CloudFormation hides it, but it is readable in each
instance's user data by anyone allowed to see instance attributes. The POV's key enrolls at most two connectors and
teardown deletes it, which limits what a copy of it is worth.
"""
from __future__ import annotations

import json

USER_DATA = """#!/bin/bash
# ZPA App Connector first boot for POV ${PovId}: enroll with the POV's provisioning key.
set -u
for i in $(seq 1 60); do systemctl list-unit-files | grep -q zpa-connector && break; sleep 10; done
systemctl stop zpa-connector || true
rm -f /opt/zscaler/var/*
install -m 644 /dev/null /opt/zscaler/var/provision_key
cat > /opt/zscaler/var/provision_key <<'ZPOV_KEY'
${ProvisioningKey}
ZPOV_KEY
systemctl enable zpa-connector
systemctl start zpa-connector
"""


def param(type_, default=None, desc="", **kw):
    p = {"Type": type_, "Description": desc, **kw}
    if default is not None:
        p["Default"] = default
    return p


def build(pov_id, prefix="ZPOV", instance_type="m5.large"):
    tag = [{"Key": "Name", "Value": {"Fn::Sub": f"{prefix} App Connector ${{AWS::StackName}}"}},
           {"Key": "zpov", "Value": pov_id}]
    instance = lambda n: {  # noqa: E731
        "Type": "AWS::EC2::Instance",
        "Properties": {"ImageId": {"Ref": "AppConnectorAmi"}, "InstanceType": {"Ref": "InstanceType"},
                       "SubnetId": {"Ref": "SubnetId"}, "SecurityGroupIds": [{"Ref": "NoInbound"}],
                       "IamInstanceProfile": {"Ref": "SsmProfile"},
                       "MetadataOptions": {"HttpTokens": "required"},
                       "UserData": {"Fn::Base64": {"Fn::Sub": [USER_DATA, {"PovId": pov_id}]}},
                       "Tags": tag + [{"Key": "zpov-connector", "Value": str(n)}]}}
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"Zscaler POV {pov_id}: two ZPA App Connectors for the POV connector group. Delete the stack to "
                       f"remove them.",
        "Metadata": {"AWS::CloudFormation::Interface": {"ParameterGroups": [
            {"Label": {"default": "Zscaler"}, "Parameters": ["ProvisioningKey", "AppConnectorAmi"]},
            {"Label": {"default": "AWS"}, "Parameters": ["VpcId", "SubnetId", "InstanceType"]}]}},
        "Parameters": {
            "ProvisioningKey": param("String", desc="The POV's provisioning key (pov-kit zpa template --show-key prints it).",
                                     NoEcho=True, MinLength=20),
            "AppConnectorAmi": param("AWS::EC2::Image::Id",
                                     desc="Zscaler App Connector AMI from your AWS Marketplace subscription in this region."),
            "VpcId": param("AWS::EC2::VPC::Id", desc="The VPC of the POV application."),
            "SubnetId": param("AWS::EC2::Subnet::Id", desc="A subnet that reaches the application and the internet on "
                                                           "TCP 443 (through a NAT gateway is fine)."),
            "InstanceType": param("String", instance_type, "Size per Zscaler's App Connector sizing guidance."),
        },
        "Resources": {
            "NoInbound": {"Type": "AWS::EC2::SecurityGroup",
                          "Properties": {"GroupDescription": f"POV {pov_id} App Connectors: no inbound, all outbound",
                                         "VpcId": {"Ref": "VpcId"},
                                         "SecurityGroupEgress": [{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}],
                                         "Tags": tag}},
            "SsmRole": {"Type": "AWS::IAM::Role",
                        "Properties": {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
                            "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"], "Tags": tag}},
            "SsmProfile": {"Type": "AWS::IAM::InstanceProfile", "Properties": {"Roles": [{"Ref": "SsmRole"}]}},
            "Connector1": instance(1),
            "Connector2": instance(2),
        },
        "Outputs": {
            "Connectors": {"Value": {"Fn::Join": [", ", [{"Ref": "Connector1"}, {"Ref": "Connector2"}]]},
                           "Description": "Instance IDs. They appear in the ZPA console's POV connector group within "
                                          "about 15 minutes."},
        },
    }


def write(path, pov_id, prefix="ZPOV"):
    path.write_text(json.dumps(build(pov_id, prefix), indent=2), encoding="utf-8")
    return path
