"""Templates for the POV's two ZPA App Connectors: AWS CloudFormation (in the shape of the demo kit's zia_aws.py)
and an Azure Resource Manager template.

`pov-kit zpa template [--cloud aws|azure]` writes one for this POV. The Azure template follows Zscaler's own
Azure modules (github.com/zscaler/terraform-azurerm-zpa-app-connector-modules): the Marketplace image
zscaler / zscaler-private-access / zpa-con-azure with its purchase plan, a 4-vCPU size, and the provisioning-key
first boot from their user_data_zscaler.sh. Each VM has no public IP and an NSG that denies all inbound; sign-in is
by SSH key (zsroot), through the customer's own bastion if they need it.

AWS: The customer (or the SE in the customer's account) uploads it in the
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


TEST_ZONE, TEST_HOST = "zpov.internal", "pov-app"   # pov-app.zpov.internal, as products/zpa.py's TEST_APP
TEST_PAGE = ("<!doctype html><title>Zscaler POV test app</title><h1>Zscaler POV test app</h1>"
             "<p>You reached this private page through Zscaler Private Access. POV {pov}.</p>")
TEST_APP_BOOT = """#!/bin/bash
# Zscaler POV {pov}: a small private web page on port 80 for the POV to reach through ZPA. Nothing else.
mkdir -p /srv/pov-app
cat > /srv/pov-app/index.html <<'ZPOV_PAGE'
{page}
ZPOV_PAGE
cat > /etc/systemd/system/pov-app.service <<'ZPOV_UNIT'
[Unit]
Description=Zscaler POV test app
After=network-online.target
[Service]
ExecStart=/usr/bin/python3 -m http.server 80 --directory /srv/pov-app
Restart=always
[Install]
WantedBy=multi-user.target
ZPOV_UNIT
systemctl daemon-reload
systemctl enable --now pov-app
"""


def test_app_boot(pov_id):
    return TEST_APP_BOOT.format(pov=pov_id, page=TEST_PAGE.format(pov=pov_id))


def build(pov_id, prefix="ZPOV", instance_type="m5.large", test_app=False):
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
    tpl = {
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
    if test_app:
        add_test_app_aws(tpl, pov_id, tag)
    return tpl


def add_test_app_aws(tpl, pov_id, tag):
    """The kit's own POV app, when the customer hasn't named one: a small instance serving one page on port 80, which
    only the connectors may reach, at pov-app.zpov.internal in a private zone for this VPC only."""
    tpl["Description"] += " Also a small private test app (pov-app.zpov.internal) for the POV to reach."
    tpl["Parameters"]["TestAppAmi"] = param("AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                                            "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
                                            "Amazon Linux 2023 for the POV test app (the latest, from AWS's own list).")
    tpl["Metadata"]["AWS::CloudFormation::Interface"]["ParameterGroups"][1]["Parameters"].append("TestAppAmi")
    r = tpl["Resources"]
    r["TestAppOnlyFromConnectors"] = {"Type": "AWS::EC2::SecurityGroup", "Properties": {
        "GroupDescription": f"POV {pov_id} test app: port 80 from the POV's App Connectors only",
        "VpcId": {"Ref": "VpcId"},
        "SecurityGroupIngress": [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
                                  "SourceSecurityGroupId": {"Ref": "NoInbound"}}],
        "SecurityGroupEgress": [{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}], "Tags": tag}}
    r["TestApp"] = {"Type": "AWS::EC2::Instance", "Properties": {
        "ImageId": {"Ref": "TestAppAmi"}, "InstanceType": "t3.micro", "SubnetId": {"Ref": "SubnetId"},
        "SecurityGroupIds": [{"Ref": "TestAppOnlyFromConnectors"}], "IamInstanceProfile": {"Ref": "SsmProfile"},
        "MetadataOptions": {"HttpTokens": "required"},
        "UserData": {"Fn::Base64": test_app_boot(pov_id)},
        "Tags": [{"Key": "Name", "Value": {"Fn::Sub": "ZPOV test app ${AWS::StackName}"}}, {"Key": "zpov", "Value": pov_id}]}}
    r["TestAppZone"] = {"Type": "AWS::Route53::HostedZone", "Properties": {
        "Name": TEST_ZONE, "VPCs": [{"VPCId": {"Ref": "VpcId"}, "VPCRegion": {"Ref": "AWS::Region"}}],
        "HostedZoneConfig": {"Comment": f"Zscaler POV {pov_id}: the test app's private name"}}}
    r["TestAppRecord"] = {"Type": "AWS::Route53::RecordSet", "Properties": {
        "HostedZoneId": {"Ref": "TestAppZone"}, "Name": f"{TEST_HOST}.{TEST_ZONE}", "Type": "A", "TTL": "60",
        "ResourceRecords": [{"Fn::GetAtt": ["TestApp", "PrivateIp"]}]}}
    tpl["Outputs"]["TestApp"] = {"Value": f"http://{TEST_HOST}.{TEST_ZONE}/",
                                 "Description": "The POV test app, reachable only through ZPA."}


AZ_IMAGE = {"publisher": "zscaler", "offer": "zscaler-private-access", "sku": "zpa-con-azure"}
AZ_SIZES = ["Standard_D4s_v5", "Standard_D4s_v3", "Standard_D4s_v4", "Standard_D4as_v5", "Standard_F4s_v2",
            "Standard_D8s_v5", "Standard_D8as_v5"]
AZ_BOOT = ["#!/bin/bash\n# ZPA App Connector first boot for POV {pov}: enroll with the POV's provisioning key.\n"
           "systemctl stop zpa-connector 2>/dev/null || true\n"
           "echo \"", "\" > /opt/zscaler/var/provision_key\nchmod 644 /opt/zscaler/var/provision_key\n"
           "systemctl start zpa-connector\nnohup yum update -y > /var/log/yum-update.log 2>&1 &\n"]


def build_azure(pov_id, prefix="ZPOV", test_app=False):
    """An ARM template (deploy with 'Deploy a custom template' in the Azure portal, or az deployment group create).
    The Marketplace terms must be accepted once per subscription:
    az vm image terms accept --publisher zscaler --offer zscaler-private-access --plan zpa-con-azure"""
    tags = {"zpov": pov_id, "purpose": f"{prefix} App Connector"}
    boot = ("[base64(concat('" + AZ_BOOT[0].format(pov=pov_id).replace("'", "''") + "', parameters('provisioningKey'), '"
            + AZ_BOOT[1].replace("'", "''") + "'))]")
    vm = lambda n: [  # noqa: E731
        {"type": "Microsoft.Network/networkInterfaces", "apiVersion": "2023-09-01",
         "name": f"[concat(parameters('namePrefix'), '-nic{n}')]", "location": "[parameters('location')]", "tags": tags,
         "dependsOn": ["[resourceId('Microsoft.Network/networkSecurityGroups', concat(parameters('namePrefix'), '-nsg'))]"],
         "properties": {"ipConfigurations": [{"name": "ipconfig1", "properties": {
             "subnet": {"id": "[parameters('subnetId')]"}, "privateIPAllocationMethod": "Dynamic"}}],
             "networkSecurityGroup": {"id": "[resourceId('Microsoft.Network/networkSecurityGroups', "
                                            "concat(parameters('namePrefix'), '-nsg'))]"}}},
        {"type": "Microsoft.Compute/virtualMachines", "apiVersion": "2023-09-01",
         "name": f"[concat(parameters('namePrefix'), '-vm{n}')]", "location": "[parameters('location')]", "tags": tags,
         "zones": f"[if(parameters('useZones'), createArray('{n}'), json('null'))]",
         "dependsOn": [f"[resourceId('Microsoft.Network/networkInterfaces', concat(parameters('namePrefix'), '-nic{n}'))]"],
         "plan": {"name": AZ_IMAGE["sku"], "publisher": AZ_IMAGE["publisher"], "product": AZ_IMAGE["offer"]},
         "properties": {
             "hardwareProfile": {"vmSize": "[parameters('vmSize')]"},
             "storageProfile": {"imageReference": dict(AZ_IMAGE, version="[parameters('imageVersion')]"),
                                "osDisk": {"createOption": "FromImage", "managedDisk": {"storageAccountType": "Premium_LRS"},
                                           "deleteOption": "Delete"}},
             "osProfile": {"computerName": f"[concat(parameters('namePrefix'), '-ac{n}')]",
                           "adminUsername": "zsroot", "customData": boot,
                           "linuxConfiguration": {"disablePasswordAuthentication": True, "ssh": {"publicKeys": [{
                               "path": "/home/zsroot/.ssh/authorized_keys", "keyData": "[parameters('sshPublicKey')]"}]}}},
             "networkProfile": {"networkInterfaces": [{
                 "id": f"[resourceId('Microsoft.Network/networkInterfaces', concat(parameters('namePrefix'), '-nic{n}'))]",
                 "properties": {"deleteOption": "Delete"}}]}}}]
    tpl = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {"description": f"Zscaler POV {pov_id}: two ZPA App Connectors for the POV connector group. Delete "
                                    f"the resource group (or these resources) to remove them."},
        "parameters": {
            "provisioningKey": {"type": "securestring", "minLength": 20,
                                "metadata": {"description": "The POV's provisioning key (pov-kit zpa template --show-key)."}},
            "subnetId": {"type": "string", "metadata": {"description": "Resource ID of a subnet that reaches the POV "
                                                                       "application and the internet on TCP 443 (a NAT "
                                                                       "gateway is fine)."}},
            "sshPublicKey": {"type": "string", "metadata": {"description": "SSH public key for the zsroot user."}},
            "vmSize": {"type": "string", "defaultValue": AZ_SIZES[0], "allowedValues": AZ_SIZES},
            "imageVersion": {"type": "string", "defaultValue": "latest",
                             "metadata": {"description": "App Connector image version (latest, or a pinned one)."}},
            "useZones": {"type": "bool", "defaultValue": False,
                         "metadata": {"description": "Put the two connectors in availability zones 1 and 2."}},
            "namePrefix": {"type": "string", "defaultValue": f"{prefix.lower()}-ac-{pov_id[-4:]}", "maxLength": 40},
            "location": {"type": "string", "defaultValue": "[resourceGroup().location]"},
        },
        "resources": [
            {"type": "Microsoft.Network/networkSecurityGroups", "apiVersion": "2023-09-01",
             "name": "[concat(parameters('namePrefix'), '-nsg')]", "location": "[parameters('location')]", "tags": tags,
             "properties": {"securityRules": [{"name": "deny-all-inbound", "properties": {
                 "priority": 4000, "direction": "Inbound", "access": "Deny", "protocol": "*", "sourcePortRange": "*",
                 "destinationPortRange": "*", "sourceAddressPrefix": "*", "destinationAddressPrefix": "*",
                 "description": "App Connectors only make outbound connections."}}]}},
            *vm(1), *vm(2),
        ],
        "outputs": {"connectors": {"type": "string",
                                   "value": "[concat(parameters('namePrefix'), '-vm1, ', parameters('namePrefix'), '-vm2')]"}},
    }
    if test_app:
        add_test_app_azure(tpl, pov_id, tags)
    return tpl


def add_test_app_azure(tpl, pov_id, tags):
    """As add_test_app_aws: a small Ubuntu VM serving one page on port 80 to the virtual network only, at
    pov-app.zpov.internal in a private DNS zone linked to the connectors' virtual network."""
    tpl["metadata"]["description"] += " Also a small private test app (pov-app.zpov.internal) for the POV to reach."
    vnet = "[substring(parameters('subnetId'), 0, indexOf(parameters('subnetId'), '/subnets/'))]"
    name = "[concat(parameters('namePrefix'), '-app')]"
    nic = "[concat(parameters('namePrefix'), '-app-nic')]"
    nsg = "[concat(parameters('namePrefix'), '-app-nsg')]"
    boot = "[base64('" + test_app_boot(pov_id).replace("'", "''") + "')]"
    tpl["resources"] += [
        {"type": "Microsoft.Network/networkSecurityGroups", "apiVersion": "2023-09-01", "name": nsg,
         "location": "[parameters('location')]", "tags": tags, "properties": {"securityRules": [
             {"name": "http-from-vnet", "properties": {
                 "priority": 1000, "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "sourcePortRange": "*",
                 "destinationPortRange": "80", "sourceAddressPrefix": "VirtualNetwork", "destinationAddressPrefix": "*",
                 "description": "The POV's App Connectors reach the test app."}},
             {"name": "deny-all-inbound", "properties": {
                 "priority": 4000, "direction": "Inbound", "access": "Deny", "protocol": "*", "sourcePortRange": "*",
                 "destinationPortRange": "*", "sourceAddressPrefix": "*", "destinationAddressPrefix": "*"}}]}},
        {"type": "Microsoft.Network/networkInterfaces", "apiVersion": "2023-09-01", "name": nic,
         "location": "[parameters('location')]", "tags": tags,
         "dependsOn": [f"[resourceId('Microsoft.Network/networkSecurityGroups', {nsg[1:-1]})]"],
         "properties": {"ipConfigurations": [{"name": "ipconfig1", "properties": {
             "subnet": {"id": "[parameters('subnetId')]"}, "privateIPAllocationMethod": "Dynamic"}}],
             "networkSecurityGroup": {"id": f"[resourceId('Microsoft.Network/networkSecurityGroups', {nsg[1:-1]})]"}}},
        {"type": "Microsoft.Compute/virtualMachines", "apiVersion": "2023-09-01", "name": name,
         "location": "[parameters('location')]", "tags": tags,
         "dependsOn": [f"[resourceId('Microsoft.Network/networkInterfaces', {nic[1:-1]})]"],
         "properties": {
             "hardwareProfile": {"vmSize": "Standard_B1s"},
             "storageProfile": {"imageReference": {"publisher": "Canonical", "offer": "0001-com-ubuntu-server-jammy",
                                                   "sku": "22_04-lts-gen2", "version": "latest"},
                                "osDisk": {"createOption": "FromImage", "deleteOption": "Delete",
                                           "managedDisk": {"storageAccountType": "Standard_LRS"}}},
             "osProfile": {"computerName": "pov-app", "adminUsername": "zpovadmin", "customData": boot,
                           "linuxConfiguration": {"disablePasswordAuthentication": True, "ssh": {"publicKeys": [{
                               "path": "/home/zpovadmin/.ssh/authorized_keys",
                               "keyData": "[parameters('sshPublicKey')]"}]}}},
             "networkProfile": {"networkInterfaces": [{
                 "id": f"[resourceId('Microsoft.Network/networkInterfaces', {nic[1:-1]})]",
                 "properties": {"deleteOption": "Delete"}}]}}},
        {"type": "Microsoft.Network/privateDnsZones", "apiVersion": "2020-06-01", "name": TEST_ZONE,
         "location": "global", "tags": tags},
        {"type": "Microsoft.Network/privateDnsZones/virtualNetworkLinks", "apiVersion": "2020-06-01",
         "name": f"[concat('{TEST_ZONE}/', parameters('namePrefix'), '-link')]", "location": "global",
         "dependsOn": [f"[resourceId('Microsoft.Network/privateDnsZones', '{TEST_ZONE}')]"],
         "properties": {"registrationEnabled": False, "virtualNetwork": {"id": vnet}}},
        {"type": "Microsoft.Network/privateDnsZones/A", "apiVersion": "2020-06-01", "name": f"{TEST_ZONE}/{TEST_HOST}",
         "dependsOn": [f"[resourceId('Microsoft.Network/privateDnsZones', '{TEST_ZONE}')]",
                       f"[resourceId('Microsoft.Network/networkInterfaces', {nic[1:-1]})]"],
         "properties": {"ttl": 60, "aRecords": [{"ipv4Address":
             f"[reference(resourceId('Microsoft.Network/networkInterfaces', {nic[1:-1]})).ipConfigurations[0].properties.privateIPAddress]"}]}},
    ]
    tpl["outputs"]["testApp"] = {"type": "string", "value": f"http://{TEST_HOST}.{TEST_ZONE}/"}


def write(path, pov_id, prefix="ZPOV", cloud="aws", test_app=False):
    tpl = build_azure(pov_id, prefix, test_app) if cloud == "azure" else build(pov_id, prefix, test_app=test_app)
    path.write_text(json.dumps(tpl, indent=2), encoding="utf-8")
    return path
