"""CloudFormation template for a POV traffic generator on AWS: a Windows pilot device that sends ZIA test traffic.

`pov-kit traffic aws` (or the console: Next steps > Traffic generator) writes a template filled in for this POV (cloud,
user domain, pilot user). Upload it in the CloudFormation console: no AWS CLI or AWS keys on your laptop. One stack
holds everything; deleting the stack removes it all.

The stack: its own small VPC (or an existing subnet), a security group with no inbound ports, an SSM role (connect
through Fleet Manager remote desktop, nothing exposed), one Windows Server 2022 instance whose first-boot script runs
the kit's pilot-device setup (the pinned Client Connector installer, checked by SHA-256 and Zscaler's signature,
installed for the POV's cloud, domain and user, then the POV kit), and two scheduled tasks: a traffic round every N
minutes (sent only once traffic is confirmed to go through Zscaler) and `pov-probe traffic check` at startup.
Optionally a weekday start / nightly stop to keep costs down.

No secrets are in the template: you sign in to Client Connector once, by hand, as the pilot user.
"""
from __future__ import annotations

import json

AMI_PARAM = "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base"
NAME = "Zscaler POV traffic generator"
REPO = "Paulie631/zscaler-pov-kit"

# First-boot script (EC2Launch runs it as SYSTEM). ${...} are CloudFormation parameters; PowerShell variables
# deliberately never use braces so Fn::Sub leaves them alone.
USER_DATA = r"""<powershell>
$ErrorActionPreference = "Continue"
$root = "C:\ZPOV"
New-Item -ItemType Directory -Force -Path $root, "$root\home" | Out-Null
Start-Transcript -Path "$root\setup.log" -Append
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
"Zscaler POV ${PovId} traffic generator: first-boot setup for pilot user ${PilotUser}"

# 1. The kit's pilot-device setup: pinned Client Connector (SHA-256 + Zscaler signature) for this POV, then the POV
#    probe with the POV's probe pack (so the traffic follows the POV's criteria). The probe lives under C:\ZPOV\home
#    so the scheduled tasks (as SYSTEM) and a remote desktop user share it.
$env:USERPROFILE = "$root\home"; $env:HOME = "$root\home"
$env:UV_INSTALL_DIR = "$root\home\.local\bin"; $env:UV_CACHE_DIR = "$root\uv-cache"; $env:UV_PYTHON_INSTALL_DIR = "$root\python"
$env:ZPOV_KIT_REPO = "${KitRepo}"
$env:ZPOV_PROBE_HOME = "$root\home\.zscaler-pov-probe"
New-Item -ItemType Directory -Force -Path $env:ZPOV_PROBE_HOME | Out-Null
$pack = "__PACK_B64__"
if ($pack) {
  $env:ZPOV_PACK_FILE = "$env:ZPOV_PROBE_HOME\pack-download.json"
  [IO.File]::WriteAllBytes($env:ZPOV_PACK_FILE, [Convert]::FromBase64String($pack))
}
$name, $domain = "${PilotUser}".Split("@", 2)
try {
  & ([scriptblock]::Create((Invoke-RestMethod "https://github.com/${KitRepo}/releases/latest/download/zcc-setup.ps1"))) -Cloud "${ZccCloudName}" -Domain $domain -User $name
} catch { "Pilot device setup stopped: $_" }

# 2. A wrapper so the tasks and the desktop shortcut run the probe from C:\ZPOV with its logs there too
$kit = "$root\home\.zscaler-pov-probe\app\pov-probe.cmd"
$envs = "@echo off`r`nset USERPROFILE=$root\home`r`nset ZPOV_PROBE_HOME=$root\home\.zscaler-pov-probe`r`nset UV_CACHE_DIR=$root\uv-cache`r`nset UV_PYTHON_INSTALL_DIR=$root\python`r`nset PYTHONUTF8=1`r`nset NO_COLOR=1`r`n"
Set-Content -Encoding ascii -Path "$root\traffic.cmd" -Value ($envs + "echo ==== %DATE% %TIME% >> `"$root\traffic.log`"`r`n`"$kit`" traffic %* >> `"$root\traffic.log`" 2>&1`r`n")

# 2b. The device's own test runner (pov-probe ui) for whoever signs in: the POV's tests, guided demos and Show it,
#     opened at sign-in and from the desktop. It runs as the signed-in user (so pages open in their browser), with
#     the shared probe home.
$ui = "@echo off`r`nset PATH=$root\home\.local\bin;%PATH%`r`nset ZPOV_PROBE_HOME=$root\home\.zscaler-pov-probe`r`nset UV_CACHE_DIR=$root\uv-cache`r`nset UV_PYTHON_INSTALL_DIR=$root\python`r`nset PYTHONUTF8=1`r`n`"$kit`" ui %*`r`n"
Set-Content -Encoding ascii -Path "$root\tests.cmd" -Value $ui

# 3. Scheduled tasks (as SYSTEM, so they run with nobody signed in to Windows)
$a = New-ScheduledTaskAction -Execute "$root\traffic.cmd" -Argument "run --count ${RequestsPerType}"
$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) -RepetitionInterval (New-TimeSpan -Minutes ${TrafficEveryMinutes})
Register-ScheduledTask -TaskName "Zscaler POV traffic" -Action $a -Trigger $t -User "SYSTEM" -RunLevel Highest -Force
$a2 = New-ScheduledTaskAction -Execute "$root\traffic.cmd" -Argument "check --cloud ${ZccCloudName}"
Register-ScheduledTask -TaskName "Zscaler POV traffic check" -Action $a2 -Trigger (New-ScheduledTaskTrigger -AtStartup) -User "SYSTEM" -RunLevel Highest -Force

# 4. Desktop shortcuts for whoever signs in over remote desktop
$sh = New-Object -ComObject WScript.Shell
foreach ($s in @(@("POV traffic log", "$root\traffic.log"), @("POV setup log", "$root\setup.log"))) {
  $l = $sh.CreateShortcut("C:\Users\Public\Desktop\" + $s[0] + ".lnk"); $l.TargetPath = $s[1]; $l.Save()
}
foreach ($d in @("C:\Users\Public\Desktop", "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")) {
  $l = $sh.CreateShortcut("$d\POV device tests.lnk"); $l.TargetPath = "$root\tests.cmd"; $l.WindowStyle = 7; $l.Save()
}
New-Item -ItemType File -Force -Path "$root\traffic.log" | Out-Null
# 5. This box is single-purpose and only administrators can sign in, so local Users may modify C:\ZPOV.
icacls $root /grant "*S-1-5-32-545:(OI)(CI)M" /T /C /Q | Out-Null
"Setup finished. Traffic starts once Client Connector is signed in as ${PilotUser}."
Stop-Transcript
</powershell>
<persist>false</persist>
"""


def param(type_, default, desc, **kw):
    p = {"Type": type_, "Default": default, "Description": desc}
    p.update(kw)
    return p


def build(pov_id, cloud, pilot_user, every=30, per_type=4, schedule=True, repo=REPO, pack=None):
    """pack: the POV's probe pack, written into the first-boot script (no secrets in it), so the generator's traffic
    follows the POV's criteria and `pov-probe test` can run there too."""
    if "@" not in (pilot_user or ""):
        raise ValueError("The pilot user is an email address.")
    import base64
    b64 = base64.b64encode(json.dumps(pack, separators=(",", ":")).encode()).decode() if pack else ""
    if len(b64) > 9000:   # EC2 user data is 16 KB in all; a pack that large stays off (install it by hand)
        b64 = ""
    user_data = USER_DATA.replace("__PACK_B64__", b64)
    tags = [{"Key": "Name", "Value": f"{NAME} ({pov_id})"}, {"Key": "zpov", "Value": pov_id}]
    params = {
        "PovId": param("String", pov_id, "The POV this generator belongs to (for names and tags)."),
        "PilotUser": param("String", pilot_user, "The pilot user Client Connector signs in as (a POV test user or a "
                                                 "named pilot user). Sign in once, over Fleet Manager remote desktop."),
        "ZccCloudName": param("String", cloud, "The customer's Zscaler cloud, for example zscalertwo."),
        "KitRepo": param("String", repo, "Where the instance gets the POV kit and its pinned Client Connector installer."),
        "TrafficEveryMinutes": param("Number", every, "Minutes between traffic rounds.", MinValue=15, MaxValue=1440),
        "RequestsPerType": param("Number", per_type, "Requests per traffic type per round.", MinValue=1, MaxValue=20),
        "InstanceType": param("String", "t3.medium", "Instance size.", AllowedValues=["t3.medium", "t3.large", "m6i.large"]),
        "WindowsAmi": param("AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>", AMI_PARAM,
                            "Latest Windows Server 2022 image (looked up at deploy time)."),
        "NetworkMode": param("String", "CreateVpc", "CreateVpc: its own VPC with direct internet access (recommended, "
                             "so no corporate inspection sits in front of Zscaler). ExistingSubnet: use the two "
                             "parameters below.", AllowedValues=["CreateVpc", "ExistingSubnet"]),
        "ExistingVpcId": param("String", "", "Only with ExistingSubnet: the VPC id."),
        "ExistingSubnetId": param("String", "", "Only with ExistingSubnet: a subnet with a direct internet route."),
        "ExistingInstanceProfile": param("String", "", "Optional: an existing instance profile with "
                                         "AmazonSSMManagedInstanceCore, if this account doesn't let stacks create IAM roles."),
        "KeyPairName": param("String", "", "Optional: an EC2 key pair, to get the Administrator password for remote desktop."),
        "WeekdaySchedule": param("String", "true" if schedule else "false", "Start the instance at 7am and stop it at "
                                 "9pm (New York time), weekdays start only. Needs IAM.", AllowedValues=["true", "false"]),
    }
    cond = {
        "CreateVpc": {"Fn::Equals": [{"Ref": "NetworkMode"}, "CreateVpc"]},
        "CreateRole": {"Fn::Equals": [{"Ref": "ExistingInstanceProfile"}, ""]},
        "HasKey": {"Fn::Not": [{"Fn::Equals": [{"Ref": "KeyPairName"}, ""]}]},
        "Schedule": {"Fn::And": [{"Fn::Equals": [{"Ref": "WeekdaySchedule"}, "true"]}, {"Condition": "CreateRole"}]},
    }
    res = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Condition": "CreateVpc",
                "Properties": {"CidrBlock": "10.77.0.0/16", "EnableDnsSupport": True, "EnableDnsHostnames": True,
                               "Tags": tags}},
        "Igw": {"Type": "AWS::EC2::InternetGateway", "Condition": "CreateVpc", "Properties": {"Tags": tags}},
        "IgwAttach": {"Type": "AWS::EC2::VPCGatewayAttachment", "Condition": "CreateVpc",
                      "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}}},
        "Subnet": {"Type": "AWS::EC2::Subnet", "Condition": "CreateVpc",
                   "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.77.1.0/24", "MapPublicIpOnLaunch": True,
                                  "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]}, "Tags": tags}},
        "RouteTable": {"Type": "AWS::EC2::RouteTable", "Condition": "CreateVpc",
                       "Properties": {"VpcId": {"Ref": "Vpc"}, "Tags": tags}},
        "DefaultRoute": {"Type": "AWS::EC2::Route", "Condition": "CreateVpc", "DependsOn": "IgwAttach",
                         "Properties": {"RouteTableId": {"Ref": "RouteTable"}, "DestinationCidrBlock": "0.0.0.0/0",
                                        "GatewayId": {"Ref": "Igw"}}},
        "SubnetRoutes": {"Type": "AWS::EC2::SubnetRouteTableAssociation", "Condition": "CreateVpc",
                         "Properties": {"SubnetId": {"Ref": "Subnet"}, "RouteTableId": {"Ref": "RouteTable"}}},
        "NoInbound": {"Type": "AWS::EC2::SecurityGroup",
                      "Properties": {"GroupDescription": "POV traffic generator: no inbound; connect with Fleet Manager",
                                     "VpcId": {"Fn::If": ["CreateVpc", {"Ref": "Vpc"}, {"Ref": "ExistingVpcId"}]},
                                     "SecurityGroupEgress": [{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}],
                                     "Tags": tags}},
        "SsmRole": {"Type": "AWS::IAM::Role", "Condition": "CreateRole",
                    "Properties": {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
                        "ManagedPolicyArns": [{"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"}],
                        "Tags": tags}},
        "SsmProfile": {"Type": "AWS::IAM::InstanceProfile", "Condition": "CreateRole",
                       "Properties": {"Roles": [{"Ref": "SsmRole"}]}},
        "Generator": {"Type": "AWS::EC2::Instance", "DependsOn": [],
                      "Properties": {
                          "ImageId": {"Ref": "WindowsAmi"}, "InstanceType": {"Ref": "InstanceType"},
                          "SubnetId": {"Fn::If": ["CreateVpc", {"Ref": "Subnet"}, {"Ref": "ExistingSubnetId"}]},
                          "SecurityGroupIds": [{"Ref": "NoInbound"}],
                          "IamInstanceProfile": {"Fn::If": ["CreateRole", {"Ref": "SsmProfile"}, {"Ref": "ExistingInstanceProfile"}]},
                          "KeyName": {"Fn::If": ["HasKey", {"Ref": "KeyPairName"}, {"Ref": "AWS::NoValue"}]},
                          "MetadataOptions": {"HttpTokens": "required"},
                          "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 60, "VolumeType": "gp3",
                                                                                       "Encrypted": True}}],
                          "UserData": {"Fn::Base64": {"Fn::Sub": user_data}},
                          "Tags": tags}},
        "SchedulerRole": {"Type": "AWS::IAM::Role", "Condition": "Schedule",
                          "Properties": {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
                              {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
                              "Policies": [{"PolicyName": "start-stop-generator", "PolicyDocument": {
                                  "Version": "2012-10-17", "Statement": [{
                                      "Effect": "Allow", "Action": ["ec2:StartInstances", "ec2:StopInstances"],
                                      "Resource": {"Fn::Sub": "arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/${Generator}"}}]}}],
                              "Tags": tags}},
        "MorningStart": {"Type": "AWS::Scheduler::Schedule", "Condition": "Schedule",
                         "Properties": {"Description": "POV traffic generator: start weekdays 7am New York",
                                        "ScheduleExpression": "cron(0 7 ? * MON-FRI *)",
                                        "ScheduleExpressionTimezone": "America/New_York",
                                        "FlexibleTimeWindow": {"Mode": "OFF"},
                                        "Target": {"Arn": "arn:aws:scheduler:::aws-sdk:ec2:startInstances",
                                                   "RoleArn": {"Fn::GetAtt": ["SchedulerRole", "Arn"]},
                                                   "Input": {"Fn::Sub": '{"InstanceIds": ["${Generator}"]}'}}}},
        "NightlyStop": {"Type": "AWS::Scheduler::Schedule", "Condition": "Schedule",
                        "Properties": {"Description": "POV traffic generator: stop nightly 9pm New York",
                                       "ScheduleExpression": "cron(0 21 * * ? *)",
                                       "ScheduleExpressionTimezone": "America/New_York",
                                       "FlexibleTimeWindow": {"Mode": "OFF"},
                                       "Target": {"Arn": "arn:aws:scheduler:::aws-sdk:ec2:stopInstances",
                                                  "RoleArn": {"Fn::GetAtt": ["SchedulerRole", "Arn"]},
                                                  "Input": {"Fn::Sub": '{"InstanceIds": ["${Generator}"]}'}}}},
    }
    del res["Generator"]["DependsOn"]
    out = {
        "InstanceId": {"Value": {"Ref": "Generator"}},
        "ConnectWithFleetManager": {
            "Description": "Open, then Node actions > Connect > Connect with Remote Desktop. Single sign-on is offered only "
                           "if you signed in to AWS with IAM Identity Center; otherwise choose User credentials and set an "
                           "Administrator password first (see SetAdministratorPassword).",
            "Value": {"Fn::Sub": "https://${AWS::Region}.console.aws.amazon.com/systems-manager/fleet-manager/"
                                 "managed-nodes/${Generator}/general?region=${AWS::Region}"}},
        "SetAdministratorPassword": {
            "Description": "Only if Fleet Manager offers no single sign-on: Systems Manager > Session Manager > Start "
                           "session on this instance, run this, type a password (not echoed), then Connect with Remote "
                           "Desktop > User credentials as Administrator",
            "Value": "$p = Read-Host -AsSecureString 'New password'; Set-LocalUser -Name Administrator -Password $p; "
                     "Enable-LocalUser Administrator"},
        "NextSteps": {"Value": {"Fn::Sub": "Wait about 10 minutes, connect with Fleet Manager remote desktop, sign in "
                                           "to Client Connector as ${PilotUser} (a test user's password: Pilot users "
                                           "in the POV console, or pov-kit users --show on the SE's laptop), then open "
                                           "'POV traffic log' on the desktop."}},
    }
    return {"AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"{NAME} for POV {pov_id}, pilot user {pilot_user}. Delete the stack to remove everything.",
            "Metadata": {"AWS::CloudFormation::Interface": {"ParameterGroups": [
                {"Label": {"default": "Zscaler"}, "Parameters": ["PovId", "PilotUser", "ZccCloudName"]},
                {"Label": {"default": "Traffic"}, "Parameters": ["TrafficEveryMinutes", "RequestsPerType", "KitRepo"]},
                {"Label": {"default": "AWS"}, "Parameters": ["InstanceType", "WeekdaySchedule", "NetworkMode", "ExistingVpcId",
                                                              "ExistingSubnetId", "ExistingInstanceProfile", "KeyPairName", "WindowsAmi"]}]}},
            "Parameters": params, "Conditions": cond, "Resources": res, "Outputs": out,
            "Rules": {"ExistingSubnetNeedsIds": {
                "RuleCondition": {"Fn::Equals": [{"Ref": "NetworkMode"}, "ExistingSubnet"]},
                "Assertions": [{"Assert": {"Fn::And": [
                    {"Fn::Not": [{"Fn::Equals": [{"Ref": "ExistingVpcId"}, ""]}]},
                    {"Fn::Not": [{"Fn::Equals": [{"Ref": "ExistingSubnetId"}, ""]}]}]},
                    "AssertDescription": "With NetworkMode ExistingSubnet, fill in ExistingVpcId and ExistingSubnetId."}]}}}


def for_pov(pov, pilot_user=None, every=30, per_type=4, schedule=True):
    """-> (file name, template dict) for this POV: its cloud and a pilot user (default: the first one)."""
    from . import device_setup
    from .core import KitError
    cloud = device_setup.cloud(pov)
    if not cloud:
        raise KitError("Set the Zscaler cloud first (Next steps > Set up a pilot device > Detect).")
    users = device_setup.users(pov)
    user = (pilot_user or (users[0] if users else "")).strip().lower()
    if not user:
        raise KitError("This POV has no pilot users yet: name them, or Apply so its test users exist.")
    device_setup.split(user)
    from . import evidence
    return f"zpov-traffic-{pov.id}.json", build(pov.id, cloud, user, every, per_type, schedule,
                                                 pack=evidence.probe_pack(pov))


def write(path, pov, **kw):
    from pathlib import Path
    name, t = for_pov(pov, **kw)
    out = Path(path or name)
    out.write_text(json.dumps(t, indent=2), encoding="utf-8")
    return out


CLOUDSHARE = r"""# Zscaler POV {pov}: the ZIA traffic generator on a CloudShare Windows pilot (or any Windows pilot device).
# Run it after the pilot device setup (Client Connector signed in as a pilot user), in PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\{name}
# It installs the POV probe if it isn't there, installs this POV's probe pack (so the traffic follows the POV's
# criteria), checks this device is in the POV's tenant, then sends a round of traffic every {every} minutes while
# you're signed in. No keys; nothing in the tenant changes. Stop it: pov-probe.cmd traffic schedule --remove
$ErrorActionPreference = "Stop"
$Repo = if ($env:ZPOV_KIT_REPO) {{ $env:ZPOV_KIT_REPO }} else {{ "{repo}" }}
$home_ = if ($env:ZPOV_PROBE_HOME) {{ $env:ZPOV_PROBE_HOME }} else {{ Join-Path $env:USERPROFILE ".zscaler-pov-probe" }}
New-Item -ItemType Directory -Force -Path $home_ | Out-Null
$packf = Join-Path $home_ "pack-download-{pov}.json"
[IO.File]::WriteAllBytes($packf, [Convert]::FromBase64String("{pack}"))
$probe = Join-Path $home_ "app\pov-probe.cmd"
if (-not (Test-Path $probe)) {{
  $env:ZPOV_PACK_FILE = $packf
  & ([scriptblock]::Create((Invoke-RestMethod "https://github.com/$Repo/releases/latest/download/install-probe.ps1")))
}} else {{
  & $probe pack install $packf
}}
Write-Host ""
Write-Host "  Checking this device is in the POV's tenant, as a pilot user..."
& $probe traffic check --cloud {cloud}
if ($LASTEXITCODE -ne 0) {{ Write-Host "  Not ready yet: sign in to Client Connector as a pilot user. Rounds wait until traffic goes through Zscaler." }}
& $probe traffic schedule --every {every}
& $probe traffic run --count 2
# The device's own test runner: the POV's tests, guided demos and Show it, on the desktop and at sign-in
$sh = New-Object -ComObject WScript.Shell
foreach ($d in @([Environment]::GetFolderPath("Desktop"), [Environment]::GetFolderPath("Startup"))) {{
  $l = $sh.CreateShortcut((Join-Path $d "POV device tests.lnk")); $l.TargetPath = $probe; $l.Arguments = "ui"; $l.WindowStyle = 7; $l.Save()
}}
Write-Host "  'POV device tests' is on the desktop (and opens at sign-in). Opening it now..."
Start-Process -FilePath $probe -ArgumentList "ui" -WindowStyle Minimized
"""


def cloudshare_script(pov, every=30):
    """-> (file name, PowerShell text) for the CloudShare Windows pilot: probe, this POV's pack, scheduled traffic."""
    import base64
    from . import device_setup, evidence
    from .core import KitError
    if "zia" not in pov.products:
        raise KitError("The traffic generator is for ZIA, which isn't in this POV.")
    cloud = device_setup.cloud(pov)
    if not cloud:
        raise KitError("Set the Zscaler cloud first (Next steps > Set up a pilot device > Detect).")
    every = max(15, min(int(every), 1440))
    pack = base64.b64encode(json.dumps(evidence.probe_pack(pov), separators=(",", ":")).encode()).decode()
    name = f"zpov-traffic-{pov.id}.ps1"
    return name, CLOUDSHARE.format(pov=pov.id, name=name, every=every, repo=REPO, pack=pack, cloud=cloud)
