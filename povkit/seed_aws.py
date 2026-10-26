"""The POV seed stack: a CloudFormation template for the customer's TEST AWS account, so AI-SPM and DSPM have
something real to find once the account is connected to Zscaler.

It makes, all named zpov-... and tagged zpov=<POV id>:
  - zpov-records-...        S3, synthetic customer, HR, health and card records (CSV, JSON, PDF, Word), locked down
  - zpov-misconfigured-...  S3, a smaller copy, deliberately weak: public access block off, no versioning or logging,
                            a policy that lets any role in the account read it; optionally one public decoy file
  - zpov-training-data-...  S3, JSONL "fine-tuning" files with synthetic personal data in them
  - zpov-customers-...      DynamoDB table of synthetic customers
  - zpov-support-agent-...  Lambda AI agent that calls a Bedrock model; its role is deliberately too broad
  - zpov-mcp-server-...     optional: a tiny MCP server on a function URL with no authentication (canned answers)
  - a seeder Lambda (custom resource) that writes the data on create and empties the buckets on delete

The kit never deploys it: the customer's cloud admin does, after connecting the account in Zscaler, and deleting the
stack removes everything. All the data is synthetic (seed_code/seeder.py says how). Costs: cents a month, plus Bedrock
calls when someone runs the agent.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

CODE = Path(__file__).resolve().parent / "seed_code"
DEFAULT_MODEL = "amazon.nova-micro-v1:0"


def code(name):
    return (CODE / f"{name}.py").read_text(encoding="utf-8")


def suffix(pov_id):
    """A bucket-name-safe POV id: S3 names are lowercase, at most 63 characters, account ID included."""
    s = re.sub(r"[^a-z0-9-]", "-", pov_id.lower()).strip("-")
    return s[:18].strip("-") or "pov"


def param(type_, default, desc, **kw):
    return dict({"Type": type_, "Default": default, "Description": desc}, **kw)


def build(pov_id, mcp=False, public_decoy=False, records=300, model=DEFAULT_MODEL):
    sfx = suffix(pov_id)
    name = lambda base: {"Fn::Sub": f"zpov-{base}-${{AWS::AccountId}}-{sfx}"}   # noqa: E731
    fn_name = lambda base: f"zpov-{base}-{sfx}"   # noqa: E731
    tags = [{"Key": "zpov", "Value": {"Ref": "PovId"}}, {"Key": "zpov-purpose", "Value": "seed: synthetic test data"}]
    arn = lambda logical: {"Fn::GetAtt": [logical, "Arn"]}   # noqa: E731
    objs = lambda logical: {"Fn::Sub": f"${{{logical}.Arn}}/*"}   # noqa: E731
    buckets = ["RecordsBucket", "MisconfiguredBucket", "TrainingBucket"]

    def log_policy(fn):
        return {"PolicyName": "logs", "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": {"Fn::Sub": f"arn:${{AWS::Partition}}:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:/aws/lambda/{fn}*"}}]}}

    assume = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                                                       "Action": "sts:AssumeRole"}]}
    locked = {"BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True, "RestrictPublicBuckets": True}
    res = {
        "RecordsBucket": {"Type": "AWS::S3::Bucket", "Properties": {
            "BucketName": name("records"), "PublicAccessBlockConfiguration": locked,
            "VersioningConfiguration": {"Status": "Enabled"},
            "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}, "Tags": tags}},
        "MisconfiguredBucket": {"Type": "AWS::S3::Bucket", "Properties": {
            "BucketName": name("misconfigured"),
            "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                               "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
            "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}, "Tags": tags}},
        "MisconfiguredBucketPolicy": {"Type": "AWS::S3::BucketPolicy", "Properties": {
            "Bucket": {"Ref": "MisconfiguredBucket"}, "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                {"Sid": "AnyRoleInThisAccountCanRead", "Effect": "Allow",
                 "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
                 "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": [arn("MisconfiguredBucket"), objs("MisconfiguredBucket")]},
                {"Fn::If": ["PublicDecoy", {"Sid": "PublicDecoyFile", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                            "Resource": {"Fn::Sub": "${MisconfiguredBucket.Arn}/public-decoy/*"}},
                            {"Ref": "AWS::NoValue"}]}]}}},
        "TrainingBucket": {"Type": "AWS::S3::Bucket", "Properties": {
            "BucketName": name("training-data"), "PublicAccessBlockConfiguration": locked,
            "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}, "Tags": tags}},
        "CustomersTable": {"Type": "AWS::DynamoDB::Table", "Properties": {
            "TableName": fn_name("customers"), "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": "customer_id", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "customer_id", "KeyType": "HASH"}], "Tags": tags}},
        "SeederRole": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": assume, "Tags": tags, "Policies": [log_policy(fn_name("seeder")), {
                "PolicyName": "seed-own-resources-only", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": ["s3:PutObject", "s3:PutObjectTagging", "s3:DeleteObject", "s3:DeleteObjectVersion",
                                                   "s3:ListBucket", "s3:ListBucketVersions"],
                     "Resource": [x for b in buckets for x in (arn(b), objs(b))]},
                    {"Effect": "Allow", "Action": ["dynamodb:BatchWriteItem", "dynamodb:PutItem"], "Resource": arn("CustomersTable")}]}}]}},
        "Seeder": {"Type": "AWS::Lambda::Function", "Properties": {
            "FunctionName": fn_name("seeder"), "Description": "Writes the POV seed stack's synthetic data; empties its buckets on delete.",
            "Runtime": "python3.12", "Handler": "index.handler", "Timeout": 300, "MemorySize": 256,
            "Role": arn("SeederRole"), "Code": {"ZipFile": code("seeder")}, "Tags": tags,
            "Environment": {"Variables": {"RECORDS_BUCKET": {"Ref": "RecordsBucket"}, "MISCONFIGURED_BUCKET": {"Ref": "MisconfiguredBucket"},
                                          "TRAINING_BUCKET": {"Ref": "TrainingBucket"}, "TABLE": {"Ref": "CustomersTable"}}}}},
        "SeedData": {"Type": "Custom::ZpovSeedData", "DependsOn": ["MisconfiguredBucketPolicy"],
                     "Properties": {"ServiceToken": arn("Seeder"), "Records": {"Ref": "Records"}, "Version": "1"}},
        "AgentRole": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": assume, "Tags": tags,
            "Description": "DELIBERATELY over-permissioned (POV finding): all of Bedrock, and read on customer records it doesn't need.",
            "Policies": [log_policy(fn_name("support-agent")), {
                "PolicyName": "too-broad-on-purpose", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": "bedrock:*", "Resource": "*"},
                    {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
                     "Resource": [arn("TrainingBucket"), objs("TrainingBucket"), arn("RecordsBucket"), objs("RecordsBucket")]},
                    {"Effect": "Allow", "Action": ["dynamodb:Scan", "dynamodb:GetItem", "dynamodb:Query"], "Resource": arn("CustomersTable")}]}}]}},
        "SupportAgent": {"Type": "AWS::Lambda::Function", "Properties": {
            "FunctionName": fn_name("support-agent"), "Description": "POV AI agent: asks a Bedrock model about its (synthetic) training data.",
            "Runtime": "python3.12", "Handler": "index.handler", "Timeout": 60, "MemorySize": 256,
            "Role": arn("AgentRole"), "Code": {"ZipFile": code("agent")}, "Tags": tags,
            "Environment": {"Variables": {"TRAINING_BUCKET": {"Ref": "TrainingBucket"}, "MODEL_ID": {"Ref": "AgentModelId"}}}}},
        "McpRole": {"Type": "AWS::IAM::Role", "Condition": "Mcp", "Properties": {
            "AssumeRolePolicyDocument": assume, "Tags": tags, "Policies": [log_policy(fn_name("mcp-server"))]}},
        "McpServer": {"Type": "AWS::Lambda::Function", "Condition": "Mcp", "Properties": {
            "FunctionName": fn_name("mcp-server"), "Description": "POV MCP server with NO authentication (on purpose); canned answers only.",
            "Runtime": "python3.12", "Handler": "index.handler", "Timeout": 10, "MemorySize": 128,
            "Role": arn("McpRole"), "Code": {"ZipFile": code("mcp")}, "Tags": tags}},
        "McpUrl": {"Type": "AWS::Lambda::Url", "Condition": "Mcp",
                   "Properties": {"TargetFunctionArn": arn("McpServer"), "AuthType": "NONE"}},
        "McpUrlPermission": {"Type": "AWS::Lambda::Permission", "Condition": "Mcp", "Properties": {
            "FunctionName": {"Ref": "McpServer"}, "Action": "lambda:InvokeFunctionUrl", "Principal": "*",
            "FunctionUrlAuthType": "NONE"}},
    }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"Zscaler POV {pov_id}: seed stack with SYNTHETIC data for AI-SPM and DSPM (deploy in a test account; "
                       "deleting the stack removes everything).",
        "Metadata": {"AWS::CloudFormation::Interface": {"ParameterGroups": [
            {"Label": {"default": "What to make"}, "Parameters": ["IncludeMcpServer", "PublicDecoy", "Records"]},
            {"Label": {"default": "AI agent"}, "Parameters": ["AgentModelId"]}, {"Label": {"default": "POV"}, "Parameters": ["PovId"]}]}},
        "Parameters": {
            "PovId": param("String", pov_id, "The POV these resources belong to (tags only)."),
            "IncludeMcpServer": param("String", "true" if mcp else "false", "Add zpov-mcp-server: a tiny MCP server on a "
                                      "PUBLIC function URL with no authentication (canned answers, reads nothing).",
                                      AllowedValues=["true", "false"]),
            "PublicDecoy": param("String", "true" if public_decoy else "false", "Make ONE file (public-decoy/zpov-decoy.csv, "
                                 "5 synthetic rows) readable by anyone on the internet. Fails if the account blocks public "
                                 "buckets (S3 > Block Public Access settings for this account).", AllowedValues=["true", "false"]),
            "Records": param("Number", records, "How many synthetic people to make.", MinValue=50, MaxValue=2000),
            "AgentModelId": param("String", model, "The Bedrock model the agent calls. If Bedrock says on-demand isn't "
                                  "supported in this Region, use the inference profile, e.g. us.amazon.nova-micro-v1:0."),
        },
        "Conditions": {"Mcp": {"Fn::Equals": [{"Ref": "IncludeMcpServer"}, "true"]},
                       "PublicDecoy": {"Fn::Equals": [{"Ref": "PublicDecoy"}, "true"]}},
        "Resources": res,
        "Outputs": {
            "RecordsBucket": {"Value": {"Ref": "RecordsBucket"}, "Description": "Synthetic sensitive records (locked down)"},
            "MisconfiguredBucket": {"Value": {"Ref": "MisconfiguredBucket"}, "Description": "The weak bucket (a DSPM/AI-SPM finding)"},
            "TrainingBucket": {"Value": {"Ref": "TrainingBucket"}, "Description": "AI training data with personal data in it"},
            "CustomersTable": {"Value": {"Ref": "CustomersTable"}},
            "SupportAgent": {"Value": {"Ref": "SupportAgent"}, "Description": "The over-permissioned AI agent (run it once from the Lambda console)"},
            "McpServerUrl": {"Condition": "Mcp", "Value": {"Fn::GetAtt": ["McpUrl", "FunctionUrl"]},
                             "Description": "The unauthenticated MCP server"},
        },
    }


def for_pov(pov, **kw):
    return f"zpov-seed-{pov.id}.json", build(pov.id, **kw)


def write(path, pov, **kw):
    name, t = for_pov(pov, **kw)
    out = Path(path or name)
    out.write_text(json.dumps(t, indent=2), encoding="utf-8")
    return out
