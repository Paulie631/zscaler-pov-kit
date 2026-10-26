# ruff: noqa: E501
"""The AI-SPM / DSPM seed stack: its template, its Lambda code, and the steps for people around it."""
import importlib.util
import io
import json
import os
import zipfile

import pytest

from povkit import lifecycle, manual, seed_aws
from povkit.core import pov as povs
from povkit.core.changelist import ChangeList


def load(name):
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")   # the seeder makes its clients at import, as in Lambda
    spec = importlib.util.spec_from_file_location(name, seed_aws.CODE / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_template_shape():
    t = seed_aws.build("Acme-Corp-0410-with-a-very-long-name")
    r = t["Resources"]
    assert {"RecordsBucket", "MisconfiguredBucket", "TrainingBucket", "CustomersTable", "Seeder", "SeedData",
            "SupportAgent", "McpServer", "McpUrl"} <= set(r)
    assert r["McpUrl"]["Condition"] == "Mcp" and t["Parameters"]["IncludeMcpServer"]["Default"] == "false"
    assert t["Parameters"]["PublicDecoy"]["Default"] == "false"
    name = r["RecordsBucket"]["Properties"]["BucketName"]["Fn::Sub"]
    real = name.replace("${AWS::AccountId}", "123456789012")
    assert len(real) <= 63 and real == real.lower()
    assert r["RecordsBucket"]["Properties"]["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] is True
    for k, v in r.items():   # everything tagged for the POV (custom resources and permissions take no tags)
        if v["Type"] not in ("Custom::ZpovSeedData", "AWS::Lambda::Url", "AWS::Lambda::Permission", "AWS::S3::BucketPolicy"):
            assert {"Key": "zpov", "Value": {"Ref": "PovId"}} in v["Properties"]["Tags"], k
    seeder_policy = json.dumps(r["SeederRole"]["Properties"]["Policies"])
    assert '"*"' not in seeder_policy   # the seeder can touch only its own buckets and table
    assert json.dumps(r["AgentRole"]["Properties"]["Policies"]).count("bedrock:*") == 1   # too broad, on purpose
    assert len(json.dumps(t, indent=2)) < 51200   # CloudFormation's upload limit
    on = seed_aws.build("p", mcp=True, public_decoy=True)["Parameters"]
    assert on["IncludeMcpServer"]["Default"] == "true" and on["PublicDecoy"]["Default"] == "true"
    for n in ("seeder", "agent", "mcp"):
        compile(seed_aws.code(n), n, "exec")


def test_seeder_data_is_synthetic():
    m = load("seeder")
    rows = m.people(300, 7)
    assert all(x["email"].endswith("@example.com") and x["ssn"].startswith("987-65-432") and "555-01" in x["phone"]
               for x in rows)
    luhn = lambda n: sum(int(d) if i % 2 == 0 else sum(divmod(int(d) * 2, 10)) for i, d in enumerate(reversed(n))) % 10 == 0  # noqa: E731
    assert all(luhn(c) for c in m.CARDS)
    assert m.pdf("t", ["a (b)"]).startswith(b"%PDF-1.4") and m.pdf("t", ["x"]).rstrip().endswith(b"%%EOF")
    z = zipfile.ZipFile(io.BytesIO(m.docx("t", ["a & <b>"])))
    assert "word/document.xml" in z.namelist() and "a and b" in z.read("word/document.xml").decode()


def test_seeder_against_mocked_aws(monkeypatch):
    moto = pytest.importorskip("moto")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "x")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "x")
    for k, v in (("RECORDS_BUCKET", "rec-b"), ("MISCONFIGURED_BUCKET", "mis-b"), ("TRAINING_BUCKET", "trn-b"), ("TABLE", "tbl")):
        monkeypatch.setenv(k, v)
    with moto.mock_aws():
        import boto3
        s3 = boto3.client("s3")
        for b in ("rec-b", "mis-b", "trn-b"):
            s3.create_bucket(Bucket=b)
        s3.put_bucket_versioning(Bucket="rec-b", VersioningConfiguration={"Status": "Enabled"})
        boto3.client("dynamodb").create_table(TableName="tbl", BillingMode="PAY_PER_REQUEST",
                                              AttributeDefinitions=[{"AttributeName": "customer_id", "AttributeType": "S"}],
                                              KeySchema=[{"AttributeName": "customer_id", "KeyType": "HASH"}])
        m = load("seeder")
        sent = []
        m.respond = lambda e, c, st, r="": sent.append(st)
        ev = {"RequestType": "Create", "ResourceProperties": {"Records": "300"}, "StackId": "s", "RequestId": "q",
              "LogicalResourceId": "SeedData", "ResponseURL": "http://x"}
        m.handler(ev, None)
        keys = {o["Key"] for o in s3.list_objects_v2(Bucket="rec-b")["Contents"]}
        assert sent == ["SUCCESS"] and {"hr/payroll-2026.csv", "docs/hr-review-1.docx", "health/patients.json"} <= keys
        assert boto3.client("dynamodb").scan(TableName="tbl")["Count"] == 200
        m.handler(dict(ev, RequestType="Update"), None)
        m.handler(dict(ev, RequestType="Delete"), None)
        assert sent[-1] == "SUCCESS" and not any(s3.list_object_versions(Bucket=b).get("Versions") for b in ("rec-b", "mis-b", "trn-b"))
        m.handler(dict(ev, ResourceProperties={"Records": "x"}), None)   # a failure is reported, not hung
        assert sent[-1] == "FAILED"


def test_agent_and_mcp_handlers(monkeypatch):
    agent = load("agent")

    class Fake:
        def __init__(self, svc):
            self.svc = svc

        def get_object(self, **k):
            return {"Body": io.BytesIO(b'{"messages": []}')}

        def converse(self, **k):
            assert k["modelId"] == "m1"
            return {"output": {"message": {"content": [{"text": "Late deliveries."}]}}}
    monkeypatch.setattr(agent.boto3, "client", lambda svc: Fake(svc))
    monkeypatch.setitem(os.environ, "TRAINING_BUCKET", "b")
    monkeypatch.setitem(os.environ, "MODEL_ID", "m1")
    assert agent.handler({}, None) == {"model": "m1", "answer": "Late deliveries."}
    mcp = load("mcp")
    call = lambda msg: mcp.handler({"requestContext": {"http": {"method": "POST"}}, "body": json.dumps(msg)}, None)  # noqa: E731
    assert json.loads(call({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})["body"])["result"]["serverInfo"]["name"] == "zpov-mcp-server"
    assert call({"jsonrpc": "2.0", "method": "notifications/initialized"})["statusCode"] == 202
    out = json.loads(call({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "lookup_order", "arguments": {"order_id": "A1"}}})["body"])
    assert "A1" in out["result"]["content"][0]["text"]
    assert mcp.handler({"requestContext": {"http": {"method": "GET"}}}, None)["statusCode"] == 405


def test_cloud_steps_once_and_dspm(home, tenant, tenant_for):
    p = povs.new("Acme Corp", ["zia", "aispm", "dspm", "airt"])
    p.cfg.update(pilot_group="POV Pilot", vanity_domain="acme")
    p.save()
    items = lifecycle.plan(p, tenant_for)[0]
    steps = [i for i in items if i["action"] == "customer_action" and i["product"] in ("aispm", "dspm", "airt")]
    keys = [i["key"] for i in steps]
    assert keys.count("cloud.ca.connect") == 1 and "cloud.ca.seed" in keys and "airt.ca.target" in keys
    connect = next(i for i in steps if i["key"] == "cloud.ca.connect")
    assert {"AS-MOD-01", "AS-RSK-01", "DS-FND-01", "DS-RSK-01", "DS-ACC-01"} == set(connect["criteria"])
    ChangeList(p.dir).approve("Jane Doe")
    lifecycle.apply(p, tenant_for, lambda *a: None)
    titles = {s["key"]: s["title"] for s in manual.guide(p)}
    assert titles["cloud.ca.seed"] == "Deploy the POV seed stack in the test account"
    end = [s["key"] for s in manual.guide(p) if s["phase"] == "end"]
    assert "cloud.end.seed" in end
    name, t = seed_aws.for_pov(p)
    assert name == f"zpov-seed-{p.id}.json"
