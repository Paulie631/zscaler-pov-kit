from povkit import lifecycle, products
from povkit.core import pov as povs


def proof(p, pov, tenant, cid):
    crit = next(c for c in products.get(p).criteria() if c["id"] == cid)
    return products.get(p).api_proof(tenant, pov, None, crit)


def test_registered_and_choosable():
    for n in ("easm", "zbi", "zms", "ztw"):
        assert n in products.CHOOSABLE and products.get(n).criteria()
        assert products.get(n).plan(None, {})[0] == []


def test_proofs_pass_from_what_the_tenant_has(pov, tenant):
    pov.cfg["customer_id"] = "7"
    tenant.ro = {
        "zeasm.organizations": {"results": [{"id": 1, "name": "Acme"}]},
        "zeasm.findings": {"results": [{"severity": "High"}, {"severity": "High"}, {"severity": "Low"}]},
        "zeasm.lookalike_domains": {"results": [{"domain": "acrne.com"}]},
        "zbi.reports": [{"name": "SaaS Spend"}],
        "zms.agents": {"nodes": [{"name": "web1", "connectionStatus": "CONNECTED"}, {"name": "db1", "status": "OFFLINE"}]},
        "zms.policy_rules": {"nodes": [{"name": "web to db"}]},
        "ztw.ec_groups": [{"id": 3, "name": "aws-east", "ecVMs": [{"operationalState": "UP"}]}],
        "ztw.forwarding_rules": [{"name": "Default", "defaultRule": True}, {"name": "VPC to ZIA", "forwardMethod": "ZIA"}],
    }
    r = proof("easm", pov, tenant, "EA-FND-01")
    assert r["status"] == "pass" and "3 findings" in r["detail"] and "2 high" in r["detail"]
    assert proof("easm", pov, tenant, "EA-LKA-01")["status"] == "pass"
    assert proof("zbi", pov, tenant, "BI-RPT-01")["detail"].startswith("1 reports")
    assert proof("zms", pov, tenant, "MS-AGT-01")["detail"] == "1 of 2 agents connected"
    assert proof("zms", pov, tenant, "MS-POL-01")["status"] == "pass"
    assert "1 of 1 connector VMs running" in proof("ztw", pov, tenant, "CC-GRP-01")["detail"]
    r = proof("ztw", pov, tenant, "CC-FWD-01")
    assert r["status"] == "pass" and r["detail"] == "1 forwarding rules (ZIA)"


def test_empty_or_denied_is_incomplete_not_a_crash(pov, tenant):
    pov.cfg["customer_id"] = "7"
    assert proof("zms", pov, tenant, "MS-AGT-01")["status"] == "incomplete"
    assert proof("ztw", pov, tenant, "CC-FWD-01")["status"] == "incomplete"
    tenant.denied = ("zeasm",)
    assert "not readable" in proof("easm", pov, tenant, "EA-FND-01")["detail"]
    snap, checks = products.get("easm").discover(tenant, pov)
    assert snap == {"readable": False} and checks[0]["status"] == "fail"


def test_discovery_with_read_only_products(home, tenant, tenant_for):
    p = povs.new("Acme Corp", ["zia", "easm", "zbi", "zms", "ztw"])
    p.cfg.update(pilot_group="POV Pilot", vanity_domain="acme", customer_id="7")
    p.save()
    lifecycle.discover(p, tenant_for)
    snap = p.read_json("discovery.json")["products"]
    assert snap["zms"]["readable"] and snap["ztw"]["groups"] == [] and snap["zbi"]["reports"] == 0


def test_whole_lifecycle_with_read_only_products(home, tenant, tenant_for):
    from povkit import evidence, report
    p = povs.new("Acme Corp", ["zia", "easm", "zms"])
    p.cfg.update(pilot_group="POV Pilot", vanity_domain="acme", customer_id="7")
    p.save()
    tenant.ro = {"zeasm.organizations": {"results": [{"id": 1, "name": "Acme"}]},
                 "zeasm.findings": {"results": [{"severity": "High"}]}}
    items = lifecycle.plan(p, tenant_for)[0]
    assert {"easm.ca.org", "zms.ca.agents", "zms.ca.policy"} <= {i["key"] for i in items}
    from povkit.core.changelist import ChangeList
    ChangeList(p.dir).approve("Jane Doe")
    lifecycle.apply(p, tenant_for, lambda *a: None)
    lifecycle.status(p, tenant_for)
    lifecycle.api_proofs(p, tenant_for)
    rows = {r["criterion"]["id"]: r for r in evidence.evaluate(p)}
    assert rows["EA-FND-01"]["proofs"]["api"]["status"] == "pass"
    assert rows["MS-AGT-01"]["proofs"]["api"]["status"] == "incomplete"
    lifecycle.teardown(p, tenant_for, log=lambda *a: None)
    html = report.render_report(p, evidence.evaluate(p), None)
    assert "External Attack Surface" in html and "Microsegmentation" in html
