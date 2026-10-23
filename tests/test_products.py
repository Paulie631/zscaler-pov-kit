"""Every product module through the full lifecycle against the fake tenant, with the same safety checks as ZIA."""
import json


from povkit import connector_template, evidence, handover, lifecycle, products
from povkit.core import secrets
from povkit.core.changelist import ChangeList
from povkit.core.guard import LedgerTenant

log = lambda *a: None  # noqa: E731


def applied(pov, tenant_for):
    items, notes, h, checks = lifecycle.plan(pov, tenant_for)
    ChangeList(pov.dir).approve("Jane Doe")
    lifecycle.apply(pov, tenant_for, log)
    return items


def names(tenant, res):
    return {r["name"] for r in tenant.store[res]}


# ---- ZIA: the kinds added in 0.2
def test_zia_supporting_objects_feed_the_rules(pov, tenant, tenant_for):
    applied(pov, tenant_for)
    cat = tenant.by_name("url_category", "ZPOV - tenant check")
    svc = tenant.by_name("network_service", "ZPOV - POV ports")
    assert cat and svc and cat["urls"] == ["www.example.com", "example.com"]
    assert tenant.by_name("url_filtering", "ZPOV: Block tenant check")["url_categories"] == [cat["id"]]
    assert tenant.by_name("firewall", "ZPOV: Block POV ports")["nw_services"] == [svc["id"]]
    iso = tenant.by_name("url_filtering", "ZPOV: Isolate games")
    assert iso["action"] == "ISOLATE" and iso["cbi_profile"]["id"] == "cbi-1"
    assert tenant.by_name("file_type", "ZPOV: Block EXE downloads")["groups"] == [77]
    assert tenant.by_name("dns", "ZPOV: Block marijuana DNS")["res_categories"] == ["MARIJUANA"]
    lifecycle.teardown(pov, tenant_for, log)
    for kind in ("url_category", "network_service", "file_type", "firewall", "dns"):
        assert tenant.rules[kind] == [], kind


def test_zia_isolation_left_out_without_a_profile(pov, tenant, tenant_for):
    tenant.cbi = []
    items, notes, _, _ = lifecycle.plan(pov, tenant_for)
    assert not any(i["name"] == "ZPOV: Isolate games" for i in items)
    assert any("Isolate games" in n for n in notes)


# ---- ZPA
def test_zpa_lifecycle_scoped_and_reversible(pov_all, tenant, tenant_for):
    applied(pov_all, tenant_for)
    st = tenant.store
    seg = next(s for s in st["zpa.application_segment"] if s["name"] == "ZPOV: HR portal")
    grp = next(g for g in st["zpa.app_connector_groups"] if g["name"] == "ZPOV: connectors")
    sgrp = next(g for g in st["zpa.segment_groups"] if g["name"] == "ZPOV: POV apps")
    assert seg["segment_group_id"] == sgrp["id"] and isinstance(seg["segment_group_id"], str)   # ZPA ids stay strings
    assert seg["tcp_port_ranges"] == ["443", "443"] and seg["domain_names"] == ["pov-app.acme.internal"]
    rule = next(r for r in st["zpa.policies"] if r["name"] == "ZPOV: pilot access")
    ops = {o["objectType"]: o["rhs"] for c in rule["conditions"] for o in c["operands"]}
    assert ops == {"APP": seg["id"], "SCIM_GROUP": "sg1"}
    assert rule["ruleOrder"] == "1"                                    # placed first, as approved
    assert secrets.get(pov_all.id, "zpa-provisioning-key") == "3|fake-provisioning-secret"
    key = next(k for k in st["zpa.provisioning"])
    assert key["component_id"] == grp["id"] and key["max_usage"] == "2"
    # connectors enrolled: teardown keeps the group until they're gone, removes everything else
    grp["connectors"] = [{"name": "ip-10-0-1-5", "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED"}]
    lifecycle.teardown(pov_all, tenant_for, log)
    assert names(tenant, "zpa.app_connector_groups") == {"Corp connectors", "ZPOV: connectors"}
    assert names(tenant, "zpa.application_segment") == {"Corp intranet"}
    assert names(tenant, "zpa.policies") == {"Corp: engineering"}
    grp["connectors"] = []
    lifecycle.teardown(pov_all, tenant_for, log)
    assert names(tenant, "zpa.app_connector_groups") == {"Corp connectors"}
    assert not secrets.get(pov_all.id, "zpa-provisioning-key")


def test_zpa_refuses_an_app_the_customer_already_publishes(pov_all, tenant, tenant_for):
    pov_all.cfg["zpa"]["domains"] = ["intranet.acme.com"]
    pov_all.save()
    _, _, _, checks = lifecycle.plan(pov_all, tenant_for)
    c = {c["id"]: c for c in checks}["zpa-overlap"]
    assert c["status"] == "fail" or c.get("waiting")   # ZPA sits out; the rest of the POV goes ahead
    ChangeList(pov_all.dir).approve("Jane Doe")
    lifecycle.apply(pov_all, tenant_for, log)                     # everything else goes ahead...
    assert not [w for w in tenant.writes if w[0].startswith("zpa.")]  # ...and ZPA is never touched
    assert tenant.by_name("url_filtering", "ZPOV: Block gambling")


def test_zpa_broad_customer_rule_fails_the_deny_proof(pov_all, tenant, tenant_for):
    tenant.store["zpa.policies"].append({"id": "70009", "name": "Corp: allow all", "action": "ALLOW", "conditions": []})
    applied(pov_all, tenant_for)
    res = lifecycle.api_proofs(pov_all, tenant_for, {"PA-APP-02", "PA-CON-01"})
    assert res["PA-APP-02"]["status"] == "fail" and "Corp: allow all" in res["PA-APP-02"]["detail"]
    assert res["PA-CON-01"]["status"] == "fail"           # no connectors yet


def test_connector_template_hides_the_key_and_opens_no_ports():
    tpl = connector_template.build("acme-1234")
    assert tpl["Parameters"]["ProvisioningKey"]["NoEcho"] is True
    inst = [r for r in tpl["Resources"].values() if r["Type"] == "AWS::EC2::Instance"]
    assert len(inst) == 2
    sg = tpl["Resources"]["NoInbound"]["Properties"]
    assert "SecurityGroupIngress" not in sg
    assert "/opt/zscaler/var/provision_key" in json.dumps(tpl)
    assert "fake" not in json.dumps(tpl)


def test_azure_template_uses_zscalers_image_and_opens_no_ports():
    tpl = connector_template.build_azure("acme-1234")
    assert tpl["parameters"]["provisioningKey"]["type"] == "securestring"
    vms = [r for r in tpl["resources"] if r["type"] == "Microsoft.Compute/virtualMachines"]
    assert len(vms) == 2
    for v in vms:
        assert v["plan"] == {"name": "zpa-con-azure", "publisher": "zscaler", "product": "zscaler-private-access"}
        assert v["properties"]["osProfile"]["linuxConfiguration"]["disablePasswordAuthentication"] is True
        assert "provisioningKey" in v["properties"]["osProfile"]["customData"]
    nics = [r for r in tpl["resources"] if r["type"] == "Microsoft.Network/networkInterfaces"]
    assert all("publicIPAddress" not in n["properties"]["ipConfigurations"][0]["properties"] for n in nics)
    nsg = next(r for r in tpl["resources"] if r["type"] == "Microsoft.Network/networkSecurityGroups")
    rules = nsg["properties"]["securityRules"]
    assert [r["properties"]["access"] for r in rules if r["properties"]["direction"] == "Inbound"] == ["Deny"]
    text = json.dumps(tpl)
    assert "/opt/zscaler/var/provision_key" in text and "fake" not in text
    # the boot script survives ARM's quoting: concat('...', key, '...') with no stray single quotes
    boot = vms[0]["properties"]["osProfile"]["customData"]
    assert boot.startswith("[base64(concat('#!/bin/bash") and boot.endswith("'))]")


# ---- AI Guard
def test_aiguard_lifecycle_profile_and_api_proof(pov_all, tenant, tenant_for, monkeypatch):
    applied(pov_all, tenant_for)
    st = tenant.store
    pol = next(p for p in st["aiguard.policies"] if p["name"] == "ZPOV: AI Guard POV")
    app = next(a for a in st["aiguard.llm_applications"] if a["name"] == "ZPOV: POV app")
    key = next(k for k in st["aiguard.llm_application_credentials"])
    rule = next(r for r in st["aiguard.policy_match_rules"] if r["name"] == "ZPOV: POV app rule")
    assert rule["policyId"] == pol["id"] and isinstance(rule["policyId"], int)
    assert rule["matchCriteria"]["llmApplications"] == [{"applicationId": app["id"], "applicationCredentialsIds": [key["id"]]}]
    assert rule["ruleOrder"] == 2                                       # after the customer's rule
    assert secrets.get(pov_all.id, "aiguard-detection-key") == "fake-detection-key"
    blocks = lambda p: {d["detector"] for d in p["inputDetectorPolicies"]  # noqa: E731
                        if (d.get("configuration") or {}).get("action") == "BLOCK"}
    assert blocks(pol) == set()                                          # starts in Monitor
    led = lifecycle.ledger(pov_all)
    products.get("aiguard").set_profile(LedgerTenant(tenant, led, []), pov_all, led, "attacks", log)
    assert "prompt_injection" in blocks(pol)
    assert next(p for p in st["aiguard.policies"] if p["name"] == "Corp AI policy")["inputDetectorPolicies"] == []

    from povkit.products.aiguard import PROOF_TESTS
    want = {t["text"].replace("{_}", "").replace("{COMPETITOR}", "Competitor Inc"): t["expect"]
            for ts in PROOF_TESTS.values() for t in ts}

    def scan(key, text, direction="IN"):   # AI Guard as it should behave: the expected detectors trigger
        hit = want.get(text, [])
        return {"policyId": pol["id"], "action": "BLOCK" if "prompt_injection" in hit else "ALLOW",
                "detectorResponses": {h: {"triggered": True} for h in hit} | {"prompt_tags": {"triggered": True}}}
    ag = products.get("aiguard")
    for cid in PROOF_TESTS:
        r = ag.api_proof(None, pov_all, led, {"id": cid}, scan=scan)
        assert r["status"] == "pass", (cid, r["detail"])
    assert "BLOCK" in ag.api_proof(None, pov_all, led, {"id": "AI-AIG-01"}, scan=scan)["detail"]
    missing = lambda key, text, direction="IN": scan(key, text, direction) | {"detectorResponses": {}}  # noqa: E731
    r = ag.api_proof(None, pov_all, led, {"id": "AI-AIG-02"}, scan=missing)
    assert r["status"] == "fail" and "not as expected" in r["detail"]
    harmful = lambda key, text, direction="IN": scan(key, text, direction) | {  # noqa: E731
        "detectorResponses": {"secrets": {"triggered": True}}}
    assert ag.api_proof(None, pov_all, led, {"id": "AI-AIG-08"}, scan=harmful)["status"] == "fail"   # false positive
    lifecycle.teardown(pov_all, tenant_for, log)
    assert names(tenant, "aiguard.policies") == {"Corp AI policy"}
    assert names(tenant, "aiguard.llm_applications") == {"Corp chatbot"}
    assert not secrets.get(pov_all.id, "aiguard-detection-key")


# ---- ZDX and CASB
def test_zdx_deep_traces_and_score_proof(pov_all, tenant, tenant_for):
    applied(pov_all, tenant_for)
    tr = tenant.store["zdx.troubleshooting"]
    assert len(tr) == 1 and tr[0]["device_id"] == "d1" and tr[0]["session_length_minutes"] == 15
    res = lifecycle.api_proofs(pov_all, tenant_for, {"DX-SCR-01", "IS-ZCC-01"})
    assert res["DX-SCR-01"]["status"] == "pass" and res["IS-ZCC-01"]["status"] == "pass"
    lifecycle.teardown(pov_all, tenant_for, log)
    assert tenant.store["zdx.troubleshooting"] == []


def test_casb_rule_is_report_only_and_activates(pov_all, tenant, tenant_for):
    applied(pov_all, tenant_for)
    rule = next(r for r in tenant.store["casb_dlp_rules"] if r["name"] == "ZPOV: SaaS card numbers")
    assert rule["action"] == "OFLCASB_DLP_REPORT_INCIDENT"
    assert rule["cloud_app_tenant_ids"] == [55] and rule["groups"] == [77] and rule["order"] == 2
    i = next(n for n, w in enumerate(tenant.writes) if w[0] == "casb_dlp_rules")
    assert ("activate", "activate") in [w[:2] for w in tenant.writes[i:]]
    lifecycle.teardown(pov_all, tenant_for, log)
    assert names(tenant, "casb_dlp_rules") == {"Corp SaaS DLP"}


# ---- across products
def test_all_products_never_write_customer_objects(pov_all, tenant, tenant_for):
    applied(pov_all, tenant_for)
    lifecycle.teardown(pov_all, tenant_for, log, include_adopted=True)
    customer_ids = {"70001", "70002", "70003", "501", "502", "503", "601", "1", "2"}
    for res, method, a, _kw in tenant.writes:
        if method.startswith(("update", "delete", "reorder")):
            target = a[1:2] if method == "reorder_rule" else a     # reorder_rule(policy type, rule id, new order)
            assert not ({str(x) for x in target} & customer_ids), (res, method, a)


def test_probe_pack_fills_in_the_pov_values(pov_all):
    pack = evidence.probe_pack(pov_all)
    pa = next(c for c in pack["criteria"] if c["id"] == "PA-APP-01")
    assert pa["probe"] == [{"type": "tcp", "host": "pov-app.acme.internal", "port": 443, "expect": "open"}]
    assert any(c["id"] == "IS-URL-01" for c in pack["criteria"])


def test_terraform_export_covers_zpa_and_flags_unconfirmed(pov_all, tenant, tenant_for):
    applied(pov_all, tenant_for)
    out, exported, skipped = handover.terraform(pov_all, lifecycle.ledger(pov_all))
    text = (out / "imports.tf").read_text()
    assert "zpa_application_segment." in text and 'source = "zscaler/zpa"' in (out / "versions.tf").read_text()
    assert "# check:" in text
    assert {e["product"] for e, _ in skipped} >= {"aiguard"}


def test_plan_is_unchanged_by_apply_for_every_product(pov_all, tenant, tenant_for):
    """The POV's own objects must never change the plan, or status would report the tenant as changed since
    approval and Fix drift would refuse to run."""
    applied(pov_all, tenant_for)
    a = ChangeList(pov_all.dir).approval()
    items, _ = lifecycle.make_plan(pov_all, lifecycle.discover(pov_all, tenant_for)[0])
    from povkit.core.changelist import digest
    assert digest(items) == a["hash"]
    checks = {c["id"]: c for c in lifecycle.status(pov_all, tenant_for)}
    assert checks["plan-approved"]["status"] == "ok"
    assert not [c for c in checks.values() if c["status"] == "fail"]


def test_connector_templates_bring_a_test_app_when_no_app_is_named(pov_all):
    from povkit.products.zpa import app_of
    pov_all.cfg["zpa"]["domains"] = []
    app = app_of(pov_all.cfg)
    assert app["test_app"] and app["domains"] == ["pov-app.zpov.internal"] and app["tcp_ports"] == ["80"]
    aws = connector_template.build("acme-1234", test_app=True)
    r = aws["Resources"]
    assert r["TestApp"]["Properties"]["InstanceType"] == "t3.micro"
    ing = r["TestAppOnlyFromConnectors"]["Properties"]["SecurityGroupIngress"]
    assert ing == [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "SourceSecurityGroupId": {"Ref": "NoInbound"}}]
    assert r["TestAppRecord"]["Properties"]["Name"] == "pov-app.zpov.internal"
    assert "TestApp" not in connector_template.build("acme-1234")["Resources"]
    az = connector_template.build_azure("acme-1234", test_app=True)
    kinds = [x["type"] for x in az["resources"]]
    assert "Microsoft.Network/privateDnsZones/A" in kinds and kinds.count("Microsoft.Compute/virtualMachines") == 3
    json.dumps(az)
    from povkit import evidence
    pack = json.dumps(evidence.probe_pack(pov_all))
    assert "pov-app.zpov.internal" in pack or "{zpa.domain}" not in pack


def test_a_product_that_isnt_ready_waits_and_the_rest_goes_ahead(pov_all, tenant, tenant_for):
    pov_all.cfg["zdx"] = {}
    tenant.zdx_forbidden = True
    items, notes, _, checks = lifecycle.plan(pov_all, tenant_for)
    waiting = [c for c in checks if c.get("waiting")]
    assert any(c.get("product") == "zdx" for c in waiting)
    assert not [i for i in items if i["product"] == "zdx"]
    assert any("ZDX is added later" in n for n in notes)
    assert [i for i in items if i["product"] == "zia"]
    assert not [c for c in checks if c["status"] == "fail"]


def test_industry_packs_are_optional_criteria(pov_all):
    from povkit import evidence
    ids = {c["id"] for c in evidence.selected_criteria(pov_all)}
    assert {"AI-AIG-01", "AI-AIG-08"} <= ids and "AI-AIG-P2" not in ids
    pov_all.cfg["criteria"] = ["AI-AIG-01", "AI-AIG-P2"]
    assert {c["id"] for c in evidence.selected_criteria(pov_all)} >= {"AI-AIG-01", "AI-AIG-P2"}
