import pytest

from povkit import devtests, lifecycle
from povkit.core import KitError
from povkit.core.changelist import ChangeList
from povkit.products import zia


def applied(pov, tenant_for):
    lifecycle.plan(pov, tenant_for)
    ChangeList(pov.dir).approve("Jane")
    lifecycle.apply(pov, tenant_for, lambda *a: None)


def test_switch_and_put_back(pov, tenant, tenant_for):
    applied(pov, tenant_for)
    pol = devtests.policy(pov)
    assert not any("tenant check" in x["name"] for x in pol["switches"]) and not pol["switched"]
    gamb = next(x for x in pol["switches"] if "gambling" in x["name"])
    assert gamb["planned"] == "BLOCK" and gamb["tests"] and {"BLOCK", "CAUTION", "ALLOW"} <= {c["id"] for c in gamb["choices"]}
    assert devtests.switch(pov, tenant, gamb["key"], "CAUTION") == "CAUTION"
    upd = [w for w in tenant.writes if w[1] == "update_rule"][-1]
    assert upd[3]["action"] == "CAUTION" and upd[3]["groups"] and tenant.writes[-1][1] == "activate"
    pol = devtests.policy(pov)
    assert pol["switched"] and next(x for x in pol["switches"] if x["key"] == gamb["key"])["current"] == "CAUTION"
    # results while switched don't count as evidence
    from povkit import probe, device
    device_gate, run_spec = device.gate, probe.run_spec
    try:
        device.gate = lambda c: None
        probe.run_spec = lambda sp, rid, s: {"spec": sp, "outcome": "caution", "expect": sp.get("expect"),
                                             "pass": False, "detail": ""}
        out = devtests.run(pov, gamb["tests"])
        assert out["evidence"] == [] and out["switched"]
    finally:
        device.gate, probe.run_spec = device_gate, run_spec
    with pytest.raises(KitError):
        devtests.switch(pov, tenant, gamb["key"], "DECRYPT")
    assert devtests.put_back(pov, tenant) and not devtests.policy(pov)["switched"]


def test_switch_bodies(pov):
    it = {"kind": "url_filtering", "body": {"action": "ISOLATE", "cbi_profile": {"id": 1}, "user_agent_types": ["CHROME"],
                                             "protocols": ["HTTPS_RULE"]}}
    b = zia.ZIA()._switched_body(None, it, dict(it["body"]), "CAUTION")
    assert b["action"] == "CAUTION" and "cbi_profile" not in b and b["request_methods"] == ["CONNECT", "GET", "HEAD"]
    b = zia.ZIA()._switched_body(None, {"kind": "ssl", "body": {}}, {}, "DO_NOT_DECRYPT")
    assert b["action"]["type"] == "DO_NOT_DECRYPT"


def test_planned_action_names():
    assert zia.planned_action({"kind": "cloud_app_control", "body": {"actions": ["DENY_AI_ML_WEB_USE"]}}) == "BLOCK"
    assert zia.planned_action({"kind": "ssl", "body": {"action": {"type": "DECRYPT"}}}) == "DECRYPT"


def test_switched_tests_expect_the_switch(pov, tenant, tenant_for, monkeypatch):
    from povkit import device, probe
    applied(pov, tenant_for)
    pol = {x["key"]: x for x in devtests.policy(pov)["switches"]}
    social = pol["zia.url_filtering.caution-social"]
    assert len(social["tests"]) == 1 and pol["zia.url_filtering.block-anonymizers"]["tests"] == []
    devtests.switch(pov, tenant, social["key"], "BLOCK")
    monkeypatch.setattr(device, "gate", lambda c: None)
    monkeypatch.setattr(probe, "run_spec", lambda sp, rid, s: {"spec": sp, "outcome": "block", "expect": sp["expect"],
                                                               "pass": sp["expect"] == "block", "detail": ""})
    seen = []
    out = devtests.run(pov, social["tests"], on_result=seen.append)
    assert out["ok"] == 1 and "switched to Block" in seen[0]["switched"] and out["evidence"] == []


def test_api_proof_goes_stale_when_its_tests_change(pov, tenant_for):
    from povkit import evidence
    applied(pov, tenant_for)
    lifecycle.api_proofs(pov, tenant_for, ids=["IS-URL-02"])
    row = lambda: next(r for r in evidence.evaluate(pov, ["IS-URL-02"]))  # noqa: E731
    assert not row()["proofs"]["api"].get("stale") and not lifecycle.stale_proofs(pov)
    saved = pov.read_json("api_proofs.json", {})
    saved["IS-URL-02"]["tests"] = "old"
    pov.write_json("api_proofs.json", saved)
    assert row()["proofs"]["api"]["stale"] and lifecycle.proofs_due(pov)


def test_mac_profile_made_without_a_windows_default(pov, tenant, tenant_for):
    tenant.apps = []   # a Mac-only tenant: no Windows app profile to follow
    applied(pov, tenant_for)
    names = [a["name"] for a in tenant.mac_apps]
    assert any("pilot Macs" in n for n in names)
    assert any(f["name"].startswith("ZPOV") for f in tenant.fwds)


def test_se_applies_directly(pov, tenant, tenant_for):
    lifecycle.plan(pov, tenant_for)
    assert lifecycle.pending(pov) and not lifecycle.changes_made(pov)
    out = lifecycle.quick_apply(pov, tenant_for, None, "Setup", "Paul", lambda *a: None)
    assert out["made"] and not lifecycle.pending(pov)
    made = lifecycle.changes_made(pov)
    assert any(m["name"] == "ZPOV: Block gambling" and m["why"] is not None for m in made)
    st = {c["id"]: c for c in lifecycle.status(pov, tenant_for)}
    assert st["plan-approved"]["status"] == "ok" and "nothing waiting" in st["plan-approved"]["detail"]
    from povkit import coach
    ids = [x["id"] for x in coach.steps(pov)]
    assert "signoff" not in ids and "plan" not in ids and "apply" in ids
