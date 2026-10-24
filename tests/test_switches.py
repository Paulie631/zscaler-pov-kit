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
