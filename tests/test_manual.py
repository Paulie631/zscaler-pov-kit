"""The steps people do (the API can't): instructions for each, checks where the API can see, and Mark done."""
import json

import pytest

from povkit import gui, lifecycle, manual
from povkit.core import KitError
from povkit.core.changelist import ChangeList

log = lambda *a: None  # noqa: E731


def planned(p, tenant_for):
    lifecycle.plan(p, tenant_for)
    ChangeList(p.dir).approve("Jane Doe")


def test_every_customer_action_has_instructions(pov_all, tenant_for):
    planned(pov_all, tenant_for)
    plan = ChangeList(pov_all.dir).plan()["items"]
    for i in plan:
        if i["action"] == "customer_action":
            assert i["key"] in manual.GUIDE["steps"], f"no instructions for {i['key']}"
    for k, s in manual.GUIDE["steps"].items():
        assert s["title"] and s["steps"] and s["who"] and s["done"], k
        assert not s.get("check") or s["check"] in manual.CHECKS, k


def test_guide_orders_setup_then_customer_then_end(pov_all, tenant_for):
    planned(pov_all, tenant_for)
    steps = manual.guide(pov_all)
    keys = [s["key"] for s in steps]
    assert keys[0] == "setup.api_client" and keys[-1] == "end.api_clients"
    assert "setup.zdx_role" in keys and "setup.zpa_customer_id" in keys
    assert [s["phase"] for s in steps] == sorted((s["phase"] for s in steps), key=["setup", "customer", "end"].index)
    assert all(s["status"] == "open" for s in steps)


def test_checks_pass_and_record_the_step_done(pov_all, tenant, tenant_for):
    planned(pov_all, tenant_for)
    assert manual.check(pov_all, "zia.ca.malware", tenant_for)["ok"] is True
    assert manual.check(pov_all, "setup.api_client", tenant_for)["ok"] is True
    s = {x["key"]: x for x in manual.guide(pov_all)}
    assert s["zia.ca.malware"]["status"] == "done" and s["zia.ca.malware"]["by"] == "the kit's check"
    tenant.malware["virusBlocked"] = False
    r = manual.check(pov_all, "zia.ca.malware", tenant_for)
    assert r["ok"] is False and "viruses" in r["detail"]
    assert {x["key"]: x for x in manual.guide(pov_all)}["zia.ca.malware"]["status"] == "open"   # reopened


def test_checks_never_write(pov_all, tenant, tenant_for):
    planned(pov_all, tenant_for)
    before = json.dumps(tenant.store, default=str, sort_keys=True)
    manual.check_all(pov_all, tenant_for, log)
    assert json.dumps(tenant.store, default=str, sort_keys=True) == before


def test_mark_done_needs_a_name_and_can_be_reopened(pov_all, tenant_for):
    planned(pov_all, tenant_for)
    with pytest.raises(KitError, match="who did it"):
        manual.mark(pov_all, "end.api_clients", "")
    manual.mark(pov_all, "end.api_clients", "Pat (Acme IT)")
    s = {x["key"]: x for x in manual.guide(pov_all)}["end.api_clients"]
    assert s["status"] == "done" and s["by"] == "Pat (Acme IT)"
    manual.mark(pov_all, "end.api_clients", None, undo=True)
    assert {x["key"]: x for x in manual.guide(pov_all)}["end.api_clients"]["status"] == "open"
    with pytest.raises(KitError, match="No step"):
        manual.mark(pov_all, "nope", "x")


def test_sheet_for_the_admin_has_steps_and_no_secrets(pov_all, tenant_for):
    planned(pov_all, tenant_for)
    md = manual.sheet_md(pov_all)
    assert "## To connect the POV kit" in md and "## When the POV ends" in md
    assert "Console search:" in md and pov_all.id in md and "<pov-id>" not in md
    assert "fake-provisioning-secret" not in md


def test_gui_endpoints(pov_all, tenant_for, monkeypatch):
    planned(pov_all, tenant_for)
    monkeypatch.setattr(gui, "tf", tenant_for)
    code, r = gui.api("GET", "/api/manual", {}, {})
    assert code == 200 and r["steps"]
    code, r = gui.api("POST", "/api/manual/check", {"key": "zia.ca.malware"}, {})
    assert r["ok"] is True, r
    code, r = gui.api("POST", "/api/manual/mark", {"key": "setup.zdx_role", "by": "SE"}, {})
    assert r["done"] is True
    assert "Zscaler POV steps" in gui.api("GET", "/api/manual/sheet", {}, {})[1]["text"]


def test_zpa_check_says_when_the_customer_id_is_missing(pov_all, tenant_for):
    planned(pov_all, tenant_for)
    r = manual.check(pov_all, "setup.zpa_customer_id", tenant_for)
    assert r["ok"] is False and "customer ID" in r["detail"]


def test_by_hand_profiles_only_after_apply(pov_all, tenant_for):
    planned(pov_all, tenant_for)
    assert "zcc.by_hand" not in [s["key"] for s in manual.guide(pov_all)]
