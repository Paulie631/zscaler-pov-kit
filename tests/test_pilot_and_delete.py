"""The POV's own pilot group in ZIdentity, the Pilot users pickers, and deleting a POV after verifying."""
import pytest

from povkit import delete_pov, gui, lifecycle
from povkit.core import KitError, pov as povs
from povkit.core.changelist import ChangeList
from povkit.products import zid as zidmod

log = lambda *a: None  # noqa: E731


@pytest.fixture
def zpov(home, tenant, monkeypatch):
    monkeypatch.setattr(zidmod, "WAIT", (0, 0))
    tenant.zidentity = True
    p = povs.new("Acme Corp", ["zia", "zcc"])
    p.cfg.update(vanity_domain="acme", pilot_emails=["jane@acme.com", "new.user@acme.com"],
                 identity={"pilot": "create", "create_users": "yes"})
    p.save()
    return p


def approve(p, tenant_for):
    items, _, _, checks = lifecycle.plan(p, tenant_for)
    ChangeList(p.dir).approve("Jane Doe")
    return items, checks


def test_plan_makes_the_group_users_and_customer_actions(zpov, tenant_for):
    items, checks = approve(zpov, tenant_for)
    assert zpov.products[0] == "zid"
    by = {i["key"]: i for i in items}
    assert by["zid.group"]["name"] == "ZPOV - pilot users"
    assert by["zid.user.new-user-acme-com"]["body"]["login_name"] == "new.user@acme.com"
    assert by["zid.group.members"]["body"]["users"] == ["z1", "{ref:zid.user.new-user-acme-com}"]
    assert by["zid.ca.entitlement"]["action"] == "customer_action" and by["zid.ca.passwords"]
    assert by["zid.ca.signin"]["action"] == "customer_action"
    rules = [i for i in items if i["product"] == "zia" and i["body"].get("groups")]
    assert rules and all(i["body"]["groups"] == ["{ref:zid.zia_group}"] for i in rules)
    assert not [c for c in checks if c["status"] == "fail"]


def test_apply_creates_links_and_scopes_then_teardown_cleans_up(zpov, tenant, tenant_for):
    approve(zpov, tenant_for)
    led = lifecycle.apply(zpov, tenant_for, log)
    zg = tenant.zid_groups[0]
    new = next(u for u in tenant.zid_users if u["loginName"] == "new.user@acme.com")
    assert zg["members"] == ["z1", new["id"]] and "zpov:" + zpov.id in zg["description"]
    link = led.linked("zid.zia_group")
    zia_group = next(g for g in tenant.groups if g.get("_zid") == zg["id"])
    assert link and link["id"] == str(zia_group["id"])
    r = tenant.by_name("url_filtering", "ZPOV: Block gambling")
    assert r["groups"] == [zia_group["id"]]
    assert not [c for c in lifecycle.status(zpov, tenant_for) if c["status"] == "fail"]

    lifecycle.teardown(zpov, tenant_for, log)
    assert tenant.zid_groups == [] and not any(g.get("_zid") for g in tenant.groups)
    assert [u["id"] for u in tenant.zid_users] == ["z1", "z2"]        # the customer's own users stay
    led = lifecycle.ledger(zpov)
    assert not led.active() and not led.linked("zid.zia_group")


def test_apply_waits_for_provisioning_and_resumes_without_duplicates(zpov, tenant, tenant_for):
    approve(zpov, tenant_for)
    tenant.zid_provisions = False                     # entitlement not granted yet
    with pytest.raises(KitError, match="click Apply\\s+again"):
        lifecycle.apply(zpov, tenant_for, log)
    assert len(tenant.zid_groups) == 1 and not tenant.rules["url_filtering"][1:]
    tenant.zid_provisions = True
    lifecycle.apply(zpov, tenant_for, log)
    assert len(tenant.zid_groups) == 1 and tenant.by_name("url_filtering", "ZPOV: Block gambling")


def test_missing_users_fail_preflight_unless_creating_them(zpov, tenant_for):
    zpov.cfg["identity"]["create_users"] = "no"
    zpov.save()
    _, checks = approve(zpov, tenant_for)
    bad = {c["id"] for c in checks if c["status"] == "fail"}
    assert "zid-members" in bad


def test_existing_group_mode_is_unchanged(pov, tenant, tenant_for):
    tenant.zidentity = True
    assert "zid" not in pov.products
    items, _, _, _ = lifecycle.plan(pov, tenant_for)
    assert not [i for i in items if i["product"] == "zid"]


def test_pilot_options_for_the_pickers(zpov, tenant, monkeypatch):
    monkeypatch.setattr(gui, "TENANT_FOR", lambda p, w: tenant)
    tenant.groups.append({"id": 99, "name": "ZPOV - pilot users"})
    code, out = gui.api("POST", "/api/pilot/options", {}, {})
    assert code == 200 and out["zidentity"]
    assert out["zia_groups"] == ["Everyone", "POV Pilot"]             # the POV's own groups aren't offered
    assert [u["login"] for u in out["zid_users"]] == ["jane@acme.com", "raj@acme.com"]


# ---- delete a POV, after verifying
def test_delete_is_blocked_while_objects_are_in_the_tenant(pov, tenant_for):
    lifecycle.plan(pov, tenant_for)
    ChangeList(pov.dir).approve("Jane Doe")
    lifecycle.apply(pov, tenant_for, log)
    v = delete_pov.verify(pov, tenant_for)
    assert not v["ok"] and v["still_there"]
    with pytest.raises(KitError, match="Not deleted"):
        delete_pov.delete(pov, pov.id, tenant_for)
    assert pov.dir.exists()


def test_delete_after_teardown_needs_the_id_and_removes_everything(pov, home, tenant_for):
    lifecycle.plan(pov, tenant_for)
    ChangeList(pov.dir).approve("Jane Doe")
    lifecycle.apply(pov, tenant_for, log)
    lifecycle.teardown(pov, tenant_for, log)
    home[(pov.id, "main-client-secret")] = "s3cret"
    assert delete_pov.verify(pov, tenant_for)["ok"]
    with pytest.raises(KitError, match="Type the POV's ID"):
        delete_pov.delete(pov, "wrong", tenant_for)
    r = delete_pov.delete(pov, pov.id, tenant_for)
    assert r["deleted"] == pov.id and not pov.dir.exists() and not povs.CURRENT.exists()
    assert (pov.id, "main-client-secret") not in home


def test_verify_marks_objects_deleted_in_the_console(pov, tenant, tenant_for):
    lifecycle.plan(pov, tenant_for)
    ChangeList(pov.dir).approve("Jane Doe")
    lifecycle.apply(pov, tenant_for, log)
    for k in tenant.rules:                          # someone removed everything by hand
        tenant.rules[k] = [r for r in tenant.rules[k] if not str(r.get("name") or r.get("configured_name") or "").startswith("ZPOV")]
    tenant.groups = [g for g in tenant.groups if not g["name"].startswith("ZPOV")]
    tenant.departments = [d for d in tenant.departments if not d["name"].startswith("ZPOV")]
    tenant.fwds = [f for f in tenant.fwds if not f["name"].startswith("ZPOV")]
    tenant.apps = [a for a in tenant.apps if not a["name"].startswith("ZPOV")]
    v = delete_pov.verify(pov, tenant_for)
    assert v["ok"], v
    assert not lifecycle.ledger(pov).active()


def test_console_delete_flow(pov, tenant, monkeypatch):
    monkeypatch.setattr(gui, "TENANT_FOR", lambda p, w: tenant)
    code, v = gui.api("POST", "/api/pov/delete/check", {"id": pov.id}, {})
    assert code == 200 and v["ok"] and any("folder" in r for r in v["removes"])
    with pytest.raises(KitError):
        gui.api("POST", "/api/pov/delete", {"id": pov.id, "confirm": ""}, {})
    code, r = gui.api("POST", "/api/pov/delete", {"id": pov.id, "confirm": pov.id}, {})
    assert code == 200 and gui.state()["povs"] == []


def test_terraform_handover_keeps_the_zidentity_group_and_allows_delete(zpov, tenant, tenant_for):
    from povkit import handover
    approve(zpov, tenant_for)
    lifecycle.apply(zpov, tenant_for, log)
    out, exported, skipped = handover.terraform(zpov, lifecycle.ledger(zpov))
    assert {e["product"] for e, _ in skipped} >= {"zid"}
    assert "ZPOV - pilot users" in (out / "README.md").read_text()
    led = lifecycle.ledger(zpov)
    assert not led.active() and not led.linked("zid.zia_group")
    assert tenant.zid_groups                                   # kept in the tenant, the customer's now
    v = delete_pov.verify(zpov, tenant_for)
    assert v["ok"] and v["notes"]


# ---- review findings (0.9.1)
def test_teardown_keeps_the_group_while_a_kept_rule_still_uses_it(zpov, tenant, tenant_for):
    approve(zpov, tenant_for)
    lifecycle.apply(zpov, tenant_for, log)
    r = tenant.by_name("url_filtering", "ZPOV: Block gambling")
    r["name"] = "Customer kept: gambling"                       # renamed, so ZIA teardown leaves it alone
    checks = lifecycle.teardown(zpov, tenant_for, log)
    assert tenant.zid_groups, "the group must stay while a rule applies to it"
    assert any(c["id"] == "zid-left" and "Customer kept" in c["detail"] for c in checks)
    r["groups"] = [78]                                          # the customer points it elsewhere
    lifecycle.teardown(zpov, tenant_for, log)
    assert not tenant.zid_groups


def test_fix_drift_recreates_a_deleted_group_and_rescopes_the_rules(zpov, tenant, tenant_for):
    approve(zpov, tenant_for)
    lifecycle.apply(zpov, tenant_for, log)
    old = tenant.zid_groups[0]["id"]
    tenant.call("zid.groups", "delete_group", old)              # deleted in the ZIdentity console
    lifecycle.status(zpov, tenant_for, fix=True)
    new = next(g for g in tenant.groups if g.get("_zid") == tenant.zid_groups[0]["id"])
    assert tenant.zid_groups[0]["id"] != old
    assert tenant.by_name("url_filtering", "ZPOV: Block gambling")["groups"] == [new["id"]]
    assert not [c for c in lifecycle.status(zpov, tenant_for) if c["status"] == "fail"]


def test_pilot_mode_cant_change_while_the_group_is_in_the_tenant(zpov, tenant_for):
    from povkit import settings
    approve(zpov, tenant_for)
    lifecycle.apply(zpov, tenant_for, log)
    with pytest.raises(KitError, match="can't change"):
        settings.set_value(zpov, "identity.pilot", "existing")


def test_teardown_covers_products_left_in_the_ledger(zpov, tenant, tenant_for):
    approve(zpov, tenant_for)
    lifecycle.apply(zpov, tenant_for, log)
    zpov.cfg["identity"]["pilot"] = "existing"                  # changed behind the kit's back
    zpov.save()
    lifecycle.teardown(zpov, tenant_for, log)
    assert not tenant.zid_groups and not lifecycle.ledger(zpov).active()


def test_delete_refused_while_a_job_runs_and_ids_are_checked(pov, monkeypatch):
    monkeypatch.setitem(gui.JOBS, "j1", {"kind": "apply", "pov": pov.id, "done": False})
    with pytest.raises(KitError, match="still running"):
        gui.api("POST", "/api/pov/delete", {"id": pov.id, "confirm": pov.id}, {})
    assert pov.dir.exists()
    with pytest.raises(KitError, match="isn't a POV ID"):
        povs.Pov("../../etc")
