"""The customer-tenant safety rules, each proved against the fake tenant."""
import pytest

from povkit import lifecycle
from povkit.core import GuardError, KitError, naming
from povkit.core.changelist import ChangeList
from povkit.core.guard import LedgerTenant, ReadOnlyTenant
from povkit.core.ledger import Ledger

log = lambda *a: None  # noqa: E731


def approve(pov, tenant_for):
    lifecycle.plan(pov, tenant_for)
    ChangeList(pov.dir).approve("Jane Doe, CISO")


# ---- rule 1: discovery is read-only
def test_read_only_guard_refuses_writes(tenant):
    with pytest.raises(GuardError):
        ReadOnlyTenant(tenant).call("url_filtering", "add_rule", name="x")
    assert tenant.calls == []


def test_discovery_and_plan_make_no_writes(pov, tenant, tenant_for):
    lifecycle.plan(pov, tenant_for)
    assert tenant.writes == []


# ---- rule 2: the approved change list, bound by its hash
def test_plan_hash_is_stable(pov, tenant_for):
    _, _, h1, _ = lifecycle.plan(pov, tenant_for)
    _, _, h2, _ = lifecycle.plan(pov, tenant_for)
    assert h1 == h2


def test_apply_refuses_without_approval(pov, tenant, tenant_for):
    lifecycle.plan(pov, tenant_for)
    with pytest.raises(KitError, match="isn't approved"):
        lifecycle.apply(pov, tenant_for, log)
    assert tenant.writes == []


def test_apply_refuses_when_tenant_changed_after_approval(pov, tenant, tenant_for):
    approve(pov, tenant_for)
    tenant.engines = []   # the DLP engine disappears: the plan would differ from what was approved
    with pytest.raises(KitError, match="changed since the customer approved"):
        lifecycle.apply(pov, tenant_for, log)
    assert tenant.writes == []


def test_replanning_differently_drops_the_approval(pov, tenant, tenant_for):
    approve(pov, tenant_for)
    tenant.cats.remove("SOCIAL_NETWORKING")
    lifecycle.plan(pov, tenant_for)
    assert ChangeList(pov.dir).approval() is None


def test_guard_only_creates_approved_items(pov, tenant):
    led = Ledger(pov.path("ledger.json"), pov.id, pov.prefix)
    t = LedgerTenant(tenant, led, [])
    with pytest.raises(GuardError):
        t.create("zia.url_filtering.anything", "url_filtering", "add_rule", name="ZPOV: x")
    with pytest.raises(GuardError):
        t.call("url_filtering", "delete_rule", 1)
    assert tenant.writes == []


# ---- apply does exactly the approved list, scoped and labelled
def test_apply_creates_scoped_labelled_rules(pov, tenant, tenant_for):
    approve(pov, tenant_for)
    led = lifecycle.apply(pov, tenant_for, log)
    label = tenant.rules["label"][0]
    assert tenant.writes[0][1] == "add_label"           # the label first: a refused write stops apply early
    for kind in ("url_filtering", "ssl", "dlp", "cloud_app_control"):
        for r in [r for r in tenant.rules[kind] if naming.has_prefix(r["name"], pov.prefix)]:
            assert r["groups"] == [77]                   # the pilot group only
            assert r["labels"] == [label["id"]]              # an integer ID, as ZIA expects
            assert naming.has_stamp(r["description"], pov.id)
            assert led.by_id("zia", kind, r["id"])
    zia_writes = [w[:2] for w in tenant.writes if not w[0].startswith("zcc")]
    assert zia_writes[-1] == ("activate", "activate")    # ZIA activates once, after its last rule


def test_rules_go_on_top_in_template_order(pov, tenant, tenant_for):
    approve(pov, tenant_for)
    lifecycle.apply(pov, tenant_for, log)
    ssl = sorted(tenant.rules["ssl"], key=lambda r: r["order"])
    assert [r["name"] for r in ssl] == ["ZPOV: Bypass finance and health", "ZPOV: Inspect pilot group",
                                        "Corp: Inspect all"]   # bypass above inspect; customer's rule keeps its place


# ---- rule 4: existing customer objects are never written
def test_customer_objects_are_never_written(pov, tenant, tenant_for):
    approve(pov, tenant_for)
    lifecycle.apply(pov, tenant_for, log)
    lifecycle.teardown(pov, tenant_for, log)
    touched = {(res, a[0] if a else kw.get("name")) for res, m, a, kw in tenant.writes if not m.startswith("add")
               and res != "activate"}
    assert all(str(x[1]) not in ("1", "2") for x in touched)
    assert tenant.by_name("url_filtering", "Corp: Block adult")["groups"] == [{"id": 78}]
    assert tenant.by_name("ssl", "Corp: Inspect all")


# ---- rule 3: teardown removes only what the ledger owns
def test_teardown_leaves_lookalikes_and_renamed_objects(pov, tenant, tenant_for):
    approve(pov, tenant_for)
    lifecycle.apply(pov, tenant_for, log)
    tenant.rules["url_filtering"].append({"id": 5, "name": "ZPOV: someone else's", "order": 99,
                                          "description": "not ours"})
    mine = tenant.by_name("url_filtering", "ZPOV: Caution social")
    mine["name"] = "Corp: kept by customer"              # renamed: no longer the POV's
    checks = lifecycle.teardown(pov, tenant_for, log)
    names = {r["name"] for r in tenant.rules["url_filtering"]}
    assert names == {"Corp: Block adult", "ZPOV: someone else's", "Corp: kept by customer"}
    assert any("Left in place" in c["label"] for c in checks)
    assert tenant.rules["dlp"] == [] and tenant.rules["label"] == []


def test_restamped_object_is_left_alone(pov, tenant, tenant_for):
    approve(pov, tenant_for)
    lifecycle.apply(pov, tenant_for, log)
    tenant.by_name("dlp", "ZPOV: Block card numbers")["description"] = "edited by the customer"
    lifecycle.teardown(pov, tenant_for, log)
    assert tenant.by_name("dlp", "ZPOV: Block card numbers")


# ---- rule 6: activation never ships someone else's work
def test_pending_changes_stop_apply_and_teardown(pov, tenant, tenant_for):
    approve(pov, tenant_for)
    tenant.activation = "PENDING"
    with pytest.raises(KitError, match="waiting to be activated"):
        lifecycle.apply(pov, tenant_for, log)
    assert tenant.writes == []


def test_apply_is_safe_to_rerun(pov, tenant, tenant_for):
    approve(pov, tenant_for)
    lifecycle.apply(pov, tenant_for, log)
    n = len([w for w in tenant.writes if w[1].startswith("add")])
    lifecycle.apply(pov, tenant_for, log)
    assert len([w for w in tenant.writes if w[1].startswith("add")]) == n


def test_name_collision_with_customer_object_is_left_out(pov, tenant, tenant_for):
    tenant.rules["dlp"].append({"id": 9, "name": "ZPOV: Block card numbers", "description": "customer's"})
    items, notes, _, checks = lifecycle.plan(pov, tenant_for)
    assert not any(i["name"] == "ZPOV: Block card numbers" for i in items)
    assert any(c["id"] == "zia-names" and c["status"] == "fail" for c in checks)
