"""The POV lifecycle across every selected product: discover, plan, apply, status, teardown.

`tenant_for(pov, which)` builds a raw tenant client ('discovery' or 'apply'); it is injected so tests can pass a
fake. Every product sees only a guarded client.
"""
from __future__ import annotations

import time

from . import products
from .core import KitError
from .core.changelist import ChangeList, digest
from .core.checks import FAIL, INFO, OK, WARN, check
from .core.guard import LedgerTenant, ReadOnlyTenant
from .core.ledger import Ledger


SHORT = {"zia": "ZIA", "zcc": "ZCC", "zpa": "ZPA", "aiguard": "AI Guard", "zdx": "ZDX", "casb": "CASB"}


def ledger(pov):
    return Ledger(pov.path("ledger.json"), pov.id, pov.prefix)


def discover(pov, tenant_for):
    t = ReadOnlyTenant(tenant_for(pov, "discovery"))
    snaps, checks = {}, []
    for p in products.selected(pov.products):
        if not p.ready:
            checks.append(check(f"{p.name}-later", p.title, INFO, f"arrives in {p.phase}; its criteria are in the catalog"))
            continue
        try:
            s, c = p.discover(t, pov)
        except KitError as e:
            s, c = {}, [check(f"{p.name}-discover", f"{p.title} discovery", FAIL, str(e)[:200])]
        snaps[p.name] = s
        checks += [dict(x, label=f"{SHORT.get(p.name, p.title)}: {x['label']}") for x in c]
    pov.write_json("discovery.json", {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "products": snaps})
    pov.log("discover", f"discovery: {len(checks)} checks")
    return snaps, checks


def make_plan(pov, snaps):
    items, notes = [], []
    for p in products.selected(pov.products):
        if not p.ready or p.name not in snaps:
            continue
        # Client Connector and CASB scope their objects to ZIA's pilot group, so they see ZIA's discovery too
        i, n = (p.plan(pov, snaps[p.name], snaps.get("zia")) if p.name in ("zcc", "casb") else p.plan(pov, snaps[p.name]))
        items += i
        notes += n
    return items, notes


def plan(pov, tenant_for):
    snaps, checks = discover(pov, tenant_for)
    items, notes = make_plan(pov, snaps)
    h = ChangeList(pov.dir).write(items, notes)
    from .report import render_plan
    pov.path("plan.html").write_text(render_plan(pov, items, notes, h), encoding="utf-8")
    pov.log("plan", f"change list {h[:12]}: {len(items)} items")
    return items, notes, h, checks


def apply(pov, tenant_for, log):
    snaps, checks = discover(pov, tenant_for)
    failed = [c for c in checks if c["status"] == FAIL]
    if failed:
        raise KitError("Discovery found problems, so nothing was applied: " + "; ".join(c["label"] for c in failed))
    items, _ = make_plan(pov, snaps)
    approval = ChangeList(pov.dir).require_approved(items)
    led = ledger(pov)
    t = LedgerTenant(tenant_for(pov, "apply"), led, items)
    pov.log("apply", f"apply start, approved {approval['hash'][:12]} by {approval['by']}")
    for p in products.selected(pov.products):
        if p.ready:
            p.apply(t, pov, items, log)
    pov.cfg["state"] = "applied"
    pov.save()
    pov.log("apply", f"apply done: {len(led.active())} POV objects")
    return led


def status(pov, tenant_for, fix=False, log=lambda lvl, msg: None):
    snaps, checks = discover(pov, tenant_for)
    items, _ = make_plan(pov, snaps)
    cl = ChangeList(pov.dir)
    a = cl.approval()
    if a:
        same = digest(items) == a["hash"]
        checks.append(check("plan-approved", "Tenant still matches the approved change list", OK if same else WARN,
                            f"approved by {a['by']} on {a['at'][:10]}",
                            "" if same else "Something the plan depends on changed (a group, a category, an engine). "
                            "Run `pov-kit plan` and get it approved again."))
    else:
        checks.append(check("plan-approved", "Change list approved", WARN, "not yet", "Run `pov-kit approve`."))
    led = ledger(pov)
    ro = ReadOnlyTenant(tenant_for(pov, "discovery"))
    for p in products.selected(pov.products):
        if p.ready:
            checks += [dict(x, label=f"{SHORT.get(p.name, p.title)}: {x['label']}") for x in p.drift(ro, pov, led, items)]
    open_actions = [i for i in items if i["action"] == "customer_action"]
    if open_actions:
        checks.append(check("customer-actions", "Customer actions to confirm", INFO,
                            "; ".join(i["name"] for i in open_actions), "Confirm each with `pov-kit attest`."))
    if fix:
        if not a or digest(items) != a["hash"]:
            raise KitError("Fix drift needs the approved change list to still match the tenant. Run `pov-kit plan` "
                           "and get it approved again first.")
        t = LedgerTenant(tenant_for(pov, "apply"), led, items)
        for p in products.selected(pov.products):
            if hasattr(p, "fix_drift"):
                p.fix_drift(t, pov, led, items, log)
            if hasattr(p, "adopt_by_name"):
                p.adopt_by_name(t, pov, items, log)
        apply(pov, tenant_for, log)   # recreates anything missing, still bound to the approval
    return checks


def teardown(pov, tenant_for, log, include_adopted=False):
    led = ledger(pov)
    if not led.active():
        return [check("teardown", "Nothing to remove", OK, "the ledger has no active POV objects")]
    pov.include_adopted = include_adopted
    t = LedgerTenant(tenant_for(pov, "apply"), led, [])
    out = []
    for p in reversed(products.selected(pov.products)):   # zcc before zia
        if p.ready and led.active(p.name):
            out += p.teardown(t, pov, led, log)
    pov.cfg["state"] = "torn_down" if not led.active() else "partly_torn_down"
    pov.save()
    pov.log("teardown", f"teardown: {len(led.active())} objects left")
    return out


def api_proofs(pov, tenant_for, ids=None):
    """Run each product's automated API proofs with the read-only discovery client; save them for the report."""
    from . import evidence
    t = ReadOnlyTenant(tenant_for(pov, "discovery"))
    led = ledger(pov)
    saved = pov.read_json("api_proofs.json", {}) or {}
    ran = {}
    for c in evidence.selected_criteria(pov, ids):
        if "api" not in c["proofs"]:
            continue
        p = products.get(c["product"])
        if not hasattr(p, "api_proof"):
            continue
        try:
            res = p.api_proof(t, pov, led, c)
        except KitError as e:
            res = {"status": "incomplete", "detail": f"couldn't run: {str(e)[:160]}"}
        if res:
            res["at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            saved[c["id"]] = ran[c["id"]] = res
    pov.write_json("api_proofs.json", saved)
    pov.log("test", f"API proofs: {len(ran)} run")
    return ran
