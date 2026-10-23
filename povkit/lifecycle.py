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


SHORT = {"zid": "ZIdentity", "zia": "ZIA", "zcc": "ZCC", "zpa": "ZPA", "aiguard": "AI Guard", "zdx": "ZDX", "casb": "CASB"}


def ledger(pov):
    return Ledger(pov.path("ledger.json"), pov.id, pov.prefix)


def in_play(pov, led=None):
    """The products to check and tear down: the POV's, plus any that still have objects in its ledger (a setting
    changed after apply must never strand objects in the tenant)."""
    led = led or ledger(pov)
    return products.selected(set(pov.products) | {e["product"] for e in led.active()})


NEEDS = {"zcc": ("zia",), "casb": ("zia",), "zia": ("zid",)}   # what a product's change-list items build on


def wait_for(pov, checks, ran=None):
    """{product: why} for the products that can't go ahead yet (a failing check of their own, or a product they build
    on that's waiting), as long as something else can: a POV with nothing ready keeps its failures as failures."""
    selected = [p.name for p in products.selected(pov.products) if p.ready and (ran is None or p.name in ran)]
    waiting = {}
    for name in selected:
        fails = [c for c in checks if c.get("product") == name and c["status"] == FAIL]
        if fails:
            waiting[name] = "; ".join(c["label"].split(": ", 1)[-1] for c in fails)
    changed = True
    while changed:
        changed = False
        for name in selected:
            dep = next((d for d in NEEDS.get(name, ()) if d in waiting and d in selected), None)
            if dep and name not in waiting:
                waiting[name] = f"{SHORT.get(dep, dep)} first"
                changed = True
    if not waiting or all(n in waiting for n in selected):
        return {}
    return waiting


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
        checks += [dict(x, label=f"{SHORT.get(p.name, p.title)}: {x['label']}", product=p.name) for x in c]
    # the identity step: who the pilot users are and how they sign in, across products (read-only too)
    from . import identity
    try:
        ident, ic = identity.discover(t, pov, snaps)
    except KitError as e:
        ident, ic = {}, [check("id-read", "Pilot users readable", FAIL, str(e)[:200])]
    snaps["identity"] = ident
    checks += [dict(x, label=f"Identity: {x['label']}") for x in ic]
    waiting = wait_for(pov, checks, [n for n in snaps if n != "identity"])
    if waiting:   # these products sit out this change list; the rest of the POV goes ahead
        for x in checks:
            if x.get("product") in waiting and x["status"] == FAIL:
                x.update(status=WARN, waiting=True)
        for name, why in waiting.items():
            checks.append(check(f"{name}-waiting", f"{SHORT.get(name, name)}: added later", INFO, "waiting on: " + why,
                                "The rest of the POV goes ahead without it. Once that's done, run the checks again "
                                "and approve the new change list, which adds it.") | {"waiting": True, "product": name})
            snaps.pop(name, None)
    if waiting:
        snaps["_waiting"] = waiting
    snaps_out = snaps
    pov.write_json("discovery.json", {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "products": snaps_out})
    pov.log("discover", f"discovery: {len(checks)} checks")
    return snaps, checks


def make_plan(pov, snaps):
    items, notes = [], []
    for name, why in (snaps.get("_waiting") or {}).items():
        notes.append(f"{SHORT.get(name, name)} is added later (waiting on: {why}).")
    if "zia" in snaps:   # ZIA keeps the identity step's sign-in sites out of SSL inspection
        snaps = dict(snaps, zia=dict(snaps["zia"], identity=snaps.get("identity") or {}))
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
    from . import backup
    try:
        for p in products.selected(pov.products):
            if p.ready and p.name in snaps:   # a product waiting on something sits this apply out
                p.apply(t, pov, items, log)
                backup.save(pov)   # after each product, so an apply that stops halfway is still backed up
    finally:
        backup.save(pov)
    pov.cfg["state"] = "applied"
    pov.save()
    pov.log("apply", f"apply done: {len(led.active())} POV objects")
    backup.save(pov)
    return led


def status(pov, tenant_for, fix=False, log=lambda lvl, msg: None):
    from .core.guard import CachedReads
    shared = {}
    raw_tenant_for = tenant_for

    def reads(p, which):   # one signed-in client and one read cache for this check (the fix below writes afresh)
        if which != "discovery":
            return raw_tenant_for(p, which)
        if "d" not in shared:
            shared["d"] = CachedReads(raw_tenant_for(p, which))
        return shared["d"]
    snaps, checks = discover(pov, reads)
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
    ro = ReadOnlyTenant(reads(pov, "discovery"))
    for p in in_play(pov, led):
        if p.ready:
            checks += [dict(x, label=f"{SHORT.get(p.name, p.title)}: {x['label']}") for x in p.drift(ro, pov, led, items)]
    from . import backup, remind
    checks.append(remind.end_check(pov))
    checks.append(backup.check(pov))
    from . import mcp
    checks.append(mcp.status(pov))
    open_actions = [i for i in items if i["action"] == "customer_action"]
    if open_actions:
        checks.append(check("customer-actions", "Customer actions to confirm", INFO,
                            "; ".join(i["name"] for i in open_actions), "Confirm each with `pov-kit attest`."))
    if fix:
        if not a or digest(items) != a["hash"]:
            raise KitError("Fix drift needs the approved change list to still match the tenant. Run `pov-kit plan` "
                           "and get it approved again first.")
        def fix_pass():
            for p in products.selected(pov.products):
                t = LedgerTenant(tenant_for(pov, "apply"), ledger(pov), items)   # fresh IDs: a fix may change them
                if hasattr(p, "fix_drift"):
                    p.fix_drift(t, pov, t.ledger, items, log)
                if hasattr(p, "adopt_by_name"):
                    p.adopt_by_name(t, pov, items, log)
        fix_pass()
        apply(pov, tenant_for, log)   # recreates anything missing, still bound to the approval
        fix_pass()                    # then re-scope rules whose group apply just recreated
    return checks


def teardown(pov, tenant_for, log, include_adopted=False):
    led = ledger(pov)
    if not led.active():
        return [check("teardown", "Nothing to remove", OK, "the ledger has no active POV objects")]
    pov.include_adopted = include_adopted
    t = LedgerTenant(tenant_for(pov, "apply"), led, [])
    out = []
    from . import backup
    try:
        for p in reversed(in_play(pov, led)):   # zcc before zia, zia before zid
            if p.ready and led.active(p.name):
                out += p.teardown(t, pov, led, log)
    finally:
        backup.save(pov)
    pov.cfg["state"] = "torn_down" if not led.active() else "partly_torn_down"
    pov.save()
    pov.log("teardown", f"teardown: {len(led.active())} objects left")
    from . import backup
    backup.save(pov)
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
        p = products.get("aiguard" if c.get("aiguard") else c["product"])   # use cases' AI Guard test prompts
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
