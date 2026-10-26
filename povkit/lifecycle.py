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


SHORT = {"zid": "ZIdentity", "zia": "ZIA", "zcc": "ZCC", "zpa": "ZPA", "aiguard": "AI Guard", "zdx": "ZDX", "casb": "CASB", "eai": "Endpoint AI",
         "aispm": "AI-SPM", "dspm": "DSPM", "airt": "AI Red Teaming",
         "easm": "EASM", "zbi": "Business Insights", "zms": "Microsegmentation", "ztw": "Cloud Connector"}


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


PILOT_PRODUCTS = {"zia", "zcc", "zpa", "zdx", "casb", "zid"}


AREA = {"zia": "ZIA", "zpa": "ZPA", "zcc": "Client Connector", "zid": "ZIdentity", "zdx": "ZDX", "aiguard": "AI Guard",
        "zwa": "Workflow Automation", "zeasm": "EASM", "zbi": "Business Insights", "zms": "Microsegmentation",
        "ztw": "Cloud Connector", "zins": "Insights", "ztb": "Zero Trust Branch"}


def describe_call(resource, method):
    """'zpa.application_segment', 'list_segments' -> 'ZPA application segment: list segments' (for the live log)."""
    pre, _, area = resource.partition(".") if "." in resource else ("zia", "", resource)
    return f"{AREA.get(pre, pre.upper())} {area.replace('_', ' ')}: {method.replace('_', ' ')}"


class Narrated:
    """A tenant that says each call it makes, as it makes it, so the console can show what the kit is doing."""
    def __init__(self, tenant, log):
        self._t, self._log = tenant, log

    def call(self, resource, method, *a, **kw):
        self._log("info", "  " + describe_call(resource, method))
        return self._t.call(resource, method, *a, **kw)

    def __getattr__(self, name):
        return getattr(self._t, name)


def _epoch(at):
    try:
        import calendar
        return calendar.timegm(time.strptime(str(at)[:19], "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, TypeError):
        return 0


def _tally(c):
    bad = sum(1 for x in c if x["status"] == FAIL)
    warn = sum(1 for x in c if x["status"] == WARN)
    return ("fail" if bad else "warn" if warn else "ok",
            f"{len(c)} check{'' if len(c) == 1 else 's'}" + (f", {bad} to fix" if bad else "") + (f", {warn} to look at" if warn else ""))


def discover(pov, tenant_for, log=None, only=None, reuse_minutes=0):
    """only: re-read just these products, and plan the rest from the last reading (a quick apply of one product's
    setting doesn't need the whole tenant read again). The others' checks aren't repeated.
    reuse_minutes: use the last reading as it is when it's this recent and nothing was applied since (Claude's
    snapshot for a use case); 0 always reads.
    Products are read at the same time, each with its own signed-in client: their APIs are separate, so this is as
    fast as the slowest product rather than all of them added up."""
    say = log or (lambda *a: None)
    last = pov.read_json("discovery.json", {}) or {} if (only or reuse_minutes) else {}
    cached = last.get("products") or {}
    when = str(last.get("at") or "")[11:16]
    if reuse_minutes and cached:
        age = time.time() - _epoch(last.get("at"))
        led_at = pov.path("ledger.json").stat().st_mtime if pov.path("ledger.json").exists() else 0
        cfg_at = pov.path("pov.json").stat().st_mtime if pov.path("pov.json").exists() else 0   # settings since?
        if age <= reuse_minutes * 60 and max(led_at, cfg_at) <= _epoch(last.get("at")) + 1:
            say("ok", f"Using the tenant reading from {when} UTC ({max(1, int(age // 60))} min ago; nothing applied since)")
            return dict(cached), list(last.get("checks") or [])
    snaps, checks, todo = {}, [], []
    for p in products.selected(pov.products):
        if not p.ready:
            checks.append(check(f"{p.name}-later", p.title, INFO, getattr(p, "later_note", "")
                                or f"arrives in {p.phase}; its criteria are in the catalog"))
        elif only and p.name not in only and p.name in cached:
            snaps[p.name] = cached[p.name]
            say("info", f"{p.title}: not changing it, so using the last reading ({when} UTC) instead of reading it again")
        else:
            todo.append(p)

    def read(p, client):
        t = ReadOnlyTenant(client)
        t0 = time.time()
        say("info", f"{p.title}: reading the tenant (read-only)")
        try:
            s, c = p.discover(t, pov)
        except KitError as e:
            s, c = {}, [check(f"{p.name}-discover", f"{p.title} discovery", FAIL, str(e)[:200])]
        lvl, txt = _tally(c)
        say(lvl, f"{p.title}: {txt} ({time.time() - t0:.1f} s)")
        return s, c
    from .core.guard import CachedReads
    # signed-in clients made here, one per product; a list asked for twice in one reading is answered from memory
    # (only real calls are narrated)
    clients = [(p, CachedReads(Narrated(tenant_for(pov, "discovery"), log) if log else tenant_for(pov, "discovery")))
               for p in todo]
    if len(clients) > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(6, len(clients))) as ex:
            found = list(ex.map(lambda pc: read(*pc), clients))
    else:
        found = [read(*pc) for pc in clients]
    # the pilot users step reads ZIA's users and groups again: through ZIA's own memory when ZIA was just read
    shared = next((c for p, c in clients if p.name == "zia"), clients[0][1] if clients else None)
    t = ReadOnlyTenant(shared or (Narrated(tenant_for(pov, "discovery"), log) if log else tenant_for(pov, "discovery")))
    for (p, _), (s, c) in zip(clients, found, strict=True):   # in product order, so checks always read the same way
        snaps[p.name] = s
        checks += [dict(x, label=f"{SHORT.get(p.name, p.title)}: {x['label']}", product=p.name) for x in c]
    # the identity step: who the pilot users are and how they sign in, across products (read-only too)
    from . import identity
    if not set(pov.products) & PILOT_PRODUCTS:   # AI Guard alone has no pilot users (its app is the scope)
        ident, ic = {}, []
    elif only and not set(only) & PILOT_PRODUCTS and "identity" in cached:
        ident, ic = cached["identity"], []
        say("info", "Pilot users: unchanged, using the last reading")
    else:
        say("info", "Pilot users: finding them across products (read-only)")
        try:
            ident, ic = identity.discover(t, pov, snaps)
        except KitError as e:
            ident, ic = {}, [check("id-read", "Pilot users readable", FAIL, str(e)[:200])]
    snaps["identity"] = ident
    if ic:
        lvl, txt = _tally(ic)
        say(lvl, f"Pilot users: {txt}")
    checks += [dict(x, label=f"Identity: {x['label']}") for x in ic]
    name_clash(pov, checks)
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
    pov.write_json("discovery.json", {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "products": snaps_out,
                                      "checks": checks})
    pov.log("discover", f"discovery: {len(checks)} checks")
    return snaps, checks


def name_clash(pov, checks):
    """Names taken in the tenant: say whose they are when another POV on this laptop uses the same prefix (two POVs
    in one lab tenant, say), and how to get past it."""
    clashes = [c for c in checks if c["id"].endswith("-names") and c["status"] == FAIL]
    if not clashes:
        return
    from .core import pov as povs
    others = povs.prefixes_in_use(exclude=pov.id).get(pov.prefix) or []
    base = pov.prefix.rstrip("0123456789") or pov.prefix
    used = set(povs.prefixes_in_use(exclude=pov.id)) | {pov.prefix}
    alt = next(f"{base}{n}" for n in range(2, 100) if f"{base}{n}" not in used)
    applied = bool(ledger(pov).active())
    for c in clashes:
        who = (f"POV {', '.join(others)} on this laptop already has these names in the tenant (same prefix "
               f"'{pov.prefix}'). " if others else f"Objects named with this POV's prefix '{pov.prefix}' are already "
               "in the tenant, and aren't this POV's. ")
        fix = (f"Give this POV its own prefix: Use prefix {alt} on the Apply step (or `pov-kit set prefix {alt}`), "
               "then approve the new change list. " if not applied else "")
        fix += (f"Or remove POV {others[0]} first (Handover)." if others else
                "Or check who made them (the Logs of the POV that did), and remove them if they're left over.")
        c.update(detail=who + c.get("detail", ""), fix=fix, prefix_alt=None if applied else alt)


def make_plan(pov, snaps, log=None):
    say = log or (lambda *a: None)
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
        made = [x for x in i if x["action"] != "customer_action"]
        say("ok" if made else "info", f"{p.title}: {len(made)} object{'' if len(made) == 1 else 's'} to make"
            + (f", {len(i) - len(made)} step{'' if len(i) - len(made) == 1 else 's'} for people" if len(i) > len(made) else ""))
        items += i
        notes += n
    return items, notes


def plan(pov, tenant_for, log=None, reuse_minutes=0):
    """reuse_minutes: plan from the last tenant reading when it's this recent and nothing was applied or changed in
    the POV's settings since (the setup steps, moments after Quick start or a setup step read it). 0 always reads."""
    return _plan(pov, tenant_for, log, reuse_minutes=reuse_minutes)[:4]


def _plan(pov, tenant_for, log=None, only=None, reuse_minutes=0):
    snaps, checks = discover(pov, tenant_for, log, only, reuse_minutes=reuse_minutes)
    if log:
        log("info", "Working out what to make (nothing is written yet)")
    items, notes = make_plan(pov, snaps, log)
    h = ChangeList(pov.dir).write(items, notes)
    from .report import render_plan
    pov.path("plan.html").write_text(render_plan(pov, items, notes, h), encoding="utf-8")
    pov.log("plan", f"change list {h[:12]}: {len(items)} items")
    if log:
        log("ok", f"Ready: {len(items)} items. Nothing has changed in the tenant.")
    return items, notes, h, checks, snaps


def _uc_key(uc_id):
    import re as _re
    m = _re.search(r"(\d+)$", str(uc_id))
    if not m:
        raise KitError(f"'{uc_id}' isn't a use case ID.")
    return _re.compile(rf"\.uc{int(m.group(1)):02d}([.-]|$)")


def make_preview(pov, tenant_for, uc_id):
    """What making one use case in the tenant would change now: its own items not yet there, and anything else
    waiting in the change list (apply makes the whole approved list). Writes the fresh change list. -> summary"""
    pat = _uc_key(uc_id)
    items, notes, h, checks = plan(pov, tenant_for)
    led = ledger(pov)
    pending = [i for i in items if i["action"] in ("create", "create_or_adopt") and not led.find(i["key"])]
    mine = [i for i in pending if pat.search(i["key"]) or uc_id in (i.get("criteria") or [])]
    others = [i for i in pending if i not in mine]
    a = ChangeList(pov.dir).approval()
    row = lambda i: {"name": i["name"], "kind": i["kind"], "product": i["product"], "affects": i.get("affects", "")}  # noqa: E731
    return {"hash": h, "mine": [row(i) for i in mine], "others": [row(i) for i in others],
            "blocked": [c["label"] + (f": {c['detail']}" if c.get("detail") else "") for c in checks if c["status"] == FAIL],
            "mode": pov.cfg.get("approval") or "se", "approved": bool(a and a["hash"] == h),
            "notes": [n for n in notes if uc_id in n or "UC" in n][:6]}


def make_now(pov, tenant_for, uc_id, seen_hash, by, log=lambda *a: None):
    """Signs off (SE sign-off POVs) the change list the SE just reviewed for this use case, then applies it.
    One tenant reading: the preview's, when it's minutes old and nothing was applied or changed since (the change
    list's hash still has to match what the SE saw), and apply builds from the same reading."""
    items, notes, h, checks, snaps = _plan(pov, tenant_for, log, reuse_minutes=10)
    if h != seen_hash:
        raise KitError("The tenant or the change list changed since you reviewed it. Review it again, then make it.")
    if any(c["status"] == FAIL for c in checks):
        raise KitError("The checks found problems, so nothing was changed. Fix them first (Setup › Review & apply).")
    cl = ChangeList(pov.dir)
    a = cl.approval()
    if not (a and a["hash"] == h):
        if (pov.cfg.get("approval") or "se") != "se":
            raise KitError("This POV needs the customer's approval of the change list first: Setup › Sign-off sends "
                           "them the change-list page. Nothing was changed.")
        if not str(by or "").strip():
            raise KitError("Type your name for the sign-off.")
        rec = cl.approve(by, f"Reviewed by the SE from Use cases ({uc_id}); customer sign-off not required for this POV.")
        pov.log("approve", f"change list {rec['hash'][:12]} approved by {rec['by']} for {uc_id}")
        log("ok", f"Change list signed off by {rec['by']}")
    led = apply(pov, tenant_for, log, found=(snaps, checks))
    return len(led.active())


def changes_made(pov):
    """The POV's objects in the tenant, newest first, with why each was made (from the change list)."""
    led = ledger(pov)
    try:
        why = {i["key"]: i for i in ChangeList(pov.dir).plan().get("items", [])}
    except KitError:
        why = {}
    out = []
    for e in reversed(led.entries):
        if e["state"] not in ("owned", "adopted", "deleted"):
            continue
        it = why.get(e["key"]) or {}
        out.append({"name": e["name"], "product": e["product"], "kind": e["kind"], "state": e["state"],
                    "at": e.get(f"{e['state']}_at") or e.get("at"), "why": it.get("why") or "",
                    "affects": it.get("affects") or "", "criteria": it.get("criteria") or []})
    return out


def pending(pov):
    """What the change list on disk would still create (not in the tenant yet)."""
    led = ledger(pov)
    try:
        items = ChangeList(pov.dir).plan().get("items", [])
    except KitError:
        return []
    return [{"name": i["name"], "product": i["product"], "kind": i["kind"], "affects": i.get("affects", "")}
            for i in items if i["action"] in ("create", "create_or_adopt") and not led.find(i["key"])]


def quick_apply(pov, tenant_for, only, why, by=None, log=lambda *a: None, reuse_minutes=0):
    """Applies one product's part of the change list straight away, for a setting the SE just saved (SE sign-off POVs
    only): the change list is made and signed off in the SE's name, then only that product's items are applied.
    -> what was applied"""
    if (pov.cfg.get("approval") or "se") != "se":
        raise KitError("This POV needs the customer's approval of each change list, so the setting is saved but not "
                       "applied: Setup › Sign-off, then Apply.")
    last_by = (ChangeList(pov.dir).approval() or {}).get("by")   # making the list again clears the old approval
    from .core.guard import CachedReads
    shared = CachedReads(tenant_for(pov, "discovery"))   # one sign-in and one read of each list, for both steps
    reads = lambda p, which: shared if which == "discovery" else tenant_for(p, which)  # noqa: E731
    items, notes, h, checks, snaps = _plan(pov, reads, log, only=set(only) if only else None,
                                           reuse_minutes=reuse_minutes)
    bad = [c["label"] for c in checks if c["status"] == FAIL]
    if bad:
        raise KitError("Saved, but not applied: the checks found problems (" + "; ".join(bad[:3]) + "). Setup › Review & apply.")
    cl = ChangeList(pov.dir)
    a = cl.approval()
    if not (a and a["hash"] == h):
        who = (by or "").strip() or last_by or "SE"
        rec = cl.approve(who, f"Signed off by the SE when saving {why} (customer sign-off not required for this POV).")
        pov.log("approve", f"change list {rec['hash'][:12]} approved by {rec['by']} ({why})")
        log("ok", f"Signed off as {rec['by']}")
    led = ledger(pov)
    before = {e["key"] for e in led.active()}
    todo = [i for i in items if i["action"] in ("create", "create_or_adopt") and not led.find(i["key"])
            and (not only or i["product"] in only)]
    log("info", f"Making {len(todo)} object{'' if len(todo) == 1 else 's'} now: " + ", ".join(i["name"] for i in todo)
        if todo else "Nothing new to make: the tenant already matches")
    apply(pov, tenant_for, log, only=set(only) if only else None, found=(snaps, checks))
    made = [e["name"] for e in ledger(pov).active() if e["key"] not in before]
    return {"made": made}


def apply(pov, tenant_for, log, only=None, found=None):
    """found: (snaps, checks) from a discovery made moments ago in the same job, so it isn't read twice."""
    snaps, checks = found or discover(pov, tenant_for)
    failed = [c for c in checks if c["status"] == FAIL]
    if failed:
        why = "; ".join(c["label"] for c in failed)
        fixes = list(dict.fromkeys(c["fix"] for c in failed if c.get("fix")))
        raise KitError("Discovery found problems, so nothing was applied: " + why + (". " + " ".join(fixes[:2]) if fixes else ""))
    items, _ = make_plan(pov, snaps)
    approval = ChangeList(pov.dir).require_approved(items)
    led = ledger(pov)
    t = LedgerTenant(tenant_for(pov, "apply"), led, items)
    pov.log("apply", f"apply start, approved {approval['hash'][:12]} by {approval['by']}")
    from . import backup
    try:
        for p in products.selected(pov.products):
            if only and p.name not in only:   # a quick apply of one product's setting (quick_apply)
                continue
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
    if (pov.cfg.get("approval") or "se") == "se":   # the SE applies directly: what's waiting, not who signed
        led0 = ledger(pov)
        wait = [i["name"] for i in items if i["action"] in ("create", "create_or_adopt") and not led0.find(i["key"])]
        checks.append(check("plan-approved", "Everything planned is in the tenant", INFO if wait else OK,
                            f"waiting to apply: {', '.join(wait[:6])}" + (f" and {len(wait) - 6} more" if len(wait) > 6
                                                                         else "") if wait else "nothing waiting",
                            "Setup › Apply." if wait else ""))
    elif a:
        same = digest(items) == a["hash"]
        checks.append(check("plan-approved", "Tenant still matches the approved change list", OK if same else WARN,
                            f"approved by {a['by']} on {a['at'][:10]}",
                            "" if same else "Something the plan depends on changed (a group, a category, an engine). "
                            "Open Setup > Change list to see it, and get it approved again."))
    else:
        checks.append(check("plan-approved", "Change list approved", WARN, "not yet", "Setup > Change list, then Approval: "
                            "record the customer's approval."))
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
                            "; ".join(i["name"] for i in open_actions), "Setup > Get ready to test (all of them: Steps for "
                            "people): check or mark each one."))
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


RUNNER_OWNS = "aiguard"   # the AI Guard test runner's results are those criteria's proof


def api_proofs(pov, tenant_for, ids=None, auto=False, log=lambda *a: None):
    """Run each product's automated API proofs with the read-only discovery client; save them for the report.
    auto: the kit's own runs (after Apply, with Status, when Success criteria opens), which leave the AI Guard
    criteria to the test runner."""
    from . import evidence
    t = ReadOnlyTenant(tenant_for(pov, "discovery"))
    led = ledger(pov)
    saved = pov.read_json("api_proofs.json", {}) or {}
    ran = {}
    for c in evidence.selected_criteria(pov, ids):
        if "api" not in c["proofs"]:
            continue
        p = products.get("aiguard" if c.get("aiguard") else c["product"])   # use cases' AI Guard test prompts
        if not hasattr(p, "api_proof") or (auto and p.name == RUNNER_OWNS):
            continue
        try:
            res = p.api_proof(t, pov, led, c)
        except KitError as e:
            res = {"status": "incomplete", "detail": f"couldn't run: {str(e)[:160]}"}
        if res:
            res["at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            res["tests"] = tests_hash(c)
            saved[c["id"]] = ran[c["id"]] = res
    pov.write_json("api_proofs.json", saved)
    pov.write_json("api_proofs_meta.json", {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "auto": auto})
    bad = [k for k, v in ran.items() if v["status"] != "pass"]
    pov.log("test", f"API proofs{' (automatic)' if auto else ''}: {len(ran)} run" + (f"; not passing: {', '.join(bad)}" if bad else ""))
    if ran:
        log("ok" if not bad else "warn", f"Success criteria checked: {len(ran) - len(bad)} of {len(ran)} pass"
            + (f" (not yet: {', '.join(bad[:8])})" if bad else ""))
    return ran


def tests_hash(c):
    """What an API proof checked: the criterion's test sites. A changed test makes the old proof stale."""
    import hashlib
    import json as _j
    return hashlib.sha256(_j.dumps(c.get("probe") or [], sort_keys=True).encode()).hexdigest()[:12]


def stale_proofs(pov):
    """Criteria whose saved API proof checked different tests than the criterion has now."""
    from . import evidence
    saved = pov.read_json("api_proofs.json", {}) or {}
    return [c["id"] for c in evidence.selected_criteria(pov)
            if c["id"] in saved and saved[c["id"]].get("tests") and saved[c["id"]]["tests"] != tests_hash(c)
            or c["id"] in saved and not saved[c["id"]].get("tests") and c.get("probe")]


def proofs_due(pov, hours=3):
    """Whether the kit's automatic proofs are due: never run, or older than `hours`, for a POV with applied objects
    and criteria the runner doesn't cover."""
    import datetime as dt
    from . import evidence
    if not ledger(pov).active():
        return False
    if not any("api" in c["proofs"] and c["product"] != RUNNER_OWNS and not c.get("aiguard")
               for c in evidence.selected_criteria(pov)):
        return False
    at = (pov.read_json("api_proofs_meta.json", {}) or {}).get("at")
    if not at or stale_proofs(pov):
        return True
    then = dt.datetime.strptime(at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    return (dt.datetime.now(dt.timezone.utc) - then).total_seconds() > hours * 3600
