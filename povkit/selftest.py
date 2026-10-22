"""`pov-kit selftest`: before taking the kit to a customer, prove it works in your own lab tenant.

For each product of the POV it reads (the same reads discovery makes), then creates one harmless object, reads it
back, and deletes it, through the same guarded client and ledger rules as apply and teardown:

  ZIA        a rule label (no policy uses it); ZIA is activated afterwards only if nothing else was pending
  ZPA        a disabled segment group with no apps
  AI Guard   an app with no key and no rule
  Client Connector, ZDX, CASB   reads only: their writes reach devices, devices' sessions, or SaaS data

It refuses unless the SE says the tenant is a lab tenant (`--lab`, and the console asks too), and it keeps its own
ledger (selftest-ledger.json) so the POV's ledger is untouched. Results go to selftest.json and the activity log.
"""
from __future__ import annotations

import time
import uuid

from .core import GuardError, KitError, naming
from .core.changelist import item
from .core.guard import LedgerTenant, ReadOnlyTenant
from .core.ledger import Ledger
from .tenant import g

WRITES = {   # product: (kind, resource, add, get, delete, body, id type)
    "zia": ("label", "rule_labels", "add_label", "get_label", "delete_label", {}, int),
    "zpa": ("segment_group", "zpa.segment_groups", "add_group", "get_group", "delete_group", {"enabled": False}, str),
    "aiguard": ("app", "aiguard.llm_applications", "add_application", "get_application", "delete_application",
                {"applicationSettings": {"includeEventContents": False, "encryptEventContents": False}}, int),
}


def run(pov, tenant_for, log, lab=False):
    if not lab:
        raise KitError("selftest writes to the tenant. Run it only in your own lab tenant, with --lab.")
    from . import lifecycle, products
    from .products.zia import activation_state
    out, t0 = [], time.time()
    log("info", "Reads: discovery, read-only")
    try:
        _, checks = lifecycle.discover(pov, tenant_for)
    except KitError as e:
        raise KitError(f"Discovery didn't run: {e}") from e
    for p in products.selected(pov.products):
        mine = [c for c in checks if c["label"].startswith(lifecycle.SHORT.get(p.name, p.title) + ":")]
        unread = [c for c in mine if c["status"] == "fail" and "read" in c["id"]]
        out.append({"product": p.name, "step": "read", "ok": not unread,
                    "detail": unread[0]["detail"] if unread else f"{len(mine)} checks"})
    run_id = uuid.uuid4().hex[:6]
    led = Ledger(pov.path("selftest-ledger.json"), pov.id, pov.prefix)
    raw = tenant_for(pov, "apply")
    ro = ReadOnlyTenant(tenant_for(pov, "discovery"))
    zia_before = None
    if "zia" in pov.products:
        try:
            zia_before = activation_state(ro)
        except KitError:
            zia_before = None
    for prod in [x for x in pov.products if x in WRITES]:
        kind, res, add, get, dele, extra, idt = WRITES[prod]
        if prod == "zia" and zia_before not in ("", "ACTIVE"):
            out.append({"product": prod, "step": "write", "ok": False,
                        "detail": f"skipped: ZIA has changes waiting to be activated ({zia_before})"})
            continue
        name = naming.name(pov.prefix, f"selftest {run_id}", 60 if prod != "zia" else 31)
        if prod == "zia":   # rule labels refuse ':' (a demo-kit lesson)
            name = naming.safe_name(name, pov.prefix)
        body = dict(extra, name=name, description=naming.describe(pov.id, "selftest, deleted right away"))
        key = f"selftest.{prod}.{run_id}"
        t = LedgerTenant(raw, led, [item(prod, kind, key, name, body=body)])
        step = {"product": prod, "step": "write", "ok": False}
        try:
            s = time.time()
            oid = t.create(key, res, add, stamped=prod != "aiguard", **body)
            step["create_ms"] = int((time.time() - s) * 1000)
            live = t.call(res, get, idt(oid))
            back = isinstance(live, dict) and str(g(live, "id")) == str(oid) and g(live, "name") == name
            e = led.find(key)
            t.delete(e, dict(live or {}, id=str(oid), name=g(live, "name") or name,
                             description=g(live, "description") or body["description"]), res, dele, idt(oid))
            step.update(ok=back, detail=f"created, read back{' ' if back else ' (NOT as written) '}and deleted {name}")
        except (KitError, GuardError) as err:
            step["detail"] = str(err)[:240]
            left = led.find(key)
            if left:
                step["detail"] += f". Left in place: {name} (id {left['id']}); delete it by hand."
        out.append(step)
        log("ok" if step["ok"] else "fail", f"{prod}: {step['detail']}")
    if "zia" in pov.products and zia_before == "ACTIVE":
        try:
            LedgerTenant(raw, led, []).activate()
            log("ok", "ZIA activated (only the selftest's own label was pending)")
        except KitError as e:
            out.append({"product": "zia", "step": "activate", "ok": False, "detail": str(e)[:200]})
    res = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seconds": round(time.time() - t0, 1),
           "ok": all(x["ok"] for x in out), "steps": out}
    pov.write_json("selftest.json", res)
    pov.log("selftest", f"selftest {'passed' if res['ok'] else 'FAILED'}: {sum(x['ok'] for x in out)} of {len(out)} steps")
    return res
