"""The steps the kit can't do through the API, with instructions, and a check for each where the API can see the
result.

`guide(pov)` lists the steps this POV needs, in order: setup (API client, ZDX role, ZPA customer ID), the change
list's customer actions, Client Connector profiles to build by hand when the API couldn't, and deleting the API
clients at the end. Each step's text lives in manual.json, so wording and click paths can be fixed in one place.

`check(pov, key, tenant_for)` runs that step's read-only check with the discovery client. `mark(pov, key, by)`
records a step done by hand, for steps the API can't see (or to override a check that can't run).
Nothing here writes to the tenant.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from .core import KitError
from .tenant import g, items

GUIDE = json.loads((Path(__file__).with_name("manual.json")).read_text(encoding="utf-8"))
DONE_FILE = "manual_done.json"


def _entry(key):
    e = GUIDE["steps"].get(key)
    if not e:
        return None
    return dict(e, key=key)


def _plan_items(pov):
    from .core.changelist import ChangeList
    cl = ChangeList(pov.dir)
    return cl.plan()["items"] if cl.plan_file.exists() else []


def guide(pov):
    """-> [step], in the order they're done. Each: key, title, who, when, steps, path, search, done, check,
    phase, status ('done' | 'open'), done_by/at, last check."""
    from . import lifecycle
    plan = _plan_items(pov)
    led = lifecycle.ledger(pov)
    keys = [("setup", "setup.api_client")]
    if "zdx" in pov.products:
        keys.append(("setup", "setup.zdx_role"))
    if "zpa" in pov.products:
        keys.append(("setup", "setup.zpa_customer_id"))
    for i in plan:
        if i["action"] == "customer_action":
            keys.append(("customer", i["key"]))
    zcc_by_hand = [i for i in plan if i["product"] == "zcc" and i["action"] == "create_or_adopt"
                   and not led.find(i["key"])]
    if zcc_by_hand:
        keys.append(("customer", "zcc.by_hand"))
    keys.append(("end", "end.api_clients"))

    done = pov.read_json(DONE_FILE, {}) or {}
    names = {i["key"]: i["name"] for i in plan}
    why = {i["key"]: i.get("why") for i in plan}
    out, seen = [], set()
    for phase, k in keys:
        if k in seen:
            continue
        seen.add(k)
        e = _entry(k) or {"key": k, "title": names.get(k, k), "steps": [], "who": "customer admin",
                          "done": "Mark it done once it's done."}
        e = {**e, "phase": phase, "item": names.get(k), "why": why.get(k) or e.get("why")}
        if k == "zcc.by_hand":
            e["names"] = [i["name"] for i in zcc_by_hand]
        d = done.get(k) or {}
        e["status"] = "done" if d.get("done") else "open"
        e.update({x: d.get(x) for x in ("by", "at", "how", "detail", "checked_at", "result")})
        e["url"] = GUIDE.get("console")
        e["check"] = check_name(k)
        out.append(e)
    return out


def mark(pov, key, by, undo=False):
    if not _entry(key) and key not in {i["key"] for i in _plan_items(pov)}:
        raise KitError(f"No step called {key}.")
    by = (by or "").strip()
    if not undo and not by:
        raise KitError("Say who did it (name), so the record shows it.")
    done = pov.read_json(DONE_FILE, {}) or {}
    cur = done.get(key) or {}
    if undo:
        cur.update(done=False, by=None, at=None, how=None)
    else:
        cur.update(done=True, by=by, at=_now(), how="marked")
    done[key] = cur
    pov.write_json(DONE_FILE, done)
    pov.log("manual", f"{key}: {'reopened' if undo else 'marked done by ' + by}")
    return cur


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------- checks (read-only)
def _ping(product):
    from .gui import PING
    return PING[product]


def _check_signin(t, pov, led):
    from . import products
    first = next(n for n in products.ORDER if n in pov.products)
    t.call(*_ping(first))
    return True, "the POV's API client signs in"


def _check_zdx(t, pov, led):
    t.call(*_ping("zdx"))
    return True, "ZDX readable with the POV's API client"


def _check_zpa(t, pov, led):
    t.call(*_ping("zpa"))
    return True, "ZPA readable with the customer ID"


def _check_entitled(t, pov, led):
    from .identity import ZIA_SERVICE, zid_services
    if any(e["key"] == "zid.zia_group" for e in led.entries if e["state"] == "linked"):
        return True, "ZIA has the POV's pilot group, so ZIdentity sends it (entitled)"
    emails = [e.strip().lower() for e in pov.cfg.get("pilot_emails") or [] if e.strip()]
    emails += [str(i["body"].get("login_name") or "").lower() for i in _plan_items(pov)
               if i["product"] == "zid" and i["kind"] == "user" and led.find(i["key"])]
    emails = [e for e in dict.fromkeys(emails) if e]
    if not emails:
        return None, "no pilot users to check yet (name them, or Apply first)"
    have, without = 0, []
    for em in emails[:10]:
        rows = items(t.call("zid.users", "list_users", query_params={"login_name": em}))
        zu = next((r for r in rows if str(g(r, "login_name") or "").lower() == em), None)
        if not zu:
            without.append(f"{em} (not in ZIdentity)")
            continue
        names = zid_services(t, g(zu, "id"))
        if names is None:
            return None, "ZIdentity's entitlements aren't readable with this API client"
        if any(ZIA_SERVICE.search(n) for n in names):
            have += 1
        else:
            without.append(em)
    if without:
        return False, f"not entitled to Internet & SaaS: {', '.join(without)}"
    return True, f"all {have} pilot users entitled to Internet & SaaS"


MALWARE_FIELDS = {"virus_blocked": "viruses", "unwanted_applications_blocked": "unwanted apps",
                  "trojan_blocked": "trojans", "worm_blocked": "worms"}


def _check_malware(t, pov, led):
    s = t.call("malware_protection_policy", "get_malware_settings")
    if not isinstance(s, dict):
        return None, "Malware Protection settings unreadable"
    known = {k: g(s, k) for k in MALWARE_FIELDS if g(s, k) is not None}
    if not known:
        return None, "Malware Protection settings didn't say what's blocked"
    off = [MALWARE_FIELDS[k] for k, v in known.items() if not v]
    if off:
        return False, f"not blocked: {', '.join(off)}"
    return True, "viruses, unwanted apps, trojans and worms blocked"


def _proof(product, cid):
    def run(t, pov, led):
        from . import products
        r = products.get(product).api_proof(t, pov, led, {"id": cid})
        if not r:
            return None, "no automatic check"
        return {"pass": True, "fail": False}.get(r["status"]), r["detail"]
    return run


def _check_adopted(t, pov, led):
    plan = [i for i in _plan_items(pov) if i["product"] == "zcc" and i["action"] == "create_or_adopt"]
    left = [i["name"] for i in plan if not led.find(i["key"])]
    if left:
        return False, f"not adopted yet: {', '.join(left)} (build them, then Status > Fix drift)"
    return True, "both profiles adopted into the ledger"


CHECKS = {"signin": _check_signin, "zdx_readable": _check_zdx, "zpa_readable": _check_zpa,
          "zid_entitled": _check_entitled, "malware_blocks": _check_malware,
          "zcc_devices": _proof("zcc", "IS-ZCC-01"), "casb_tenant": _proof("casb", "CS-SAS-01"),
          "zpa_connectors": _proof("zpa", "PA-CON-01"), "zpa_access": _proof("zpa", "PA-APP-01"),
          "zcc_adopted": _check_adopted}
# setup steps prove themselves by signing in
SETUP_CHECK = {"setup.api_client": "signin", "setup.zdx_role": "zdx_readable", "setup.zpa_customer_id": "zpa_readable"}


def check_name(key):
    return SETUP_CHECK.get(key) or (GUIDE["steps"].get(key) or {}).get("check")


def check(pov, key, tenant_for):
    """Run one step's read-only check. -> {ok: True|False|None, detail}. A pass records the step done."""
    from . import lifecycle
    from .core.guard import ReadOnlyTenant
    name = check_name(key)
    if not name:
        raise KitError("This step has no automatic check: mark it done once it's done.")
    led = lifecycle.ledger(pov)
    try:
        t = ReadOnlyTenant(tenant_for(pov, "discovery"))
        ok, detail = CHECKS[name](t, pov, led)
    except KitError as e:
        msg = str(e)
        if key == "setup.zdx_role" and re.search(r"\b403\b|forbidden", msg, re.I):
            ok, detail = False, "ZDX refused the API client (403): it has no ZDX role yet"
        else:
            ok, detail = None, f"couldn't check: {msg[:180]}"
    done = pov.read_json(DONE_FILE, {}) or {}
    cur = done.get(key) or {}
    cur.update(checked_at=_now(), result=ok, detail=detail)
    if ok:
        cur.update(done=True, by="the kit's check", at=_now(), how="checked")
    elif ok is False and cur.get("how") == "checked":
        cur.update(done=False)   # a check that passed before and fails now reopens the step
    done[key] = cur
    pov.write_json(DONE_FILE, done)
    pov.log("manual", f"{key}: check {'passed' if ok else 'failed' if ok is False else 'inconclusive'}: {detail}")
    return {"ok": ok, "detail": detail}


def check_all(pov, tenant_for, log=lambda *a: None):
    out = {}
    for s in guide(pov):
        if not check_name(s["key"]) or s["phase"] == "end":
            continue
        r = check(pov, s["key"], tenant_for)
        log("ok" if r["ok"] else "warn" if r["ok"] is False else "info", f"{s['title']}: {r['detail']}")
        out[s["key"]] = r
    return out


# ---------------------------------------------------------------- a sheet for the customer's admin
def sheet_md(pov):
    """The open steps as a Markdown sheet the SE sends the customer's admin (no secrets in it)."""
    steps = [s for s in guide(pov)]
    lines = [f"# {pov.cfg.get('customer') or pov.id}: Zscaler POV steps for your admin", "",
             "The POV kit does everything it can through Zscaler's API. These steps need a person in the Zscaler "
             f"console ({GUIDE['console']}). If a menu has moved, use the console's Search menu with the term "
             "given. Never send secrets (API client secrets, passwords, keys) by email or chat.", ""]
    phase_h = {"setup": "Before we start", "customer": "During the POV", "end": "When the POV ends"}
    last = None
    n = 0
    for s in steps:
        if s["phase"] != last:
            lines += [f"## {phase_h[s['phase']]}", ""]
            last = s["phase"]
        n += 1
        tick = "[x]" if s["status"] == "done" else "[ ]"
        lines.append(f"### {tick} {n}. {s['title']}")
        meta = [f"Who: {s.get('who')}"] + ([f"When: {s['when']}"] if s.get("when") else [])
        if s.get("path"):
            meta.append(f"Where: {s['path']}")
        if s.get("search"):
            meta.append(f"Console search: \"{s['search']}\"")
        lines += ["", " · ".join(meta), ""]
        if s.get("why"):
            lines += [f"Why: {s['why']}", ""]
        lines += [f"{i}. {x.replace('<pov-id>', pov.id)}" for i, x in enumerate(s.get("steps") or [], 1)]
        if s.get("names"):
            lines += ["", "Exact names: " + "; ".join(f"`{x}`" for x in s["names"])]
        if s.get("done"):
            lines += ["", f"Done when: {s['done']}"]
        lines.append("")
    return "\n".join(lines)
