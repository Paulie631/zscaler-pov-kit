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
    # before the change list exists, the steps Review & apply waits on (they come back as customer actions in the plan)
    keys += [("customer", k) for k, need in (("zia.ca.malware", "zia"), ("casb.ca.tenant", "casb")) if need in pov.products]
    for i in plan:
        if i["action"] == "customer_action":
            keys.append(("customer", i["key"]))
    applied = bool(led.active() or pov.cfg.get("state") in ("applied", "partly_applied"))
    zcc_by_hand = [i for i in plan if i["product"] == "zcc" and i["action"] == "create_or_adopt"
                   and not led.find(i["key"])] if applied else []
    if zcc_by_hand:
        keys.append(("customer", "zcc.by_hand"))
    if {"aispm", "dspm"} & set(pov.products):
        keys.append(("end", "cloud.end.seed"))
    keys.append(("end", "end.api_clients"))

    done = pov.read_json(DONE_FILE, {}) or {}
    crit = {i["key"]: i.get("criteria") or [] for i in plan}
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
        e["status"] = "done" if d.get("done") else "skipped" if d.get("skipped") else "open"
        e["stage"] = e.get("stage") or STAGE_OF_PHASE.get(phase, "finish")
        e["skipped_by"], e["skip_why"] = d.get("skipped_by"), d.get("skip_why")
        e.update({x: d.get(x) for x in ("by", "at", "how", "detail", "checked_at", "result")})
        e["url"] = GUIDE.get("console")
        e["check"] = check_name(k)
        e["values"] = values(pov, k, plan)
        e["criteria"] = [i for i in (crit.get(k) or [])]
        out.append(e)
    blocks_by_rule(pov, out)
    out.sort(key=lambda e: (STAGES.index(e["stage"]), FINISH_ORDER.index(e["key"]) if e["key"] in FINISH_ORDER else 50))
    return out


# where the setup flow stops for each step, and the order the Get ready to test step walks them in
STAGES = ("connect", "preflight", "finish", "end")
STAGE_H = {"connect": "To connect the POV kit", "preflight": "Before the change list",
           "finish": "After the POV's objects are created", "end": "When the POV ends"}
STAGE_OF_PHASE = {"setup": "preflight", "customer": "finish", "end": "end"}
FINISH_ORDER = ["zid.ca.entitlement", "zid.ca.passwords", "zcc.by_hand", "zpa.ca.connectors", "zpa.ca.users",
                "zcc.ca.devices"]


def stage(pov, name, steps=None):
    """-> {steps, open, passed}: one stage's steps; passed when each is done, or skipped on purpose."""
    st = [s for s in (steps if steps is not None else guide(pov)) if s["stage"] == name]
    left = [s for s in st if s["status"] == "open"]
    return {"steps": st, "open": len(left), "skipped": sum(s["status"] == "skipped" for s in st), "passed": not left}


def skip(pov, keys, by, why=""):
    """'Continue anyway' at a gate: records who let the setup go on with these steps still open. They stay on the
    list (and keep holding up their criteria) until they're done."""
    by = (by or "").strip()
    if not by:
        raise KitError("Say who decided to continue (name), so the record shows it.")
    known = {s["key"] for s in guide(pov)}
    done = pov.read_json(DONE_FILE, {}) or {}
    for k in keys:
        if k not in known:
            raise KitError(f"No step called {k}.")
        cur = done.get(k) or {}
        if not cur.get("done"):
            cur.update(skipped=True, skipped_by=by, skipped_at=_now(), skip_why=(why or "")[:200])
        done[k] = cur
    pov.write_json(DONE_FILE, done)
    pov.log("manual", f"continued with {len(keys)} step(s) open, decided by {by}: {', '.join(keys)}")
    return len(keys)


HELP = json.loads((Path(__file__).with_name("check_help.json")).read_text(encoding="utf-8"))


def check_help(check_id):
    """The 'How to verify' panel for a preflight check, if there is one."""
    h = HELP.get(check_id)
    if h is None:
        h = next((v for k, v in HELP.items() if (k.endswith("-*") and check_id.startswith(k[:-1]))
                  or (k.startswith("*-") and check_id.endswith(k[1:]))), None)
    if h and h.get("same"):
        h = HELP.get(h["same"])
    return h


def with_help(checks):
    """Adds each check's 'How to verify' panel, for the console."""
    for c in checks or []:
        if isinstance(c, dict) and c.get("id") and not c.get("help"):
            h = check_help(c["id"])
            if h:
                c["help"] = h
    return checks


# ---------------------------------------------------------------- what each step holds up, and the values to paste
# Steps whose plan item doesn't name criteria hold up these: a product's criteria, or every criterion a pilot device
# proves ("probe"). The API client itself holds up everything, which needs no saying.
RULES = {"setup.zdx_role": ("product", ["zdx"]), "setup.zpa_customer_id": ("product", ["zpa"]),
         "zid.ca.entitlement": ("probe", ["zia", "zcc"]), "zia.ca.entitlement": ("probe", ["zia", "zcc"]),
         "zid.ca.passwords": ("probe", None), "zcc.ca.devices": ("probe", None), "zcc.by_hand": ("product", ["zcc"]),
         "casb.ca.tenant": ("product", ["casb"]), "zpa.ca.connectors": ("product", ["zpa"]),
         "zpa.ca.users": ("product", ["zpa"])}


def blocks_by_rule(pov, steps):
    from . import evidence
    # a product rule fills in only when the plan item names no criteria; a device rule always adds (no pilot device
    # signed in as an entitled pilot user means no device test can pass)
    rules = {k: v for k, v in RULES.items()
             if any(s["key"] == k and (v[0] == "probe" or not s["criteria"]) for s in steps)}
    if not rules:
        return
    crit = evidence.selected_criteria(pov)
    for s in steps:
        how, prods = rules.get(s["key"], (None, None))
        if how == "product":
            s["criteria"] = [c["id"] for c in crit if c.get("product") in prods]
        elif how == "probe":
            s["criteria"] = list(dict.fromkeys(s["criteria"] + [
                c["id"] for c in crit if "probe" in (c.get("proofs") or [])
                and (prods is None or c.get("product") in prods)]))


def waiting_on(pov, steps=None):
    """-> {criterion id: [open steps holding it up]}, for the Success criteria tab."""
    out = {}
    for s in steps if steps is not None else guide(pov):
        if s["status"] == "done" or s["phase"] == "end":
            continue
        for cid in s.get("criteria") or []:
            out.setdefault(cid, []).append({"key": s["key"], "title": s["title"]})
    return out


def _plan_names(plan, product=None, kinds=()):
    return [i["name"] for i in plan if (product is None or i["product"] == product) and i["kind"] in kinds
            and i["action"] != "customer_action"]


def values(pov, key, plan):
    """The exact values a person types or picks for this step, so they can copy them instead of retyping."""
    client = f"ZPOV {pov.id}"
    group = (_plan_names(plan, "zid", ("group",)) + _plan_names(plan, "zia", ("user_group",))
             or [pov.cfg.get("pilot_group") or ""])[0]
    users = [str((i.get("body") or {}).get("login_name") or (i.get("body") or {}).get("email") or i["name"])
             for i in plan if i["kind"] == "user" and i["product"] in ("zid", "zia")]
    v = []
    if key in ("setup.api_client", "setup.zdx_role"):
        v.append(("API client name", client))
    elif key == "end.api_clients":
        v += [("API client name", client), ("Read-only client (if made)", f"{client} read-only")]
    elif key == "setup.zpa_customer_id" and pov.cfg.get("customer_id"):
        v.append(("Customer ID saved in the kit", str(pov.cfg["customer_id"])))
    elif key in ("zid.ca.entitlement", "zia.ca.entitlement"):
        if group:
            v.append(("Group to entitle", group))
        v.append(("Service", "Internet & SaaS" + (" and Private Access" if "zpa" in pov.products else "")))
    elif key == "zid.ca.passwords":
        v += [("Pilot user", u) for u in users]
    elif key == "zcc.ca.devices":
        cloud = (pov.cfg.get("zcc") or {}).get("cloud")
        if cloud:
            v.append(("Zscaler cloud", cloud))
        emails = list(dict.fromkeys([e for e in pov.cfg.get("pilot_emails") or [] if "@" in e] + users))
        v += [("Pilot user", e) for e in emails[:10]]
    elif key == "zcc.by_hand":
        v += [("Profile name", n) for n in _plan_names(plan, "zcc", ("forwarding_profile", "app_profile",
                                                                     "web_app_profile", "app_profile_windows"))
              or [i["name"] for i in plan if i["product"] == "zcc" and i["action"] == "create_or_adopt"]]
        if group:
            v.append(("For the group", group))
    elif key == "zpa.ca.connectors":
        v += [("Connector group", n) for n in _plan_names(plan, "zpa", ("connector_group",))]
        v += [("Provisioning key name", n) for n in _plan_names(plan, "zpa", ("provisioning_key",))]
    elif key == "zpa.ca.users":
        v += [("Access rule", n) for n in _plan_names(plan, "zpa", ("access_rule", "policy_rule"))]
        if group:
            v.append(("Pilot group", group))
    return [{"label": a, "value": b} for a, b in v if b]


def preview(product_names):
    """Before a POV exists: the steps a person will do for these products (titles, who, when), for kickoff."""
    keys = ["setup.api_client"] + (["setup.zdx_role"] if "zdx" in product_names else []) + \
        (["setup.zpa_customer_id"] if "zpa" in product_names else [])
    if {"zia", "zcc"} & set(product_names):
        keys += ["zid.ca.entitlement", "zid.ca.passwords", "zia.ca.malware", "zcc.ca.devices"]
    keys += [k for k, need in (("casb.ca.tenant", "casb"), ("zpa.ca.connectors", "zpa"), ("zpa.ca.users", "zpa"))
             if need in product_names]
    keys.append("end.api_clients")
    return [{"key": k, "title": GUIDE["steps"][k]["title"], "who": GUIDE["steps"][k].get("who"),
             "when": GUIDE["steps"][k].get("when")} for k in keys if k in GUIDE["steps"]]


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
        cur.update(done=True, by=by, at=_now(), how="marked", skipped=False)
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
    from .gui import PING
    first = next((n for n in products.ORDER if n in pov.products and n in PING), None)
    if not first:
        return None, "no product with an API in this POV"
    t.call(*_ping(first))
    return True, "the POV's API client signs in"


def _check_zdx(t, pov, led):
    t.call(*_ping("zdx"))
    return True, "ZDX readable with the POV's API client"


def _check_zpa(t, pov, led):
    if not pov.cfg.get("customer_id"):
        return False, "no ZPA customer ID set yet (Connect > ZPA customer ID)"
    try:
        t.call(*_ping("zpa"))
    except KitError as e:
        if re.search(r"\b404\b|resource\.not\.found", str(e)):
            return False, f"ZPA doesn't know customer ID {pov.cfg['customer_id']}: check it was copied whole"
        raise
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
        cur.update(done=True, by="the kit's check", at=_now(), how="checked", skipped=False)
    elif ok is False and cur.get("how") == "checked":
        cur.update(done=False)   # a check that passed before and fails now reopens the step
    done[key] = cur
    pov.write_json(DONE_FILE, done)
    pov.log("manual", f"{key}: check {'passed' if ok else 'failed' if ok is False else 'inconclusive'}: {detail}")
    return {"ok": ok, "detail": detail}


def check_all(pov, tenant_for, log=lambda *a: None, only_stage=None):
    out = {}
    for s in guide(pov):
        if not check_name(s["key"]) or s["phase"] == "end" or (only_stage and s["stage"] != only_stage):
            continue
        r = check(pov, s["key"], tenant_for)
        log("ok" if r["ok"] else "warn" if r["ok"] is False else "info", f"{s['title']}: {r['detail']}")
        out[s["key"]] = r
    return out


# ---------------------------------------------------------------- a sheet for the customer's admin
def sheet_md(pov, only_stage=None):
    """The steps as a Markdown sheet the SE sends the customer's admin (no secrets in it): all of them, or one
    stage's (what the setup is waiting on now)."""
    steps = [s for s in guide(pov) if only_stage is None or s["stage"] == only_stage]
    lines = [f"# {pov.cfg.get('customer') or pov.id}: Zscaler POV steps for your admin", "",
             "The POV kit does everything it can through Zscaler's API. These steps need a person in the Zscaler "
             f"console ({GUIDE['console']}). If a menu has moved, use the console's Search menu with the term "
             "given. Never send secrets (API client secrets, passwords, keys) by email or chat.", ""]
    last = None
    n = 0
    for s in steps:
        if s["stage"] != last:
            lines += [f"## {STAGE_H[s['stage']]}", ""]
            last = s["stage"]
        n += 1
        tick = "[x]" if s["status"] == "done" else "[ ]"
        lines.append(f"### {tick} {n}. {s['title']}")
        meta = [f"Who: {s.get('who')}"] + ([f"When: {s['when']}"] if s.get("when") else [])
        if s.get("path"):
            meta.append(f"Where: {s['path']}")
        if s.get("search"):
            meta.append(f"Console search: \"{s['search']}\"")
        lines += ["", " · ".join(meta), ""]
        h = s.get("help") or {}
        if h.get("verify"):
            lines += ["How to check it's done:"] + [f"- {x.replace('<pov-id>', pov.id)}" for x in h["verify"]] + [""]
        if s.get("why"):
            lines += [f"Why: {s['why']}", ""]
        lines += [f"{i}. {x.replace('<pov-id>', pov.id)}" for i, x in enumerate(s.get("steps") or [], 1)]
        if s.get("values"):
            lines += ["", "Values to use:"] + [f"- {x['label']}: `{x['value']}`" for x in s["values"]]
        elif s.get("names"):
            lines += ["", "Exact names: " + "; ".join(f"`{x}`" for x in s["names"])]
        if s.get("criteria") and s["status"] != "done":
            lines += ["", "Holds up: " + ", ".join(s["criteria"][:12])]
        if s.get("done"):
            lines += ["", f"Done when: {s['done']}"]
        lines.append("")
    return "\n".join(lines)
