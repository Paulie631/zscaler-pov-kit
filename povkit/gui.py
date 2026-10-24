"""The POV console: a local web page with the setup wizard and tabs for status, criteria, handover and logs.

Built on the demo kit's console pattern: the server listens on 127.0.0.1 only, refuses any other Host header (so a
web page can't reach it through DNS rebinding), and every /api call must carry a token minted for this run and
written into the page. Long operations (apply, status, proofs, handover) run as jobs the page polls. Secrets go
straight to the keychain and never come back to the page, except a test user's password or the ZPA provisioning key
when the SE asks for it by name.
"""
from __future__ import annotations

import json
import os
import secrets as _rand
import threading
import time
import uuid
from pathlib import Path

from . import VERSION, evidence, handover, installer, lifecycle, mcp, products, remind, rolespec, settings, updater
from .core import KitError, pov as povs, secrets
from .core.changelist import ChangeList
from .core.checks import exit_code

HERE = Path(__file__).resolve().parent
JOBS: dict[str, dict] = {}


def real_tenant_for(pov, which):
    from .tenant import Tenant
    return Tenant(pov, which)


TENANT_FOR = real_tenant_for   # tests swap in a fake


def tf(pov, which):
    return TENANT_FOR(pov, which)


# ---------------------------------------------------------------- state for the page
def _manual_open(p):
    from . import manual
    try:
        every = manual.guide(p)
    except Exception:   # noqa: BLE001 - never let the badge break the page
        return None
    steps = [s for s in every if s["status"] != "done" and s["phase"] != "end"]
    return {"open": len(steps), "next": steps[0]["title"] if steps else None,
            "stages": {n: {k: v for k, v in manual.stage(p, n, every).items() if k != "steps"} for n in manual.STAGES}}


def pov_state(p):
    led = lifecycle.ledger(p)
    cl = ChangeList(p.dir)
    plan = cl.plan() if cl.plan_file.exists() else None
    appr = cl.approval()
    slots = ["main"] if p.cfg.get("client_mode", "single") == "single" else ["discovery", "apply"]
    states = {}
    for e in led.entries:
        states[e["state"]] = states.get(e["state"], 0) + 1
    return {"id": p.id, "customer": p.cfg["customer"], "prefix": p.prefix, "products": p.products,
            "state": p.cfg.get("state"), "settings": settings.snapshot(p),
            "clients": {s: {"client_id": ((p.cfg.get("clients") or {}).get(s) or {}).get("client_id"),
                            "saved": bool(secrets.get(p.id, f"{s}-client-secret"))} for s in slots},
            "plan": {"hash": plan["hash"], "items": len(plan["items"]),
                     "creates": sum(1 for i in plan["items"] if i["action"] != "customer_action")} if plan else None,
            "approval": appr, "ledger": states,
            "test_users": sum(1 for e in led.active("zia") if e["kind"] == "user"),
            "zpa_key": bool(secrets.get(p.id, "zpa-provisioning-key")),
            "end": remind.end_check(p), "backup_at": (p.cfg.get("backup") or {}).get("at"),
            "record": bool(p.cfg.get("record")), "selftest": p.read_json("selftest.json"),
            "manual_open": _manual_open(p),
            "claude_desktop": (lambda c: {"server": c["server"], "vanity_domain": c["vanity_domain"]} if c else None)(
                mcp.desktop_client()),
            "aiguard": {"live": bool(led.find("aiguard.policy")),
                        "profile": (p.cfg.get("aiguard") or {}).get("profile") or "monitor"},
            "mcp": {"consent": mcp.consent(p), "installed": (p.cfg.get("mcp") or {}).get("installed"),
                    "uses": mcp.slot(p)[1], "entry": mcp.entry_name(p)}}


def state():
    cur = povs.CURRENT.read_text().strip() if povs.CURRENT.exists() else ""
    from . import backup
    out = {"version": VERSION, "povs": [], "current": None, "backup_folder": str(backup.folder() or "") or None,
           "products": [{"name": n, "title": products.get(n).title, "phase": products.get(n).phase}
                        for n in products.CHOOSABLE],
           "claude_desktop": (lambda c: {"server": c["server"], "vanity_domain": c["vanity_domain"]} if c else None)(
               mcp.desktop_client())}
    for pid in povs.all_povs():
        p = povs.Pov(pid)
        out["povs"].append({"id": pid, "customer": p.cfg["customer"], "state": p.cfg.get("state")})
        if pid == cur:
            out["current"] = pov_state(p)
    return out


def current():
    return povs.current()


# one cheap read per product, to prove the client signs in and can see that product
PING = {"zia": ("activate", "status"), "zcc": ("zcc.forwarding_profile", "list_by_company"),
        "zpa": ("zpa.idp", "list_idps"), "aiguard": ("aiguard.policies", "list_policies"),
        "zdx": ("zdx.apps", "list_apps"), "casb": ("saas_security_api", "list_casb_tenant_lite"),
        "zid": ("zid.users", "list_users")}


def sign_in_check(p, which):
    from .core.guard import ReadOnlyTenant
    t = ReadOnlyTenant(tf(p, which))
    first = next((n for n in products.ORDER if n in p.products and n in PING), None)
    if first:   # a POV of draft products only (Endpoint AI) has nothing to sign in to
        t.call(*PING[first])


def pilot_options(p):
    """What the Pilot users step offers to pick from: ZIA's groups and ZIdentity's users (read-only, discovery
    client). Shown on this laptop only; nothing is saved."""
    from .core.guard import ReadOnlyTenant
    from .tenant import g, items
    t = ReadOnlyTenant(tf(p, "discovery"))
    out = {"zia_groups": [], "zid_users": [], "zidentity": False, "errors": []}
    try:
        out["zia_groups"] = sorted({str(g(x, "name")) for x in items(t.call("user_management", "list_groups",
                                                                               query_params={"page_size": 1000}))
                                    if g(x, "name") and not str(g(x, "name")).startswith(p.prefix)})
    except KitError as e:
        out["errors"].append(f"ZIA groups: {str(e)[:120]}")
    try:
        rows = items(t.call("zid.users", "list_users", query_params={"limit": 1000}))
        out["zidentity"] = True
        out["zid_users"] = sorted(({"login": str(g(u, "login_name") or ""), "name": str(g(u, "display_name") or "")}
                                   for u in rows if g(u, "login_name")), key=lambda u: u["login"])
    except KitError:
        pass   # no ZIdentity (or no access): the step falls back to typing emails
    return out


def diagnostics_zip(q, token):
    if q.get("t") != token:
        return None
    from . import diagnostics
    return diagnostics.build(current())


# ---------------------------------------------------------------- jobs
def running(pov_id):
    """A job (apply, teardown, status fix...) still running for this POV."""
    return next((j["kind"] for j in JOBS.values() if j.get("pov") == pov_id and not j["done"]), None)


def start_job(kind, work):
    pid = povs.CURRENT.read_text(encoding="utf-8").strip() if povs.CURRENT.exists() else None
    busy = running(pid) if pid else None
    if busy:
        raise KitError(f"This POV's {busy} is still running. Wait for it to finish (the Logs tab shows it).")
    jid = uuid.uuid4().hex[:8]
    job = JOBS[jid] = {"kind": kind, "pov": pid, "done": False, "lines": [], "result": None, "error": None}

    def log(level, msg):
        job["lines"].append({"level": level, "msg": str(msg), "t": time.strftime("%H:%M:%S")})

    def run():
        try:
            job["result"] = work(log)
        except KitError as e:
            job["error"] = str(e)
            log("fail", str(e))
        except Exception as e:   # never let a job thread die silently
            job["error"] = f"{type(e).__name__}: {e}"
            log("fail", job["error"])
        job["done"] = True
    threading.Thread(target=run, daemon=True).start()
    return jid


# ---------------------------------------------------------------- quick start
def quickstart(body):
    """Start a POV from three answers (customer, products, API client): the kit fills in the rest from the tenant,
    runs preflight and makes the change list, all read-only. -> {id, job}. The wizard stays for changing anything."""
    if body.get("existing"):   # a POV started earlier (to send the role spec before the kickoff): carry on from Connect
        p = current()
    else:
        _, r = api("POST", "/api/pov/new", {"customer": body.get("customer"), "products": body.get("products"),
                                            "ends": body.get("ends"), "lab": body.get("lab") is True}, {})
        p = povs.Pov(r["id"])
        povs.use(p.id)
    try:   # the API client first: a bad secret should show at once, not in a job
        if body.get("from_claude_desktop"):
            api("POST", "/api/connect/claude-desktop", {}, {})
        else:
            api("POST", "/api/connect", {k: body.get(k) for k in ("vanity_domain", "customer_id", "client_id",
                                                                   "secret", "cloud")}, {})
    except KitError as e:
        raise KitError(("" if body.get("existing") else "The POV was created, but ") +
                       f"the API client didn't sign in: {e} Fix it in Connect.") from e

    def work(log):
        p = current()
        ic = p.cfg.get("identity") or {}
        if not (p.cfg.get("pilot_group") or p.cfg.get("pilot_emails") or ic.get("pilot")):
            settings.set_value(p, "identity.pilot", "test")
            settings.set_value(p, "identity.test_users", 1)
            log("ok", "Pilot users: one test user made by the kit (name the customer's group or users any time)")
        if {"zcc", "zia"} & set(p.products) and not (p.cfg.get("zcc") or {}).get("cloud"):
            from . import device_setup
            from .core.guard import ReadOnlyTenant
            try:
                c = device_setup.detect_cloud(ReadOnlyTenant(tf(p, "discovery")))
            except Exception:   # noqa: BLE001 - the cloud is a convenience; Set up a pilot device asks for it if unknown
                c = None
            if c:
                settings.set_value(p, "zcc.cloud", c)
                log("ok", f"Zscaler cloud: {c}")
        log("info", "Reading the tenant (read-only) and making the change list…")
        before = (p.cfg.get("identity") or {}).get("users_in")
        items, notes, h, checks = lifecycle.plan(p, tf)
        p = current()
        if (p.cfg.get("identity") or {}).get("users_in") != before:   # discovery learned where users live: again
            log("info", "This tenant keeps its users in ZIdentity, so the test user goes there. Making the change "
                        "list again…")
            items, notes, h, checks = lifecycle.plan(p, tf)
        fails = [c for c in checks if c["status"] == "fail"]
        waiting = [c for c in checks if c.get("waiting") and c["id"].endswith("-waiting")]
        for c in waiting:
            log("warn", f"{c['label']}: {c['detail']}")
        for c in fails:
            log("fail", f"{c['label']}: {c['detail']}" + (f" Fix: {c['fix']}" if c.get("fix") else ""))
        creates = sum(1 for i in items if i["action"] != "customer_action")
        log("ok" if not fails else "warn", f"Change list: {creates} objects to create, ready for the customer to review")
        return {"id": p.id, "fails": len(fails), "waiting": len(waiting), "creates": creates}
    return {"id": p.id, "job": start_job("quickstart", work)}


# ---------------------------------------------------------------- API
def api(method, path, body, q):
    """-> (status, payload). Pure function of the request, so tests can call it without a server."""
    if method == "GET":
        if path == "/api/state":
            return 200, state()
        if path == "/api/rolespec":
            return 200, {"text": rolespec.render(current())}
        if path == "/api/job":
            j = JOBS.get(q.get("id"))
            if not j:
                return 404, {"error": "no such job"}
            since = int(q.get("since", 0))
            return 200, {"done": j["done"], "lines": j["lines"][since:], "result": j["result"], "error": j["error"]}
        if path == "/api/plan":
            p = current()
            cl = ChangeList(p.dir)
            if not cl.plan_file.exists():
                return 200, {"plan": None}
            return 200, {"plan": cl.plan(), "approval": cl.approval()}
        if path == "/api/update":
            return 200, updater.status(force=q.get("force") == "1")
        if path == "/api/criteria":
            from . import summary
            summ, stale = summary.current(current())
            from . import manual
            rows = evidence.evaluate(current())
            wait = manual.waiting_on(current())
            for r in rows:
                if r["status"] != "pass" and wait.get(r["criterion"]["id"]):
                    r["waiting_on"] = wait[r["criterion"]["id"]]
            return 200, {"rows": rows, "summary": summ, "summary_stale": stale}
        if path == "/api/logs":
            p = current()
            f = p.path("activity.jsonl")
            lines = f.read_text(encoding="utf-8").splitlines()[-500:] if f.exists() else []
            return 200, {"lines": [json.loads(x) for x in lines if x.strip()][::-1]}
        if path == "/api/usecases":
            from . import ai, usecases
            p = current()
            via, key, where = ai.route()
            from . import library
            return 200, {"usecases": [{k: v for k, v in u.items() if k != "raw"} for u in usecases.load(p)][::-1],
                         "consent": ai.consent(p), "key": bool(key), "key_source": where, "share": ai.share(p),
                         "route": via, "proxy": bool(ai.proxy_key()[0]), "direct": bool(ai.direct_key()),
                         "model": (p.cfg.get("ai") or {}).get("model") or ai.DEFAULT_MODEL,
                         "library": [{k: e.get(k) for k in ("id", "title", "summary", "products", "proved", "saved")}
                                     for e in library.entries()], "library_folder": str(library.folder())}
        if path == "/api/usecase/directions":
            from . import usecases
            return 200, {"text": usecases.directions_md(usecases.get(current(), q.get("id")))}
        if path == "/api/manual/preview":
            from . import manual
            return 200, {"steps": manual.preview([x for x in (q.get("products") or "").split(",") if x])}
        if path == "/api/manual":
            from . import manual
            p = current()
            steps = manual.guide(p)
            return 200, {"steps": steps, "console": manual.GUIDE["console"],
                         "mode": (p.cfg.get("manual") or {}).get("mode") or "live",
                         "stages": {n: {k: v for k, v in manual.stage(p, n, steps).items() if k != "steps"}
                                    for n in manual.STAGES}}
        if path == "/api/probe/status":
            return 200, evidence.pack_status(current())
        if path == "/api/device":
            from . import device_setup
            return 200, device_setup.info(current())
        if path == "/api/aiguard":
            from . import aiguard_runner
            from .products import aiguard as agm
            p = current()
            lib = aiguard_runner.library(p)
            slim = lambda t: {k: t.get(k) for k in ("id", "name", "group", "category", "direction", "expect", "text")}  # noqa: E731
            dkey, pkey = aiguard_runner.keys(p)
            mode, ptype, model = agm.proxy_cfg(p)
            disc = ((p.read_json("discovery.json", {}) or {}).get("products") or {}).get("aiguard") or {}
            px = disc.get("proxy") or {}
            rs = aiguard_runner.runs(p, 200)
            return 200, {"groups": lib["groups"], "presets": lib["presets"], "users": lib["users"],
                         "tests": [slim(t) for t in lib["tests"]], "panels": lib["panels"],
                         "packs": {k: {"name": v["name"], "description": v.get("description", ""), "customer": v["customer"],
                                       "criterion": v.get("criterion"), "tests": [slim(t) for t in v["tests"]]}
                                   for k, v in lib["packs"].items()},
                         "stories": lib["stories"],
                         "levels": {"attacks": sorted(set().union(*agm.ATTACKS.values())), "data": ["pii", "secrets"],
                                    "never": sorted(agm.NEVER_BLOCK)},
                         "profile": (p.cfg.get("aiguard") or {}).get("profile") or "monitor",
                         "custom": (p.cfg.get("aiguard") or {}).get("custom") or {},
                         "profiles": agm.PROFILES, "detectors": agm.template_detectors(), "never_block": sorted(agm.NEVER_BLOCK),
                         "proxy": {"mode": mode, "provider": ptype, "model": model, "creds": px.get("creds") or [],
                                   "cred": (p.cfg.get("aiguard") or {}).get("provider_credential"),
                                   "se_key": bool(secrets.get(p.id, agm.PROVIDER_SECRET)), "has_provider": bool(px.get("provider"))},
                         "keys": {"detection": bool(dkey), "proxy": bool(pkey)}, "runs": rs[-100:][::-1],
                         "competitor": (p.cfg.get("aiguard") or {}).get("competitor") or "Competitor Inc"}
        if path == "/api/criteria/import":
            from . import criteria_import
            p = current()
            return 200, dict(criteria_import.load(p), catalog=[{"id": c["id"], "product": c["product"], "title": c["title"]}
                                                                for c in criteria_import.catalog(p)])
        if path == "/api/manual/sheet":
            from . import manual
            return 200, {"text": manual.sheet_md(current(), q.get("stage") or None)}
        if path == "/api/users":
            p = current()
            plan = {i["key"]: i for i in (ChangeList(p.dir).plan()["items"] if ChangeList(p.dir).plan_file.exists() else [])}
            return 200, {"users": [{"n": e["key"].rsplit(".", 1)[-1],
                                    "email": plan.get(e["key"], {}).get("body", {}).get("email", e["name"])}
                                   for e in lifecycle.ledger(p).active("zia") if e["kind"] == "user"]}
        return 404, {"error": "not found"}

    # ---- POST
    if path == "/api/pov/new":
        names = [x for x in body.get("products") or [] if x in products.CHOOSABLE]
        if not (body.get("customer") or "").strip():
            raise KitError("Enter the customer's name.")
        if not names:
            raise KitError("Choose at least one product.")
        p = povs.new(body["customer"].strip(), names, (body.get("prefix") or "").strip() or None,
                     remind.parse_date(body["ends"]) if body.get("ends") else None)
        settings.set_value(p, "client_mode", body.get("client_mode") or "single")
        if body.get("lab") is True:   # your own lab tenant: allows the self-test, which writes
            settings.set_value(p, "lab", "yes")
        return 200, {"id": p.id}
    if path == "/api/quickstart":
        return 200, quickstart(body)
    if path == "/api/pov/use":
        povs.Pov(body["id"])
        povs.use(body["id"])
        return 200, {"ok": True}
    if path == "/api/pov/delete/check":
        from . import delete_pov
        return 200, delete_pov.verify(povs.Pov(body["id"]), tf)
    if path == "/api/pov/delete":
        from . import delete_pov
        busy = running(body.get("id"))
        if busy:
            raise KitError(f"This POV's {busy} is still running, so it can't be deleted now. Nothing was deleted.")
        return 200, delete_pov.delete(povs.Pov(body["id"]), body.get("confirm"), tf)
    if path == "/api/pilot/options":
        return 200, pilot_options(current())
    if path == "/api/settings":
        p = current()
        for k, v in (body.get("values") or {}).items():
            if v in ("", None) and k not in settings.LISTS:
                continue
            settings.set_value(p, k, v, save=False)
        p.save()
        return 200, {"settings": settings.snapshot(p)}
    if path == "/api/connect/claude-desktop":
        p = current()
        slot = "main" if p.cfg.get("client_mode", "single") == "single" else "discovery"
        server = mcp.use_desktop_client(p, slot)
        sign_in_check(p, "discovery")
        return 200, {"server": server}
    if path == "/api/connect":
        p = current()
        for k in ("vanity_domain", "cloud", "customer_id"):
            if body.get(k) is not None and str(body[k]).strip():
                settings.set_value(p, k, body[k], save=False)
        slot = body.get("slot") or ("main" if p.cfg.get("client_mode", "single") == "single" else "discovery")
        cid, secret = (body.get("client_id") or "").strip(), (body.get("secret") or "").strip()
        known = ((p.cfg.get("clients") or {}).get(slot) or {}).get("client_id")
        if secret or not known:
            if not (cid and secret):
                raise KitError("Enter the client ID and the secret.")
            secrets.put(p.id, f"{slot}-client-secret", secret)
            p.cfg.setdefault("clients", {})[slot] = {"client_id": cid}
            p.log("connect", f"{slot} client saved")
        p.save()
        sign_in_check(p, "discovery" if slot in ("main", "discovery") else "apply")   # a bad secret shows here
        return 200, {"ok": True}
    if path == "/api/preflight":
        p = current()
        good, why = secrets.keychain_works()
        from .core.checks import FAIL, OK, check
        checks = [check("keychain", "Keychain works on this computer", OK if good else FAIL, why,
                        "" if good else "Unlock the login keychain (Mac) or install a keyring service (Linux).")]
        _, more = lifecycle.discover(p, tf)
        checks += more
        from . import manual
        for c in checks:
            h = manual.check_help(c["id"])
            if h:
                c["help"] = h
        return 200, {"checks": checks, "exit": exit_code(checks)}
    if path == "/api/plan":
        p = current()
        items, notes, h, checks = lifecycle.plan(p, tf)
        return 200, {"items": items, "notes": notes, "hash": h, "checks": checks}
    if path == "/api/approve":
        p = current()
        if not body.get("reviewed"):
            raise KitError("Tick the box to confirm the customer reviewed the change list.")
        rec = ChangeList(p.dir).approve(body.get("by"), body.get("note") or "")
        p.log("approve", f"change list {rec['hash'][:12]} approved by {rec['by']}")
        return 200, {"approval": rec}
    if path == "/api/approve/file":
        p = current()
        text = body.get("content") or ""
        if len(text) > 20000:
            raise KitError("That file is too large to be an approval file.")
        f = p.path("approval-upload.json")
        f.write_text(text, encoding="utf-8")
        try:
            rec = ChangeList(p.dir).approve_file(f)
        finally:
            f.unlink(missing_ok=True)
        p.log("approve", f"change list {rec['hash'][:12]} approved by {rec['by']} on the change-list page")
        return 200, {"approval": rec}
    if path == "/api/summary":
        from . import summary
        p = current()

        def work(log):
            log("info", f"Asking Claude {ai.ROUTES[ai.route_name()]} for the executive summary (results only, names removed)")
            s = summary.write(p, body.get("note") or "")
            log("ok", s["headline"])
            return s
        return 200, {"job": start_job("summary", work)}
    if path == "/api/apply":
        p = current()
        return 200, {"job": start_job("apply", lambda log: len(lifecycle.apply(p, tf, log).active()))}
    if path == "/api/status":
        p = current()
        from . import manual
        return 200, {"job": start_job("status", lambda log: manual.with_help(
            lifecycle.status(p, tf, fix=bool(body.get("fix")), log=log)))}
    if path == "/api/mcp":
        p, what = current(), body.get("what")
        if what == "consent":
            mcp.record_consent(p, body.get("by"))
        elif what == "install":
            return 200, {"path": str(mcp.install(p))}
        elif what == "remove":
            return 200, {"removed": mcp.remove(p)}
        elif what == "config":
            return 200, {"config": {"mcpServers": mcp.snippet(p)}}
        return 200, {"ok": True}
    if path == "/api/remind/install":
        return 200, {"message": remind.install()}
    if path == "/api/record":
        p = current()
        p.cfg["record"] = bool(body.get("on"))
        p.save()
        return 200, {"record": p.cfg["record"]}
    if path == "/api/selftest":
        from . import selftest
        p = current()
        if body.get("lab") is not True:
            raise KitError("Tick the box to confirm this is your own lab tenant.")
        return 200, {"job": start_job("selftest", lambda log: selftest.run(p, tf, log, lab=True))}
    if path == "/api/aiguard/run":
        from . import aiguard_runner
        p = current()
        if body.get("text"):
            tests = [{"id": "live", "name": "Live prompt", "group": "Live", "category": "Live",
                      "direction": "OUT" if body.get("direction") == "OUT" else "IN", "text": str(body["text"])[:8000],
                      "expect": []}]
        else:
            tests = aiguard_runner.find_tests(p, body.get("ids"), body.get("preset"), body.get("pack"))
        mode = "proxy" if body.get("mode") == "proxy" else "detect"

        def work(log):
            return {"results": aiguard_runner.run(p, tests, mode, bool(body.get("tags")), body.get("users"),
                                                  body.get("rounds") or 1, log)}
        return 200, {"job": start_job("aiguard", work)}
    if path == "/api/aiguard/settings":
        p = current()
        vals = {k: body[k] for k in ("proxy", "provider", "provider_credential", "model", "competitor") if k in body}
        for k, v in vals.items():
            settings.set_value(p, f"aiguard.{k}", v, save=False)
        p.save()
        return 200, {"ok": True, "note": "Run the checks again and approve the new change list to add the proxy key."
                     if "proxy" in vals and vals["proxy"] != "none" else ""}
    if path == "/api/aiguard/provider-key":
        from .products import aiguard as agm
        p = current()
        k = (body.get("key") or "").strip()
        if len(k) < 20:
            raise KitError("Paste the whole provider API key.")
        secrets.put(p.id, agm.PROVIDER_SECRET, k)
        p.log("aiguard", "SE's model key saved to the keychain (proxy mode)")
        return 200, {"ok": True}
    if path == "/api/aiguard/pack":
        from . import aiguard_runner
        p = current()
        rows = aiguard_runner.parse_csv(body.get("csv") or "")
        pid, cid, n = aiguard_runner.import_pack(p, body.get("name"), rows)
        return 200, {"pack": pid, "criterion": cid, "count": n}
    if path == "/api/criteria/read":
        import base64
        from . import criteria_import
        if body.get("b64"):
            raw = base64.b64decode(body["b64"])
            if len(raw) > 15_000_000:
                raise KitError("That file is over 15 MB: paste the criteria instead.")
            text = criteria_import.read(body.get("name") or "", raw)
        else:
            text = body.get("text") or ""
        return 200, {"items": criteria_import.split(text)}
    if path == "/api/criteria/map":
        from . import ai, criteria_import
        p = current()
        items = [str(x).strip()[:600] for x in body.get("items") or [] if str(x).strip()][:criteria_import.MAX_ROWS]

        def work(log):
            claude = ai.available() and bool(ai.consent(p)) and body.get("ai", True)
            log("info", f"Mapping {len(items)} criteria " + (f"with Claude, {ai.ROUTES[ai.route_name()]}" if claude else
                        "by keywords (Claude isn't set up for this POV: record the customer's agreement in Use cases)"))
            rows = criteria_import.map_all(p, items, use_ai=claude)
            criteria_import.save(p, rows, body.get("source") or "pasted text")
            log("ok", f"{sum(1 for r in rows if r['catalog'])} map to the catalog, "
                      f"{sum(1 for r in rows if r['usecase'])} become use cases, "
                      f"{sum(1 for r in rows if r['out_of_scope'])} are out of scope")
            return {"rows": rows}
        return 200, {"job": start_job("criteria", work)}
    if path == "/api/criteria/build":
        from . import criteria_import
        p = current()
        rows = body.get("rows") or criteria_import.load(p).get("rows") or []
        data = criteria_import.load(p)
        data["rows"] = rows
        p.write_json(criteria_import.FILE, data)

        def work(log):
            log("info", "Reading the tenant (read-only) for a fresh snapshot")
            snaps, _ = lifecycle.discover(p, tf)
            res = criteria_import.build(p, snaps, rows, log, by=body.get("by") or "SE")
            log("ok", "Done. Review the change list, then the customer approves it.")
            return res
        return 200, {"job": start_job("criteria", work)}
    if path == "/api/manual/mark":
        from . import manual
        return 200, manual.mark(current(), body.get("key"), body.get("by"), undo=bool(body.get("undo")))
    if path == "/api/manual/check":
        from . import manual
        p = current()
        if body.get("key"):
            return 200, manual.check(p, body["key"], tf)
        return 200, {"job": start_job("manual", lambda log: manual.check_all(p, tf, log, body.get("stage")))}
    if path == "/api/manual/skip":
        from . import manual
        p = current()
        keys = body.get("keys") or [s["key"] for s in manual.stage(p, body.get("stage") or "")["steps"]
                                     if s["status"] == "open"]
        return 200, {"skipped": manual.skip(p, keys, body.get("by"), body.get("why") or "")}
    if path == "/api/test-api":
        p = current()
        return 200, {"job": start_job("proofs", lambda log: lifecycle.api_proofs(p, tf))}
    if path == "/api/import-probe":
        p = current()
        data = body.get("data")
        if not isinstance(data, dict):
            raise KitError("That isn't a probe results file.")
        tmp = p.path("probe-upload.json")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        try:
            d = evidence.import_probe(p, tmp)
        finally:
            tmp.unlink(missing_ok=True)
        return 200, {"run_id": d["run_id"], "results": len(d["results"])}
    if path == "/api/attest":
        p = current()
        rec = evidence.attest(p, body.get("criterion"), body.get("note") or "", body.get("by") or "SE")
        return 200, {"attestation": rec}
    if path == "/api/device/cloud":
        from . import device_setup
        from .core.guard import ReadOnlyTenant
        p = current()
        c = body.get("cloud")
        if body.get("detect"):
            c = device_setup.detect_cloud(ReadOnlyTenant(tf(p, "discovery")))
            if not c:
                raise KitError("ZIdentity didn't say which cloud: type it (the Zscaler console's address or Client "
                               "Connector's About page shows it, such as zscalertwo).")
        return 200, {"cloud": settings.set_value(p, "zcc.cloud", c)}
    if path == "/api/device/setup":
        from . import device_setup
        p = current()
        os_, email = body.get("os"), str(body.get("email") or "").strip().lower()
        if body.get("what") == "script":
            pack = evidence.probe_pack(p) if body.get("pack", True) else None
            name, text = device_setup.script(p, os_, email, pack)
            p.log("device", f"device setup script for {email} ({os_})")
            return 200, {"name": name, "text": text}
        return 200, {"line": device_setup.one_liner(p, os_, email)}
    if path == "/api/traffic/aws":
        from . import traffic_aws
        p = current()
        name, t = traffic_aws.for_pov(p, pilot_user=str(body.get("email") or "").strip() or None,
                                      every=int(body.get("every") or 30), per_type=int(body.get("count") or 4))
        p.log("traffic", f"AWS traffic generator template for {t['Parameters']['PilotUser']['Default']}")
        return 200, {"name": name, "template": t}
    if path == "/api/traffic/cloudshare":
        from . import traffic_aws
        p = current()
        name, text = traffic_aws.cloudshare_script(p, int(body.get("every") or 30))
        p.log("traffic", "CloudShare traffic generator script")
        return 200, {"name": name, "text": text}
    if path == "/api/probe-pack":
        return 200, evidence.probe_pack(current())
    if path == "/api/backup":
        from . import backup
        if body.get("now"):
            out = backup.save(current(), quiet=False)
            if not out:
                raise KitError("Backups aren't set up yet: choose a folder and a passphrase first.")
            return 200, {"file": str(out)}
        d = backup.setup(body.get("folder") or "", body.get("passphrase") or "")
        return 200, {"folder": str(d)}
    if path == "/api/report":
        from .report import render_report
        p = current()
        p.path("report.html").write_text(render_report(p, evidence.evaluate(p), ChangeList(p.dir).approval()),
                                         encoding="utf-8")
        return 200, {"ok": True}
    if path == "/api/aiguard-policy":
        from .core.guard import LedgerTenant
        p = current()
        led = lifecycle.ledger(p)
        out = []
        products.get("aiguard").set_profile(LedgerTenant(tf(p, "apply"), led, []), p, led, body.get("profile"),
                                            lambda lv, m: out.append(m))
        prof = body.get("profile")
        p.cfg.setdefault("aiguard", {})["profile"] = prof if isinstance(prof, str) else "custom"
        if isinstance(prof, dict):
            p.cfg["aiguard"]["custom"] = prof
        p.save()
        return 200, {"message": " ".join(out)}
    if path == "/api/update/apply":
        def work(log):
            v = updater.install(updater.fetch_release(force=True), log=log)
            p0 = None
            try:
                p0 = current()
            except KitError:
                pass
            if p0:
                p0.log("update", f"kit updated to {v}")
            return {"version": v, "restart": True}
        return 200, {"job": start_job("update", work)}
    if path == "/api/update/rollback":
        return 200, {"version": updater.rollback()}
    if path == "/api/update/restart":
        if not (installer.APP / "pov_kit.py").exists():
            raise KitError("The kit isn't installed, so there's nothing to restart into.")
        threading.Timer(0.5, restart_console).start()
        return 200, {"ok": True}
    if path == "/api/zpa-template":
        from . import connector_template
        p = current()
        if not lifecycle.ledger(p).find("zpa.provisioning_key"):
            raise KitError("No POV provisioning key yet: apply the change list with ZPA in scope first.")
        cloud = body.get("cloud") or "aws"
        from .products.zpa import app_of
        ta = app_of(p.cfg)["test_app"]
        return 200, {"template": connector_template.build_azure(p.id, p.prefix, ta) if cloud == "azure"
                     else connector_template.build(p.id, p.prefix, test_app=ta), "cloud": cloud, "test_app": ta}
    if path == "/api/reveal":   # a secret the SE asks for by name, shown once on their own screen
        p = current()
        what = body.get("what")
        if what == "zpa-key":
            return 200, {"value": secrets.get(p.id, "zpa-provisioning-key")}
        if what == "test-user" and str(body.get("n", "")).isdigit():
            return 200, {"value": secrets.get(p.id, f"zia-test-user-{int(body['n'])}")}
        return 400, {"error": "unknown secret"}
    if path == "/api/ai/consent":
        from . import ai
        ai.record_consent(current(), body.get("by"))
        return 200, {"ok": True}
    if path == "/api/ai/key":
        from . import ai
        k = (body.get("key") or "").strip()
        if body.get("direct"):
            if body.get("remove"):
                secrets.delete(*ai.DIRECT_KEY)
                return 200, {"ok": True}
            if not k.startswith("sk-ant-") or len(k) < 30:
                raise KitError("Paste your Anthropic API key (it starts with sk-ant-), from the Anthropic Console.")
            secrets.put(*ai.DIRECT_KEY, k)
            return 200, {"ok": True}
        if len(k) < 16:
            raise KitError("Paste the AI Guard app's proxy key.")
        secrets.put(*ai.OWN_KEY, k)
        return 200, {"ok": True}
    if path == "/api/usecase/propose":
        from . import usecases
        p = current()
        text = (body.get("prompt") or "").strip()
        if not text:
            raise KitError("Describe the use case first.")

        def work(log):
            log("info", "Reading the tenant (read-only) for a fresh snapshot")
            snaps, _ = lifecycle.discover(p, tf)
            log("info", f"Asking Claude {ai.ROUTES[ai.route_name()]}")
            uc = usecases.propose(p, snaps, text, by=body.get("by") or "SE")
            log("ok", f"{uc['id']}: {len(uc['spec']['changes'])} changes the kit can build, "
                      f"{len(uc['spec']['directions'])} directions")
            return {k: v for k, v in uc.items() if k != "raw"}
        return 200, {"job": start_job("usecase", work)}
    if path == "/api/ai/share":
        from . import ai
        settings.set_value(current(), "ai.share", body.get("share"))
        return 200, {"share": ai.share(current()), "consent": ai.consent(current())}
    if path == "/api/usecase/refine":
        from . import usecases
        p, uid, text = current(), body.get("id"), (body.get("feedback") or "").strip()
        if not text:
            raise KitError("Say what to change.")

        def work(log):
            log("info", "Reading the tenant (read-only) for a fresh snapshot")
            snaps, _ = lifecycle.discover(p, tf)
            log("info", f"Asking Claude {ai.ROUTES[ai.route_name()]} to rework {uid}")
            uc = usecases.refine(p, snaps, uid, text, by=body.get("by") or "SE")
            log("ok", f"{uid}: {len(uc['spec']['changes'])} changes the kit can build, "
                      f"{len(uc['spec']['directions'])} directions")
            return {k: v for k, v in uc.items() if k != "raw"}
        return 200, {"job": start_job("usecase", work)}
    if path == "/api/library/save":
        from . import library, usecases
        p = current()
        e = library.save(p, usecases.get(p, body.get("id")), title=body.get("title"))
        return 200, {"entry": e}
    if path == "/api/library/use":
        from . import library
        p, name = current(), body.get("name")

        def work(log):
            log("info", "Reading the tenant (read-only) to check the library entry against it")
            snaps, _ = lifecycle.discover(p, tf)
            uc = library.use(p, snaps, name)
            log("ok", f"{uc['id']} from the library (no AI call): {len(uc['spec']['changes'])} changes the kit can build")
            return {k: v for k, v in uc.items() if k != "raw"}
        return 200, {"job": start_job("usecase", work)}
    if path == "/api/usecase/status":
        from . import usecases
        uc = usecases.set_status(current(), body.get("id"), body.get("status"))
        return 200, {"usecase": {k: v for k, v in uc.items() if k != "raw"}}
    if path == "/api/handover":
        p = current()
        how = body.get("how")
        if how == "teardown":
            if body.get("confirm") != "DELETE":
                raise KitError("Type DELETE to confirm.")

            def work(log):
                checks = lifecycle.teardown(p, tf, log, include_adopted=bool(body.get("include_adopted")))
                if lifecycle.ledger(p).active():
                    log("warn", "Some objects are still in the ledger; secrets and data are kept until they're gone.")
                    return {"checks": checks, "finished": False}
                gone, purged = handover.finish(p)
                log("ok", f"Deleted {len(gone)} secrets and {', '.join(purged) or 'no'} customer data files.")
                return {"checks": checks, "finished": True}
            return 200, {"job": start_job("teardown", work)}
        if how == "terraform":
            def work(log):
                out, exported, skipped = handover.terraform(p, lifecycle.ledger(p))
                log("ok", f"Terraform folder: {out} ({len(exported)} objects; kept in place but not in Terraform: "
                          f"{', '.join(e['name'] for e, _ in skipped) or 'none'})")
                gone, purged = handover.finish(p)
                log("ok", f"Deleted {len(gone)} secrets and {', '.join(purged) or 'no'} customer data files.")
                return {"folder": str(out), "finished": True}
            return 200, {"job": start_job("terraform", work)}
        raise KitError("Choose teardown or terraform.")
    return 404, {"error": "not found"}


def page_file(path, q, token):
    """Pages that carry customer data (change list, report) need the run's token too."""
    if q.get("t") != token:
        return None
    p = current()
    if path == "/aiguard-report":
        from . import aiguard_runner
        return aiguard_runner.report(p, q.get("customer")).encode("utf-8")
    f = {"/plan": p.path("plan.html"), "/report": p.path("report.html")}.get(path)
    return f.read_bytes() if f and f.exists() else None


# ---------------------------------------------------------------- server
SERVER = {}


def restart_console():
    """After an update or rollback: stop serving; serve() then starts the installed kit's console on the same port.
    The page polls until it answers, then reloads (with the new run's token)."""
    SERVER["restart"] = True
    if SERVER.get("srv"):
        SERVER["srv"].shutdown()


def _exec_installed(port):
    """Replace this process with the installed kit's console (on Windows, start it and exit)."""
    import subprocess
    launcher = installer.APP / ("pov-kit.cmd" if installer.windows() else "pov-kit")
    args = [str(launcher), "gui", "--port", str(port), "--no-browser"]
    if installer.windows():
        subprocess.Popen(["cmd", "/c", *args], creationflags=0x00000010)   # CREATE_NEW_CONSOLE
        os._exit(0)
    os.execv(str(launcher), args)


def serve(port=8790, open_browser=True):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qsl, urlsplit
    import webbrowser

    token = _rand.token_urlsafe(24)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj=None, ctype="application/json", raw=None):
            data = raw if raw is not None else json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _route(self, method):
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
            if host not in ("127.0.0.1", "localhost"):
                return self._send(403, {"error": "bad host"})
            u = urlsplit(self.path)
            q = dict(parse_qsl(u.query))
            if u.path == "/" and method == "GET":
                html = (HERE / "console.html").read_text(encoding="utf-8").replace("__POV_TOKEN__", token)
                return self._send(200, raw=html.encode(), ctype="text/html; charset=utf-8")
            if u.path in ("/plan", "/report", "/aiguard-report") and method == "GET":
                data = page_file(u.path, q, token)
                return self._send(200, raw=data, ctype="text/html; charset=utf-8") if data else \
                    self._send(404, {"error": "not found"})
            if u.path == "/diagnostics" and method == "GET":
                data = diagnostics_zip(q, token)
                return self._send(200, raw=data, ctype="application/zip") if data else self._send(403, {"error": "bad token"})
            if not u.path.startswith("/api/") or self.headers.get("X-POV-Token") != token:
                return self._send(403, {"error": "bad token"})
            body = {}
            if method == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                if n > 20 * 1024 * 1024:
                    return self._send(413, {"error": "too large"})
                try:
                    body = json.loads(self.rfile.read(n) or b"{}")
                except ValueError:
                    return self._send(400, {"error": "bad JSON"})
            try:
                code, out = api(method, u.path, body, q)
            except KitError as e:
                code, out = 400, {"error": str(e)}
            except Exception as e:
                code, out = 500, {"error": f"{type(e).__name__}: {e}"}
            self._send(code, out)

        def do_GET(self):
            self._route("GET")

        def do_POST(self):
            self._route("POST")

    srv = None
    for p in range(port, port + 20):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), H)
            port = p
            break
        except OSError:
            continue
    if not srv:
        raise KitError(f"No free local port between {port} and {port + 19}.")
    SERVER.update(srv=srv, port=port)
    url = f"http://127.0.0.1:{port}/"
    print(f"  POV console: {url}   (this computer only; Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    if SERVER.pop("restart", False):   # an update or rollback asked for it: the main thread restarts, not a timer
        srv.server_close()
        print("  Restarting the console with the installed kit...")
        _exec_installed(port)
    return srv
