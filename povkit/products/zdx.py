"""Digital Experience (ZDX): evidence from the pilot devices, plus one deep trace per device for the report.

ZDX's API can't create probes, so this module mostly reads: it finds the pilot users' devices, checks they report a
ZDX score, and starts a short deep trace on each (the POV's only ZDX objects). Deep traces end on their own after
the chosen length; teardown deletes them so the customer's troubleshooting list stays clean.
Methods are from zscaler-sdk-python 1.11 (zdx.devices, zdx.apps, zdx.troubleshooting); field names are unverified
until the lab test plan runs.
"""
from __future__ import annotations

import re

from ..core import GuardError, KitError, naming
from ..core.changelist import item
from ..core.checks import FAIL, INFO, OK, WARN, check
from ..tenant import g, items
from .base import Product

MINUTES = 15


def zcfg(pov):
    return pov.cfg.get("zdx") or {}


class ZDX(Product):
    name, title, phase = "zdx", "Digital Experience (ZDX)", "v3"

    def role_scopes(self, pov=None):
        return {"discovery": [("ZDX", "view only")], "apply": [("ZDX: troubleshooting (deep traces)", "full")]}

    def discover(self, t, pov):
        c, checks, snap = zcfg(pov), [], {}
        emails = [e for e in pov.cfg.get("pilot_emails") or [] if e]
        try:
            apps = items(t.call("zdx.apps", "list_apps"))
        except KitError as e:
            denied = bool(re.search(r"\b403\b|not authori", str(e), re.I))
            return {"readable": False}, [check(
                "zdx-read", "ZDX readable", FAIL, "the API client has no ZDX role" if denied else str(e)[:160],
                "In ZIdentity → Integration → API Clients, edit this POV's client and add a ZDX role (view only is "
                "enough for preflight), then run the checks again. The kit never changes its own client's roles. "
                "Or take ZDX out of the POV's products (Start a POV)." if denied else
                "Give the discovery client view access to ZDX.", console="oneapi.clients")]
        snap["readable"] = True
        want = c.get("app")
        app = next((a for a in apps if want and str(g(a, "name")) == want), None) or (apps[0] if apps else None)
        snap["app"] = {"id": str(g(app, "id")), "name": g(app, "name")} if app else None
        snap["apps"] = [{"id": str(g(a, "id")), "name": g(a, "name")} for a in apps[:200] if g(a, "id")]
        checks.append(check("zdx-app", "A ZDX-monitored app to trace", OK if app else WARN,
                            g(app, "name") if app else "none", "" if app else "Monitor an app in ZDX first."))
        if not emails:
            checks.append(check("zdx-users", "Pilot users chosen for ZDX", FAIL, "none yet",
                                "`pov-kit set pilot_emails jane@acme.com,raj@acme.com` (pilot users with Client Connector)."))
            snap["devices"] = []
            return snap, checks
        devs = items(t.call("zdx.devices", "list_devices", query_params={"emails": emails, "since": 24}))
        snap["devices"] = [{"id": str(g(d, "id")), "name": g(d, "name"), "user": g(d, "user_email") or g(d, "email")}
                           for d in devs if g(d, "id")]
        checks.append(check("zdx-devices", "Pilot devices report to ZDX", OK if snap["devices"] else WARN,
                            f"{len(snap['devices'])} in the last 24 hours",
                            "" if snap["devices"] else "Pilot devices appear once Client Connector with ZDX has run."))
        return snap, checks

    def plan(self, pov, snap):
        if not snap.get("readable") or not snap.get("app") or not snap.get("devices"):
            return [], ["No ZDX deep traces until pilot devices report and an app is monitored."]
        from .. import usecases
        P, app = pov.prefix, snap["app"]
        out = []
        for d in snap["devices"]:
            n = naming.name(P, f"baseline {d['name'] or d['id']}", 60)
            out.append(item("zdx", "deeptrace", f"zdx.deeptrace.{d['id']}", n, rule_type=d["id"],
                            affects=f"device {d['name'] or d['id']} only, for {MINUTES} minutes",
                            criteria=["DX-SCR-01"], why=f"A {MINUTES}-minute deep trace of {app['name']}, for the report.",
                            body={"session_name": n, "app_id": app["id"], "session_length_minutes": MINUTES,
                                  "probe_device": True}))
        return out + usecases.zdx_items(pov, snap), ["Deep traces end on their own; teardown deletes them."]

    def apply(self, t, pov, items_, log):
        for it in [i for i in items_ if i["product"] == "zdx" and i["action"] == "create"]:
            t.create(it["key"], "zdx.troubleshooting", "start_deeptrace", it["rule_type"], stamped=False,
                     extract_id=lambda r: r.get("trace_id") or r.get("traceId") or r.get("id"), **it["body"])
            log("ok", f"Started {it['name']}")

    def live_object(self, t, entry):
        try:
            o = t.call("zdx.troubleshooting", "get_deeptrace", entry["rule_type"], entry["id"])
        except Exception as e:
            if re.search(r"\b404\b|not.?found", str(e), re.I):
                return None
            raise
        if isinstance(o, dict) and o:
            return dict(o, id=entry["id"], name=o.get("session_name") or o.get("sessionName") or entry["name"])
        return None

    def drift(self, t, pov, ledger, items_):
        want = [i for i in items_ if i["product"] == "zdx" and i["action"] == "create"]
        done = [i for i in want if ledger.find(i["key"])]
        return [check("zdx-traces", "Baseline deep traces", OK if len(done) == len(want) else INFO,
                      f"{len(done)} of {len(want)} started")] if want else []

    def teardown(self, t, pov, ledger, log):
        out = []
        for e in ledger.newest_first("zdx"):
            live = self.live_object(t, e)
            if live is None:
                ledger.mark(e, "deleted")
                continue
            try:
                t.delete(e, live, "zdx.troubleshooting", "delete_deeptrace", e["rule_type"], e["id"])
                log("ok", f"Deleted {e['name']}")
            except GuardError as err:
                out.append(check("zdx-left", f"Left in place: {e['name']}", WARN, str(err)))
        return out

    def api_proof(self, t, pov, ledger, criterion):
        if criterion["id"] != "DX-SCR-01":
            return None
        snap = ((pov.read_json("discovery.json", {}) or {}).get("products") or {}).get("zdx") or {}
        rows = []
        for d in snap.get("devices") or []:
            try:
                apps = items(t.call("zdx.devices", "get_device_apps", d["id"]))
                scores = [g(a, "score") for a in apps if g(a, "score") not in (None, -1)]
            except KitError:
                scores = []
            rows.append({"device": d["name"] or d["id"], "scores": scores})
        good = [r for r in rows if r["scores"]]
        return {"status": "pass" if rows and len(good) == len(rows) else "fail" if rows else "incomplete",
                "results": rows, "detail": f"{len(good)} of {len(rows)} pilot devices report ZDX scores"}

    def customer_names(self, snap):
        return {d["name"] for d in snap.get("devices") or [] if d.get("name")} | \
            {d["user"] for d in snap.get("devices") or [] if d.get("user")}
