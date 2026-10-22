"""CASB and SSPM: one report-only CASB DLP rule over a SaaS tenant the customer has already connected.

Connecting a SaaS tenant (Microsoft 365, Google Workspace, Box...) is an OAuth grant only the customer can make, so
it is a customer action. Once it's connected, the POV adds one CASB DLP rule for the pilot group's files with the
action "report incident": it never quarantines, deletes or changes the customer's data. The API proof reads the SaaS
scan status. Methods are from zscaler-sdk-python 1.11 (zia.saas_security_api, zia.casb_dlp_rules; the action and
type values are from its docstrings); bodies are unverified until the lab test plan runs.
"""
from __future__ import annotations

import re

from ..core import GuardError, KitError, naming
from ..core.changelist import item
from ..core.checks import FAIL, OK, WARN, check
from ..tenant import g, items
from .base import Product
from .zia import activation_state


def guard_activation(t, verb):
    st = activation_state(t)
    if st not in ("", "ACTIVE"):
        raise KitError(f"ZIA has changes waiting to be activated (status {st}). Nothing was {verb}; the kit never "
                       "activates someone else's work.")

RULE_TYPE = "OFLCASB_DLP_FILE"
ACTION = "OFLCASB_DLP_REPORT_INCIDENT"


class CASB(Product):
    name, title, phase = "casb", "CASB and SSPM", "v3"

    def role_scopes(self, pov=None):
        return {"discovery": [("ZIA: SaaS security (CASB, SSPM)", "view only")],
                "apply": [("ZIA: CASB DLP rules", "full"), ("ZIA: SaaS tenant connections", "none")]}

    def discover(self, t, pov):
        checks, snap = [], {}
        try:
            tenants = items(t.call("saas_security_api", "list_casb_tenant_lite"))
        except KitError as e:
            return {"readable": False}, [check("casb-read", "SaaS security readable", FAIL, str(e)[:160],
                                               "Give the discovery client view access to ZIA SaaS security.")]
        snap["readable"] = True
        want = (pov.cfg.get("casb") or {}).get("tenant")
        hit = next((x for x in tenants if want and str(g(x, "tenant_name") or g(x, "name")) == want), None) or \
            (tenants[0] if len(tenants) == 1 else None)
        snap["tenant"] = {"id": g(hit, "tenant_id") or g(hit, "id"), "name": g(hit, "tenant_name") or g(hit, "name")} \
            if hit else None
        checks.append(check("casb-tenant", "A connected SaaS tenant", OK if hit else WARN,
                            snap["tenant"]["name"] if hit else f"{len(tenants)} connected"
                            + ("; choose one: `pov-kit set casb.tenant NAME`" if len(tenants) > 1 else ""),
                            "" if hit else "The customer connects a SaaS tenant in the console (an OAuth grant)."))
        zia_snap = ((pov.read_json("discovery.json", {}) or {}).get("products") or {}).get("zia") or {}
        engines = zia_snap.get("dlp_engines") or {
            str(g(e, "name")): g(e, "id") for e in items(t.call("dlp_engine", "list_dlp_engines_lite"))}
        snap["engine"] = engines.get("5 or more Credit Card Numbers")
        from ..core.ledger import Ledger
        led = Ledger(pov.path("ledger.json"), pov.id, pov.prefix)
        rules = items(t.call("casb_dlp_rules", "list_rules", RULE_TYPE))
        name = naming.name(pov.prefix, "SaaS card numbers")
        snap["taken"] = [name] if any(g(r, "name") == name and not led.by_id("casb", "casb_dlp_rule", g(r, "id"))
                                      for r in rules) else []
        theirs = [r for r in rules if not naming.has_prefix(g(r, "name"), pov.prefix)]
        snap["customer_names"] = [str(g(r, "name")) for r in theirs]
        # the customer's rules only: the POV rule's own order must not change the plan after apply
        snap["orders"] = sorted(int(g(r, "order") or 0) for r in theirs)
        if snap["taken"]:
            checks.append(check("casb-names", "POV names are free", FAIL, name, "Use a different prefix."))
        return snap, checks

    def plan(self, pov, snap, zia_snap=None):
        if not snap.get("readable"):
            return [], ["No CASB items: SaaS security wasn't readable in discovery."]
        out = [item("casb", "customer_action", "casb.ca.tenant", "A SaaS tenant is connected for SaaS security",
                    action="customer_action", criteria=["CS-SAS-01"], console="zia.saas_tenants",
                    why="Connecting it is an OAuth grant in the customer's SaaS admin; only the customer can make it.")]
        grp = (zia_snap or {}).get("pilot_group")
        if snap.get("tenant") and snap.get("engine") and grp and not snap.get("taken"):
            n = naming.name(pov.prefix, "SaaS card numbers")
            out.insert(0, item("casb", "casb_dlp_rule", "casb.dlp_rule", n, rule_type=RULE_TYPE,
                               affects=f"files owned by members of '{grp['name']}' in {snap['tenant']['name']}",
                               criteria=["CS-SAS-01"], placement="bottom",
                               why="Reports incidents only: it never quarantines, deletes or changes files.",
                               body={"name": n, "type": RULE_TYPE, "enabled": True, "action": ACTION, "rank": 7,
                                     "order": (snap.get("orders") or [0])[-1] + 1, "severity": "RULE_SEVERITY_MEDIUM",
                                     "cloud_app_tenant_ids": [snap["tenant"]["id"]], "dlp_engines": [snap["engine"]],
                                     "groups": [grp["id"]], "without_content_inspection": False,
                                     "description": naming.describe(pov.id, "report-only SaaS DLP for the pilot group")}))
        notes = [] if len(out) > 1 else ["No CASB DLP rule until a SaaS tenant is connected and the ZIA pilot group exists."]
        return out, notes

    def apply(self, t, pov, items_, log):
        mine = [i for i in items_ if i["product"] == "casb" and i["action"] == "create"]
        if not mine:
            return
        guard_activation(t, "applied")
        for it in mine:
            t.create(it["key"], "casb_dlp_rules", "add_rule", **it["body"])
            log("ok", f"Created {it['name']}")
        t.activate()   # CASB DLP rules are ZIA policy

    def live_object(self, t, entry):
        try:
            o = t.call("casb_dlp_rules", "get_rule", int(entry["id"]), entry["rule_type"])
        except Exception as e:
            if re.search(r"\b404\b|not.?found", str(e), re.I):
                return None
            raise
        return o if isinstance(o, dict) and o else None

    def drift(self, t, pov, ledger, items_):
        want = [i for i in items_ if i["product"] == "casb" and i["action"] == "create"]
        missing = [i["name"] for i in want if not ledger.find(i["key"])]
        gone = [e["name"] for e in ledger.active("casb") if self.live_object(t, e) is None]
        if not want:
            return []
        return [check("casb-present", "POV CASB DLP rule present", WARN if (missing or gone) else OK,
                      ", ".join(missing + gone) or "present", "Run `pov-kit status --fix`." if (missing or gone) else "",
                      fixable=bool(missing or gone))]

    def fix_drift(self, t, pov, ledger, items_, log):
        for e in ledger.active("casb"):
            if self.live_object(t, e) is None:
                ledger.mark(e, "deleted")
        return False

    def teardown(self, t, pov, ledger, log):
        out, deleted = [], 0
        if ledger.active("casb"):
            guard_activation(t, "deleted")
        for e in ledger.newest_first("casb"):
            live = self.live_object(t, e)
            if live is None:
                ledger.mark(e, "deleted")
                continue
            try:
                t.delete(e, live, "casb_dlp_rules", "delete_rule", int(e["id"]), e["rule_type"])
                deleted += 1
                log("ok", f"Deleted {e['name']}")
            except GuardError as err:
                out.append(check("casb-left", f"Left in place: {e['name']}", WARN, str(err)))
        if deleted:
            t.activate()
        return out

    def api_proof(self, t, pov, ledger, criterion):
        if criterion["id"] != "CS-SAS-01":
            return None
        scans = items(t.call("saas_security_api", "list_saas_scan_info"))
        snap = ((pov.read_json("discovery.json", {}) or {}).get("products") or {}).get("casb") or {}
        tid = str((snap.get("tenant") or {}).get("id"))
        mine = [s for s in scans if str(g(s, "tenant_id") or g(s, "id")) == tid] or scans
        return {"status": "pass" if mine else "incomplete",
                "detail": f"{len(mine)} SaaS scan configuration(s) for the connected tenant"
                + ("" if mine else "; findings appear after the first scan")}

    def terraform(self, entry, live):
        return {"type": "zia_casb_dlp_rule", "confirmed": False, "id": entry["id"], "name": entry["name"]}

    def customer_names(self, snap):
        names = set(snap.get("customer_names") or [])
        if snap.get("tenant"):
            names.add(str(snap["tenant"]["name"]))
        return names
