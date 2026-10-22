"""Internet Access (ZIA): the rules behind the Internet Security POV.

Reuses the AI Guard SE Demo Kit's ZIA know-how (resource names, the 31-character name limit, safe_name for labels,
SSL action bodies, tenant-aware Cloud App Control actions, rules placed at the top), with the POV safety model on
top: discovery is read-only, rules apply only to the customer's pilot group, and every write goes through the
ledger guard.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..core import GuardError, KitError, naming
from ..core.changelist import item
from ..core.checks import FAIL, INFO, OK, WARN, check
from ..core.ledger import Ledger
from ..tenant import g, items
from .base import Product

HERE = Path(__file__).resolve().parent
KINDS = ("label", "url_filtering", "ssl", "cloud_app_control", "dlp")
# resource, get, add, update, delete (cloud app control takes the rule type first)
API = {"label": ("rule_labels", "get_label", "add_label", "update_label", "delete_label"),
       "url_filtering": ("url_filtering", "get_rule", "add_rule", "update_rule", "delete_rule"),
       "ssl": ("ssl_inspection_rules", "get_rule", "add_rule", "update_rule", "delete_rule"),
       "cloud_app_control": ("cloudappcontrol", "get_rule", "add_rule", "update_rule", "delete_rule"),
       "dlp": ("dlp_web_rules", "get_rule", "add_rule", "update_rule", "delete_rule")}
LIST = {"label": ("rule_labels", "list_labels"), "url_filtering": ("url_filtering", "list_rules"),
        "ssl": ("ssl_inspection_rules", "list_rules"), "dlp": ("dlp_web_rules", "list_rules"),
        "cloud_app_control": ("cloudappcontrol", "list_rules")}
KIND_LABEL = {"label": "Rule label", "url_filtering": "URL filtering", "ssl": "SSL inspection",
              "cloud_app_control": "Cloud App Control", "dlp": "DLP"}
# Terraform resources for the export. confirmed = resource name and import ID checked against provider docs.
TF = {"url_filtering": ("zia_url_filtering_rules", True),
      "ssl": ("zia_ssl_inspection_rules", False), "cloud_app_control": ("zia_cloud_app_control_rule", False),
      "dlp": ("zia_dlp_web_rules", False), "label": ("zia_rule_labels", False)}
ALL_METHODS = ["CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "OTHER", "POST", "PUT", "TRACE"]
SSL_ACTIONS = {   # from the demo kit, checked against a live tenant
    "DECRYPT": {"type": "DECRYPT",
                "decrypt_sub_actions": {"server_certificates": "ALLOW", "ocsp_check": True,
                                        "block_ssl_traffic_with_no_sni_enabled": False,
                                        "min_client_tls_version": "CLIENT_TLS_1_0",
                                        "min_server_tls_version": "SERVER_TLS_1_0", "block_undecrypt": False}},
    "DO_NOT_DECRYPT": {"type": "DO_NOT_DECRYPT",
                       "do_not_decrypt_sub_actions": {"bypass_other_policies": False, "server_certificates": "ALLOW",
                                                      "ocsp_check": True,
                                                      "block_ssl_traffic_with_no_sni_enabled": False,
                                                      "min_tls_version": "SERVER_TLS_1_0"}},
}


def template():
    return json.loads((HERE / "zia_pov_template.json").read_text(encoding="utf-8"))


def key_for(kind, n):
    return f"zia.{kind}.{re.sub(r'[^a-z0-9]+', '-', n.lower()).strip('-')}"


def ledger_of(pov):
    return Ledger(pov.path("ledger.json"), pov.id, pov.prefix)


# ---------------------------------------------------------------- discovery helpers (all reads)
def auth_mode(t):
    """'hosted', 'saml' or 'directory' (the demo kit's auth_mode), or None if unreadable."""
    try:
        a = t.call("authentication_settings", "get_authentication_settings") or {}
    except Exception:
        return None, "couldn't read Internet Authentication Settings"
    repo = str(g(a, "org_auth_type") or "").upper()
    saml = bool(g(a, "saml_enabled"))
    detail = f"{'Hosted DB' if repo == 'SAFECHANNEL_DIR' else repo or 'unknown'}, {'SAML' if saml else 'form-based'} sign-in"
    if saml:
        return "saml", detail
    if repo == "SAFECHANNEL_DIR":
        return "hosted", detail
    return ("directory" if repo else None), detail


def activation_state(t):
    st = t.call("activate", "status")
    return str((g(st, "status") if isinstance(st, dict) else st) or "").upper()


def available_actions(t, rule_type, app):
    try:
        return [str(a) for a in items(t.call("cloudappcontrol", "list_available_actions", rule_type, [app] if app else []))
                if isinstance(a, str) and a]
    except Exception:
        return []


def _match(choice, avail):
    """From the demo kit: the preferred action, else one with the same verb and last word."""
    for a in choice:
        if a in avail:
            return a
    verb = ("BLOCK", "DENY") if choice[0].startswith(("BLOCK", "DENY")) else (choice[0].split("_", 1)[0],)
    tail = choice[0].rsplit("_", 2)[-2:] if choice[0].endswith("WEB_USE") else choice[0].rsplit("_", 1)[-1:]
    return next((a for a in avail if a.startswith(verb) and a.endswith("_".join(tail))), None)


def pick_actions(t, rule_type, apps, choices):
    """Ask the tenant which actions each app supports (never guess: a guessed name makes ZIA reject the whole rule).
    -> (apps kept, actions or None, why). A shortened port of the demo kit's pick_actions."""
    groups = {}
    for app in apps:
        avail = available_actions(t, rule_type, app)
        picked = [_match(c, avail) for c in choices]
        if avail and None not in picked:
            groups.setdefault(tuple(picked), []).append(app)
    if not groups:
        general = available_actions(t, rule_type, None)
        picked = [_match(c, general) for c in choices] if general else [None]
        if None not in picked:
            return list(apps), picked, "actions from the rule type (the apps list none of their own)"
        return [], None, f"the tenant offers no action like {choices[0][0]} for {', '.join(apps)}"
    actions, kept = max(groups.items(), key=lambda kv: len(kv[1]))
    dropped = [a for a in apps if a not in kept]
    return kept, list(actions), (f"left out {', '.join(dropped)} (no matching actions)" if dropped else "")


class ZIA(Product):
    name, title, phase = "zia", "Internet Access (ZIA)", "v1"

    def role_scopes(self):
        # Placeholders: the exact ZIA role scope names are an open question in the design (confirm in a lab tenant).
        return {"discovery": [("ZIA: all policy and administration areas", "view only")],
                "apply": [("ZIA policy: URL filtering, SSL inspection, Cloud App Control, DLP web rules, rule labels",
                           "full"),
                          ("ZIA: activation", "allowed"),
                          ("ZIA administration, roles, user management, authentication settings", "none")]}

    # ---------------------------------------------------------------- discover
    def discover(self, t, pov):
        tpl, checks, snap = template(), [], {"kinds": {}}
        ledger = ledger_of(pov)
        try:
            snap["activation"] = activation_state(t)
            pending = snap["activation"] not in ("", "ACTIVE")
            checks.append(check("zia-activation", "No ZIA changes waiting to be activated",
                                WARN if pending else OK, f"status {snap['activation'] or 'unknown'}",
                                "Ask the admin to activate or discard their pending changes first; the kit never "
                                "activates someone else's work." if pending else "", console="zia.activation"))
        except Exception as e:
            snap["activation"] = ""
            checks.append(check("zia-activation", "Activation status readable", FAIL, str(e)[:160],
                                "The discovery client needs view access to ZIA activation."))
        mode, detail = auth_mode(t)
        snap["auth"] = {"mode": mode, "detail": detail}
        checks.append(check("zia-auth", "How users sign in", INFO if mode else WARN, detail,
                            "" if mode else "Check Internet Authentication Settings by hand.", console="zia.auth"))
        try:
            t.call("zid.users", "list_users", query_params={"page_size": 1})
            snap["zidentity"] = True
        except Exception:
            snap["zidentity"] = False

        want = (pov.cfg.get("pilot_group") or "").strip()
        snap["pilot_group"] = None
        if not want:
            checks.append(check("zia-pilot", "Pilot group chosen", FAIL, "none yet",
                                "The customer names an existing group of pilot users: `pov-kit set pilot_group NAME`."))
        else:
            found = [x for x in items(t.call("user_management", "list_groups", query_params={"search": want}))
                     if str(g(x, "name")) == want]
            if found:
                snap["pilot_group"] = {"id": g(found[0], "id"), "name": g(found[0], "name")}
                checks.append(check("zia-pilot", "Pilot group exists in ZIA", OK, want))
            else:
                checks.append(check("zia-pilot", "Pilot group exists in ZIA", FAIL, f"no group named exactly '{want}'",
                                    "Use the group's name as ZIA shows it. Groups from an IdP appear after the "
                                    "first sync or sign-in.", console="zia.groups"))

        snap["url_categories"] = sorted({str(g(c, "id")) for c in items(t.call("url_categories", "list_categories"))
                                         if g(c, "id")})
        snap["dlp_engines"] = {}
        for e in items(t.call("dlp_engine", "list_dlp_engines_lite")):
            for k in ("name", "predefined_engine_name"):
                if g(e, k):
                    snap["dlp_engines"][str(g(e, k))] = g(e, "id")
        snap["cac"] = {}
        for r in tpl["cloud_app_control"]:
            apps, actions, why = pick_actions(t, r["rule_type"], r["applications"], r["actions"])
            snap["cac"][r["name"]] = {"apps": apps, "actions": actions, "why": why}

        planned = self._planned_names(pov)
        snap["customer_names"], lookalikes, taken = [], [], []
        for kind in KINDS:
            types_ = sorted({r["rule_type"] for r in tpl["cloud_app_control"]}) if kind == "cloud_app_control" else [None]
            rows = []
            for rt in types_:
                res, meth = LIST[kind]
                rows += items(t.call(res, meth, rt) if rt else t.call(res, meth))
            snap["kinds"][kind] = {"count": len(rows),
                                   "orders": sorted(int(g(r, "order") or 0) for r in rows if int(g(r, "order") or 0) > 0)}
            for r in rows:
                n = str(g(r, "name") or "")
                mine = ledger.by_id("zia", kind, g(r, "id")) is not None
                if not naming.has_prefix(n, pov.prefix):
                    snap["customer_names"].append(n)
                elif not mine:
                    lookalikes.append(f"'{n}' ({KIND_LABEL[kind]})")
                if n in planned.get(kind, ()) and not mine:
                    taken.append(f"'{n}' ({KIND_LABEL[kind]})")
        snap["taken"] = taken
        if lookalikes:
            checks.append(check("zia-lookalike", "Objects named like the POV's, but not the POV's", INFO,
                                ", ".join(lookalikes), "The kit leaves these alone."))
        checks.append(check("zia-names", "POV names are free", FAIL if taken else OK,
                            ", ".join(taken) if taken else f"{sum(len(v) for v in planned.values())} names checked",
                            "Start the POV with a different prefix (`pov-kit new --prefix NAME`)." if taken else ""))
        return snap, checks

    def _planned_names(self, pov):
        tpl, P = template(), pov.prefix
        out = {"label": {naming.safe_name(naming.name(P, tpl["label"]["name"]), P)}}
        for kind, sect in (("url_filtering", "url_filtering"), ("ssl", "ssl_inspection"),
                           ("cloud_app_control", "cloud_app_control"), ("dlp", "dlp")):
            out[kind] = {naming.name(P, r["name"]) for r in tpl[sect]}
        return out

    # ---------------------------------------------------------------- plan (snapshot only, no tenant calls)
    def plan(self, pov, snap):
        tpl, P, pid = template(), pov.prefix, pov.id
        notes, out = [], []
        grp = snap.get("pilot_group")
        if not grp:
            return [], ["No ZIA items: the pilot group wasn't found in discovery."]
        placement = pov.cfg.get("placement", "top")
        affects = f"members of '{grp['name']}' only"
        scope = {"groups": [grp["id"]], "state": "ENABLED", "rank": 7, "labels": ["{ref:zia.label}"]}
        cats = set(snap.get("url_categories") or [])

        lname = naming.safe_name(naming.name(P, tpl["label"]["name"]), P)
        out.append(item("zia", "label", "zia.label", lname, body={
            "name": lname, "description": naming.describe(pid, "labels every rule this POV creates")},
            affects="nobody (a label only)", why="Created first: if the apply client lacks write access, apply stops "
            "here with nothing else changed."))

        def keep_cats(r):
            ok = [c for c in r.get("url_categories", []) if not cats or c in cats]
            gone = [c for c in r.get("url_categories", []) if c not in ok]
            if gone:
                notes.append(f"'{naming.name(P, r['name'])}': categories not in this tenant, left out: {', '.join(gone)}")
            return ok

        for r in tpl["url_filtering"]:
            n = naming.name(P, r["name"])
            c = keep_cats(r)
            if not c:
                continue
            out.append(item("zia", "url_filtering", key_for("url_filtering", r["name"]), n, placement=placement,
                            affects=affects, criteria=r["criteria"], body=dict(
                                scope, name=n, action=r["action"], url_categories=c, protocols=["ANY_RULE"],
                                request_methods=["CONNECT", "GET", "HEAD"] if r["action"] == "CAUTION" else ALL_METHODS,
                                description=naming.describe(pid, ", ".join(r["criteria"])))))
        for r in tpl["ssl_inspection"]:
            n = naming.name(P, r["name"])
            body = dict(scope, name=n, action=SSL_ACTIONS[r["action"]], description=naming.describe(pid, r["why"]))
            if r.get("url_categories"):
                body["url_categories"] = keep_cats(r)
                if not body["url_categories"]:
                    continue
            out.append(item("zia", "ssl", key_for("ssl", r["name"]), n, placement=placement, affects=affects,
                            criteria=r["criteria"], why=r.get("why", ""), body=body))
        for r in tpl["cloud_app_control"]:
            n = naming.name(P, r["name"])
            got = (snap.get("cac") or {}).get(r["name"]) or {}
            if not got.get("actions"):
                notes.append(f"'{n}' left out: {got.get('why') or 'actions not checked'}")
                continue
            if got.get("why"):
                notes.append(f"'{n}': {got['why']}")
            out.append(item("zia", "cloud_app_control", key_for("cloud_app_control", r["name"]), n,
                            rule_type=r["rule_type"], placement=placement, affects=affects, criteria=r["criteria"],
                            body=dict(scope, name=n, applications=got["apps"], actions=got["actions"],
                                      description=naming.describe(pid, ", ".join(r["criteria"])))))
        for r in tpl["dlp"]:
            n = naming.name(P, r["name"])
            ids = [snap["dlp_engines"][e] for e in r["engines"] if e in (snap.get("dlp_engines") or {})]
            missing = [e for e in r["engines"] if e not in (snap.get("dlp_engines") or {})]
            if missing:
                notes.append(f"'{n}': DLP engines not found, left out: {', '.join(missing)}")
            if not ids:
                continue
            out.append(item("zia", "dlp", key_for("dlp", r["name"]), n, placement=placement, affects=affects,
                            criteria=r["criteria"], body=dict(
                                scope, name=n, action=r["action"], dlp_engines=ids,
                                protocols=["FTP_RULE", "HTTPS_RULE", "HTTP_RULE"],
                                severity="RULE_SEVERITY_HIGH" if r["action"] == "BLOCK" else "RULE_SEVERITY_MEDIUM",
                                description=naming.describe(pid, ", ".join(r["criteria"])))))
        for ca in tpl["customer_actions"]:
            out.append(item("zia", "customer_action", ca["key"], ca["name"], action="customer_action",
                            criteria=ca["criteria"], why=ca["why"], console=ca["console"]))
        if snap.get("zidentity"):
            out.append(item("zia", "customer_action", "zia.ca.entitlement",
                            f"Every member of '{grp['name']}' has the Internet & SaaS entitlement in ZIdentity",
                            action="customer_action", console="zid.entitlements",
                            why="ZIdentity's API can read entitlements but not grant them."))
        taken = {x.split("'")[1] for x in snap.get("taken", [])}
        if taken:
            notes.append("Names already used by the customer's own objects, so those items are left out: "
                         + ", ".join(sorted(taken)))
            out = [i for i in out if i["name"] not in taken]
        if placement == "top":
            notes.append("Rules go above the customer's rules of the same kind. That shifts their order numbers "
                         "but not their order, and the POV rules apply only to the pilot group.")
        return out, notes

    # ---------------------------------------------------------------- apply
    def guard_activation(self, t, verb):
        st = activation_state(t)
        if st not in ("", "ACTIVE"):
            raise KitError(f"ZIA has changes waiting to be activated (status {st}). Nothing was {verb}. Ask the admin "
                           "to activate or discard them, then rerun; the kit never activates someone else's work.")

    def _place(self, t, it, body):
        """Order 1 upward for 'top' (some tenants pin predefined rules first; the next slot is tried), last+1 for
        'bottom'. As the demo kit's _add_at_top."""
        res, meth = LIST[it["kind"]]
        rows = items(t.call(res, meth, it["rule_type"]) if it.get("rule_type") else t.call(res, meth))
        taken = sorted(int(g(r, "order") or 0) for r in rows if int(g(r, "order") or 0) > 0)
        tries = range(1, (taken[-1] if taken else 0) + 2) if it.get("placement") != "bottom" else [(taken[-1] if taken else 0) + 1]
        last = None
        for order in tries:
            try:
                args = (it["rule_type"],) if it.get("rule_type") else ()
                return t.create(it["key"], API[it["kind"]][0], API[it["kind"]][2], *args, **dict(body, order=order))
            except GuardError:
                raise
            except KitError as e:
                if not re.search(r"order|rank|predefined", str(e), re.I):
                    raise
                last = e
        raise last

    def apply(self, t, pov, items_, log):
        self.guard_activation(t, "applied")
        mine = [i for i in items_ if i["product"] == "zia" and i["action"] == "create"]
        for it in [i for i in mine if i["kind"] == "label"]:
            t.create(it["key"], "rule_labels", "add_label", **it["body"])
            log("ok", f"Created {it['name']}")
        for kind in ("url_filtering", "ssl", "cloud_app_control", "dlp"):
            group = [i for i in mine if i["kind"] == kind]
            # placed one by one at the top, so the last created ends up first: go in reverse to keep template order
            for it in (reversed(group) if pov.cfg.get("placement", "top") == "top" else group):
                self._place(t, it, it["body"])
                log("ok", f"Created {it['name']}")
        t.activate()
        log("ok", "ZIA changes activated")

    # ---------------------------------------------------------------- live objects, drift, teardown
    def live_object(self, t, entry):
        res, get = API[entry["kind"]][:2]
        args = (entry["rule_type"], entry["id"]) if entry.get("rule_type") else (entry["id"],)
        try:
            o = t.call(res, get, *args)
        except Exception as e:
            if re.search(r"\b404\b|not found|does not exist", str(e), re.I):
                return None
            raise
        return o if isinstance(o, dict) and o else None

    def drift(self, t, pov, ledger, items_):
        out, missing, gone, foreign, disabled, unscoped = [], [], [], [], [], []
        grp_id = None
        for it in items_:
            if it["product"] != "zia" or it["action"] != "create":
                continue
            grp_id = grp_id or (it["body"].get("groups") or [None])[0]
            e = ledger.find(it["key"])
            if not e:
                missing.append(it["name"])
                continue
            live = self.live_object(t, e)
            if live is None:
                gone.append(it["name"])
                continue
            ok, why = ledger.owns("zia", e["kind"], live)
            if not ok:
                foreign.append(f"{it['name']}: {why}")
                continue
            if e["kind"] != "label":
                if g(live, "state") not in (None, "ENABLED"):
                    disabled.append(it["name"])
                ids = {str(g(x, "id") if isinstance(x, dict) else x) for x in (g(live, "groups") or [])}
                if grp_id is not None and ids != {str(grp_id)}:
                    unscoped.append(it["name"])
        total = sum(1 for i in items_ if i["product"] == "zia" and i["action"] == "create")
        out.append(check("zia-present", "POV objects present", WARN if (missing or gone) else OK,
                         "; ".join(filter(None, [f"not created yet: {', '.join(missing)}" if missing else "",
                                                 f"deleted in the console: {', '.join(gone)}" if gone else ""]))
                         or f"all {total}", "Run `pov-kit status --fix`." if (missing or gone) else "",
                         fixable=bool(missing or gone)))
        if disabled:
            out.append(check("zia-disabled", "POV rules enabled", WARN, ", ".join(disabled), "Run `pov-kit status --fix`.",
                             fixable=True))
        if unscoped:
            out.append(check("zia-scope", "POV rules apply only to the pilot group", FAIL, ", ".join(unscoped),
                             "Someone changed who these rules apply to. Run `pov-kit status --fix` to put them back.",
                             fixable=True))
        if foreign:
            out.append(check("zia-foreign", "POV objects still the POV's", WARN, "; ".join(foreign),
                             "Renamed or restamped by someone, so the kit no longer touches them. Rename them back, "
                             "or delete them in the console."))
        try:
            st = activation_state(t)
            if st not in ("", "ACTIVE"):
                out.append(check("zia-activation", "ZIA changes activated", WARN, f"status {st}",
                                 "Activate in the ZIA console once you've checked whose changes are pending."))
        except Exception:
            pass
        return out

    def fix_drift(self, t, pov, ledger, items_, log):
        """Re-enable and re-scope the POV's own rules; forget ones deleted in the console so apply recreates them."""
        self.guard_activation(t, "fixed")
        changed = False
        for it in items_:
            if it["product"] != "zia" or it["action"] != "create":
                continue
            e = ledger.find(it["key"])
            if not e:
                continue
            live = self.live_object(t, e)
            if live is None:
                ledger.mark(e, "deleted")
                log("info", f"{it['name']} was deleted in the console; apply will recreate it")
                continue
            if e["kind"] == "label":
                continue
            ids = {str(g(x, "id") if isinstance(x, dict) else x) for x in (g(live, "groups") or [])}
            want = {str(x) for x in it["body"].get("groups", [])}
            if g(live, "state") not in (None, "ENABLED") or ids != want:
                res, _, _, upd, _ = API[e["kind"]]
                args = (e["rule_type"], e["id"]) if e.get("rule_type") else (e["id"],)
                body = dict(it["body"], order=g(live, "order"))
                t.update(e, live, res, upd, *args, **body)
                log("ok", f"Restored {it['name']}")
                changed = True
        if changed:
            t.activate()
        return changed

    def teardown(self, t, pov, ledger, log):
        self.guard_activation(t, "deleted")
        out, deleted = [], 0
        for e in ledger.newest_first("zia"):   # rules before the label they carry
            live = self.live_object(t, e)
            if live is None:
                ledger.mark(e, "deleted")
                log("info", f"{e['name']} was already gone")
                continue
            res, _, _, _, dele = API[e["kind"]]
            args = (e["rule_type"], e["id"]) if e.get("rule_type") else (e["id"],)
            if e["state"] == "adopted" and not getattr(pov, "include_adopted", False):
                out.append(check("zia-adopted", f"Kept: {e['name']}", INFO, "built by hand and adopted",
                                 "Run teardown again and answer yes to delete adopted objects too."))
                continue
            try:
                t.delete(e, live, res, dele, *args)
                deleted += 1
                log("ok", f"Deleted {e['name']}")
            except GuardError as err:
                out.append(check("zia-left", f"Left in place: {e['name']}", WARN, str(err)))
        if deleted:
            t.activate()
            log("ok", "ZIA changes activated")
        for e in [x for x in ledger.entries if x["product"] == "zia" and x["state"] == "deleted"]:
            if self.live_object(t, e) is not None and e.get("deleted_at"):
                out.append(check("zia-still", f"Still in the tenant: {e['name']}", FAIL, "deleted, but still listed",
                                 "Wait a minute and rerun teardown; then delete it in the console."))
        out.append(check("zia-teardown", "ZIA POV objects removed", OK if not out else WARN, f"{deleted} deleted"))
        return out

    def terraform(self, entry, live):
        if entry["kind"] not in TF:
            return None
        rtype, confirmed = TF[entry["kind"]]
        return {"type": rtype, "confirmed": confirmed, "id": entry["id"], "name": entry["name"]}

    def customer_names(self, snap):
        names = set(snap.get("customer_names") or [])
        if snap.get("pilot_group"):
            names.add(snap["pilot_group"]["name"])
        return names
