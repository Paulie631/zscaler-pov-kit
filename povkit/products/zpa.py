"""Private Access (ZPA): one POV application reached through the POV's own App Connectors, for the pilot group only.

Creates, in order: an App Connector group, a provisioning key for it (its secret goes to the keychain, then into the
connector template), a server group, a segment group, the application segment for the customer's POV app, and an
access rule that allows the pilot SCIM group to that segment only. Nothing the customer already has is changed.

ZPA lets the first matching access rule decide, and with no match access is denied, so users outside the pilot
group are denied by default (PA-APP-02) unless a broad customer rule allows them. Discovery looks for such rules.
Method names and arguments are from zscaler-sdk-python 1.11 (its docstrings); bodies are unverified until the lab
test plan runs.
"""
from __future__ import annotations

import re

from ..core import GuardError, KitError, naming, secrets
from ..core.changelist import item
from ..core.checks import FAIL, OK, WARN, check
from ..core.ledger import Ledger
from ..tenant import g, items
from .base import Product

KEY_TYPE = "connector"
KEY_SECRET = "zpa-provisioning-key"
# kind: resource, get(entry) args, delete(entry) args, Terraform resource (name, confirmed)
KINDS = {
    "connector_group": dict(res="zpa.app_connector_groups", get="get_connector_group", dele="delete_connector_group",
                            title="App Connector group", tf=("zpa_app_connector_group", False)),
    "provisioning_key": dict(res="zpa.provisioning", get="get_provisioning_key", dele="delete_provisioning_key",
                             typed=True, title="Provisioning key", tf=("zpa_provisioning_key", False)),
    "server_group": dict(res="zpa.server_groups", get="get_group", dele="delete_group", title="Server group",
                         tf=("zpa_server_group", False)),
    "segment_group": dict(res="zpa.segment_groups", get="get_group", dele="delete_group", title="Segment group",
                          tf=("zpa_segment_group", False)),
    "app_segment": dict(res="zpa.application_segment", get="get_segment", dele="delete_segment",
                        title="Application segment", tf=("zpa_application_segment", False)),
    "access_rule": dict(res="zpa.policies", get="get_rule", dele="delete_rule", policy=True, title="Access rule",
                        tf=("zpa_policy_access_rule", False)),
}
ORDER = list(KINDS)   # creation order; teardown runs newest first
LISTS = {"connector_group": ("zpa.app_connector_groups", "list_connector_groups"),
         "server_group": ("zpa.server_groups", "list_groups"), "segment_group": ("zpa.segment_groups", "list_groups"),
         "app_segment": ("zpa.application_segment", "list_segments")}


def ledger_of(pov):
    return Ledger(pov.path("ledger.json"), pov.id, pov.prefix)


def zcfg(pov):
    return pov.cfg.get("zpa") or {}


def args_for(entry, verb):
    k = KINDS[entry["kind"]]
    if k.get("policy"):
        return ("access", entry["id"])
    if k.get("typed"):
        return (entry["id"], KEY_TYPE)
    return (entry["id"],)


def port_pairs(ports):
    """['443', '8443-8445'] -> the SDK's legacy pairs ['443', '443', '8443', '8445']."""
    out = []
    for p in ports:
        lo, _, hi = str(p).partition("-")
        out += [lo.strip(), (hi or lo).strip()]
    return out


def broad_allow(rule):
    """An enabled allow rule with no application condition: it can let anyone it matches reach any app."""
    if str(g(rule, "action") or "").upper() != "ALLOW":
        return False
    operands = [o for c in (g(rule, "conditions") or []) for o in (g(c, "operands") or [])]
    return not any(str(g(o, "object_type") or "").upper() in ("APP", "APP_GROUP") for o in operands)


class ZPA(Product):
    name, title, phase = "zpa", "Private Access (ZPA)", "v2"

    def role_scopes(self, pov=None):
        return {"discovery": [("ZPA: all areas", "view only")],
                "apply": [("ZPA: App Connector groups, provisioning keys, server groups, segment groups, application "
                           "segments, access policy", "full"),
                          ("ZPA: administrators, roles, IdP configuration, enrollment certificates", "none")]}

    # ---------------------------------------------------------------- discover
    def discover(self, t, pov):
        c, checks, snap = zcfg(pov), [], {}
        ledger = ledger_of(pov)
        domains = [d for d in c.get("domains", []) if d]
        snap["app"] = {"name": c.get("app_name") or "POV app", "domains": domains,
                       "tcp_ports": c.get("tcp_ports") or ["443"]}
        checks.append(check("zpa-app", "POV application chosen", OK if domains else FAIL,
                            ", ".join(domains) or "no domains yet",
                            "" if domains else "Set the app's domains or IPs: `pov-kit set zpa.domains app.acme.internal` "
                            "(and `zpa.tcp_ports 443`)."))
        try:
            certs = items(t.call("zpa.enrollment_certificates", "list_enrolment"))
            cert = next((x for x in certs if str(g(x, "name")).lower() == "connector"), None)
            snap["enrollment_cert"] = g(cert, "id") if cert else None
        except KitError as e:
            return {"readable": False}, [check("zpa-read", "ZPA readable", FAIL, str(e)[:160],
                                               "Give the discovery client view access to ZPA.")]
        snap["readable"] = True
        checks.append(check("zpa-cert", "Connector enrollment certificate", OK if snap["enrollment_cert"] else FAIL,
                            "found" if snap["enrollment_cert"] else "no certificate named 'Connector'",
                            "" if snap["enrollment_cert"] else "Every ZPA tenant has one; check the discovery client's "
                            "view access to certificates."))

        want = (c.get("group") or pov.cfg.get("pilot_group") or "").strip()
        snap["pilot_group"] = snap["pilot_saml"] = None
        idps = items(t.call("zpa.idp", "list_idps"))
        snap["idps"] = [{"id": str(g(i, "id")), "name": g(i, "name")} for i in idps]
        if c.get("scope") == "saml":   # tenants that scope ZPA by a SAML attribute instead of SCIM groups
            attr, value = c.get("saml_attribute"), c.get("saml_value") or want
            for idp in idps:
                for a in items(t.call("zpa.saml_attributes", "list_saml_attributes_by_idp", str(g(idp, "id")))):
                    if attr and str(g(a, "name")) == attr:
                        snap["pilot_saml"] = {"idp_id": str(g(idp, "id")), "attr_id": str(g(a, "id")), "name": attr,
                                              "value": value, "idp": g(idp, "name")}
                        break
                if snap["pilot_saml"]:
                    break
            ps = snap["pilot_saml"]
            checks.append(check("zpa-pilot", "Pilot users matched by a SAML attribute", OK if ps and value else FAIL,
                                f"{attr} = {value} ({ps['idp']})" if ps else f"no SAML attribute named '{attr}'",
                                "" if ps and value else "`pov-kit set zpa.saml_attribute NAME` (as ZPA lists it under "
                                "the IdP's SAML attributes) and `set zpa.saml_value VALUE`."))
            idps = []   # skip the SCIM lookup
        for idp in idps:
            for grp in items(t.call("zpa.scim_groups", "list_scim_groups", str(g(idp, "id")),
                                    query_params={"search": want})) if want else []:
                if str(g(grp, "name")) == want:
                    snap["pilot_group"] = {"idp_id": str(g(idp, "id")), "id": str(g(grp, "id")), "name": want,
                                           "idp": g(idp, "name")}
                    break
            if snap["pilot_group"]:
                break
        if c.get("scope") != "saml":
            checks.append(check("zpa-pilot", "Pilot group exists as a ZPA SCIM group", OK if snap["pilot_group"] else FAIL,
                                f"{want} ({snap['pilot_group']['idp']})" if snap["pilot_group"]
                                else f"no SCIM group named exactly '{want}'",
                                "" if snap["pilot_group"] else "Name the SCIM group with `pov-kit set zpa.group NAME`. "
                                "If this tenant doesn't use SCIM for ZPA, scope by a SAML attribute instead: "
                                "`set zpa.scope saml`, `set zpa.saml_attribute NAME`, `set zpa.saml_value VALUE`."))

        snap["customer_names"], snap["segment_domains"], taken, overlap = [], [], [], []
        probe_snap = dict(snap, enrollment_cert="x", app=dict(snap["app"], domains=domains or ["x"]),
                          pilot_group=snap["pilot_group"] or {"idp_id": "x", "id": "x", "name": "x"}, pilot_saml=None)
        planned = {i["name"] for i in self.plan(pov, probe_snap)[0] if i["action"] == "create"}
        for kind, (res, meth) in LISTS.items():
            for o in items(t.call(res, meth)):
                n = str(g(o, "name") or "")
                mine = ledger.by_id("zpa", kind, g(o, "id")) is not None
                if not naming.has_prefix(n, pov.prefix):
                    snap["customer_names"].append(n)
                if n in planned and not mine:
                    taken.append(f"'{n}' ({KINDS[kind]['title']})")
                if kind == "app_segment" and not mine:
                    snap["segment_domains"] += [str(d).lower() for d in g(o, "domain_names") or []]
                    hit = set(g(o, "domain_names") or []) & set(domains)
                    if hit:
                        overlap.append(f"{', '.join(sorted(hit))} in '{n}'")
        snap["segment_domains"] = sorted(set(snap["segment_domains"]))
        rules = items(t.call("zpa.policies", "list_rules", "access"))
        snap["customer_names"] += [str(g(r, "name") or "") for r in rules if not naming.has_prefix(g(r, "name"), pov.prefix)]
        broad = [str(g(r, "name")) for r in rules if broad_allow(r) and not naming.has_prefix(g(r, "name"), pov.prefix)]
        snap["broad_rules"] = broad
        snap["taken"] = taken
        checks.append(check("zpa-names", "POV names are free", FAIL if taken else OK,
                            ", ".join(taken) if taken else f"{len(planned)} names checked",
                            "Start the POV with a different prefix." if taken else ""))
        checks.append(check("zpa-overlap", "POV app isn't already a customer segment", FAIL if overlap else OK,
                            "; ".join(overlap) if overlap else "no overlap",
                            "ZPA matches the most specific segment, so these domains already belong to the customer's "
                            "segment. Pick another app for the POV, or a domain only the POV uses." if overlap else ""))
        if broad:
            checks.append(check("zpa-broad", "No broad allow rules", WARN, ", ".join(broad),
                                "These rules allow access without naming an app, so users outside the pilot group may "
                                "reach the POV app too (PA-APP-02). The customer decides whether to change them."))
        return snap, checks

    # ---------------------------------------------------------------- plan (snapshot only)
    def plan(self, pov, snap):
        if not snap.get("readable"):
            return [], ["No ZPA items: ZPA wasn't readable in discovery."]
        app, saml = snap.get("app") or {}, snap.get("pilot_saml")
        grp = snap.get("pilot_group") or ({"name": f"{saml['name']} = {saml['value']}"} if saml else None)
        if not grp or not app.get("domains"):
            return [], ["No ZPA items until the pilot users (SCIM group or SAML attribute) and the POV app's domains "
                        "are set."]
        who = (["saml", [[saml["attr_id"], saml["value"]]]] if saml else ["scim_group", [[grp["idp_id"], grp["id"]]]])
        P, pid, c = pov.prefix, pov.id, zcfg(pov)
        n = {k: naming.name(P, s) for k, s in (("connector_group", "connectors"), ("provisioning_key", "connector key"),
                                               ("server_group", "POV servers"), ("segment_group", "POV apps"),
                                               ("app_segment", app["name"]), ("access_rule", "pilot access"))}
        d = lambda why: naming.describe(pid, why)  # noqa: E731
        affects = f"members of '{grp['name']}' only"
        out = [
            item("zpa", "connector_group", "zpa.connector_group", n["connector_group"], affects="nobody (no apps yet)",
                 criteria=["PA-CON-01"], why="The POV's own connectors, so no customer connector carries POV traffic.",
                 body={"name": n["connector_group"], "description": d("App Connectors for the POV"), "enabled": True,
                       "location": c.get("location", "New York, US"), "latitude": str(c.get("latitude", "40.7128")),
                       "longitude": str(c.get("longitude", "-74.0060")), "dns_query_type": "IPV4_IPV6",
                       "version_profile": "default", "enrollment_cert_id": snap["enrollment_cert"]}),
            item("zpa", "provisioning_key", "zpa.provisioning_key", n["provisioning_key"], affects="nobody",
                 criteria=["PA-CON-01"], why="Enrolls at most 2 connectors into the POV group; its secret goes to the "
                 "SE's keychain and the connector template, and teardown deletes it.",
                 body={"name": n["provisioning_key"], "max_usage": "2", "enrollment_cert_id": snap["enrollment_cert"],
                       "component_id": "{ref:zpa.connector_group}"}),
            item("zpa", "server_group", "zpa.server_group", n["server_group"], affects="nobody",
                 body={"name": n["server_group"], "description": d("servers found by the POV connectors"), "enabled": True,
                       "dynamic_discovery": True, "app_connector_group_ids": ["{ref:zpa.connector_group}"]}),
            item("zpa", "segment_group", "zpa.segment_group", n["segment_group"], affects="nobody",
                 body={"name": n["segment_group"], "description": d("the POV application"), "enabled": True}),
            item("zpa", "app_segment", "zpa.app_segment", n["app_segment"], affects=affects,
                 criteria=["PA-APP-01", "PA-APP-02"],
                 why=f"{', '.join(app['domains'])} on TCP {', '.join(map(str, app['tcp_ports']))}.",
                 body={"name": n["app_segment"], "description": d("the POV application"), "enabled": True,
                       "domain_names": app["domains"], "segment_group_id": "{ref:zpa.segment_group}",
                       "server_group_ids": ["{ref:zpa.server_group}"], "tcp_port_ranges": port_pairs(app["tcp_ports"]),
                       "bypass_type": "NEVER", "health_reporting": "ON_ACCESS", "is_cname_enabled": True}),
            item("zpa", "access_rule", "zpa.access_rule", n["access_rule"], affects=affects, placement="top",
                 criteria=["PA-APP-01", "PA-APP-02"],
                 why="Allows the pilot group to the POV app only. Placed first, so a customer rule above can't deny it.",
                 body={"name": n["access_rule"], "description": d("pilot group to the POV app"), "action": "allow",
                       "app_connector_group_ids": ["{ref:zpa.connector_group}"],
                       "conditions": [["app", ["{ref:zpa.app_segment}"]], who]}),
            item("zpa", "customer_action", "zpa.ca.connectors", "Two App Connectors run from the POV connector template",
                 action="customer_action", criteria=["PA-CON-01"], console="zpa.app_connectors",
                 why="`pov-kit zpa template` writes an AWS CloudFormation template; the customer deploys it in their "
                     "account, in a subnet that reaches the app and Zscaler on TCP 443."),
            item("zpa", "customer_action", "zpa.ca.users", f"Members of '{grp['name']}' have ZPA enabled in Client Connector",
                 action="customer_action", criteria=["PA-APP-01"], console="zcc.app_profiles",
                 why="Their Client Connector app profile must have ZPA turned on."),
        ]
        from .. import usecases   # accepted use cases: more POV apps, each with its own pilot-only access rule
        out[-2:-2] = usecases.zpa_items(pov, snap, who, affects)
        taken = {x.split("'")[1] for x in snap.get("taken", [])}
        notes = ["ZPA access rules: the first match decides, and no match means deny."]
        if snap.get("broad_rules"):
            notes.append("Broad allow rules found (" + ", ".join(snap["broad_rules"]) + "): users outside the pilot "
                         "group may reach the POV app.")
        if taken:
            notes.append("Names already used by the customer's objects, left out: " + ", ".join(sorted(taken)))
            out = [i for i in out if i["name"] not in taken]
        return out, notes

    # ---------------------------------------------------------------- apply
    def apply(self, t, pov, items_, log):
        mine = [i for i in items_ if i["product"] == "zpa" and i["action"] == "create"]
        for kind in ORDER:
            k = KINDS[kind]
            for it in [i for i in mine if i["kind"] == kind]:
                if kind == "connector_group":
                    t.create(it["key"], k["res"], "add_connector_group", **it["body"])
                elif kind == "provisioning_key":
                    def keep_key(r, pov=pov):   # the key's secret, shown only now: straight to the keychain
                        if r.get("provisioning_key") or r.get("provisioningKey"):
                            secrets.put(pov.id, KEY_SECRET, r.get("provisioning_key") or r.get("provisioningKey"))
                        return r.get("id")
                    t.create(it["key"], k["res"], "add_provisioning_key", KEY_TYPE, extract_id=keep_key, stamped=False,
                             **it["body"])
                elif kind in ("server_group", "segment_group"):
                    t.create(it["key"], k["res"], "add_group", **it["body"])
                elif kind == "app_segment":
                    t.create(it["key"], k["res"], "add_segment", **it["body"])
                elif kind == "access_rule":
                    body = dict(it["body"])
                    t.create(it["key"], k["res"], "add_access_rule_v2", body.pop("name"), body.pop("action"),
                             extract_id=lambda r: r.get("id"), **body)
                    e = t.ledger.find(it["key"])
                    live = self.live_object(t, e)
                    if live and it.get("placement") == "top":
                        t.update(e, live, k["res"], "reorder_rule", "access", e["id"], "1")
                log("ok", f"Created {it['name']}")
        if secrets.get(pov.id, KEY_SECRET):
            log("info", "Provisioning key saved to the keychain. Next: `pov-kit zpa template` for the connectors.")

    # ---------------------------------------------------------------- live objects, drift, teardown
    def live_object(self, t, entry):
        k = KINDS[entry["kind"]]
        try:
            o = t.call(k["res"], k["get"], *args_for(entry, "get"))
        except Exception as e:
            if re.search(r"\b404\b|not found|does not exist|resource.not.found", str(e), re.I):
                return None
            raise
        return o if isinstance(o, dict) and o else None

    def connectors(self, t, ledger):
        e = ledger.find("zpa.connector_group")
        live = self.live_object(t, e) if e else None
        return list((live or {}).get("connectors") or [])

    def drift(self, t, pov, ledger, items_):
        out, missing, gone, foreign = [], [], [], []
        mine = [i for i in items_ if i["product"] == "zpa" and i["action"] == "create"]
        for it in mine:
            e = ledger.find(it["key"])
            if not e:
                missing.append(it["name"])
                continue
            live = self.live_object(t, e)
            if live is None:
                gone.append(it["name"])
                continue
            ok, why = ledger.owns("zpa", e["kind"], live)
            if not ok:
                foreign.append(f"{it['name']}: {why}")
        out.append(check("zpa-present", "POV ZPA objects present", WARN if (missing or gone) else OK,
                         "; ".join(filter(None, [f"not created yet: {', '.join(missing)}" if missing else "",
                                                 f"deleted in the console: {', '.join(gone)}" if gone else ""]))
                         or f"all {len(mine)}", "Run `pov-kit status --fix`." if (missing or gone) else "",
                         fixable=bool(missing or gone)))
        if foreign:
            out.append(check("zpa-foreign", "POV ZPA objects still the POV's", WARN, "; ".join(foreign),
                             "Renamed or restamped by someone, so the kit no longer touches them."))
        if ledger.find("zpa.connector_group"):
            n = len(self.connectors(t, ledger))
            out.append(check("zpa-connectors", "POV App Connectors enrolled", OK if n >= 2 else WARN, f"{n} of 2",
                             "" if n >= 2 else "Deploy the connector template (`pov-kit zpa template`)."))
        return out

    def fix_drift(self, t, pov, ledger, items_, log):
        for it in items_:
            if it["product"] == "zpa" and it["action"] == "create":
                e = ledger.find(it["key"])
                if e and self.live_object(t, e) is None:
                    ledger.mark(e, "deleted")
                    log("info", f"{it['name']} was deleted in the console; apply will recreate it")
        return False

    def teardown(self, t, pov, ledger, log):
        out = []
        n = len(self.connectors(t, ledger)) if ledger.find("zpa.connector_group") else 0
        if n:
            out.append(check("zpa-connectors-left", "App Connectors still enrolled", WARN, f"{n} in the POV group",
                             "Delete the connector stack in AWS and the connectors in the ZPA console, then rerun "
                             "teardown; ZPA won't delete a group with connectors in it."))
        for e in ledger.newest_first("zpa"):
            live = self.live_object(t, e)
            if live is None:
                ledger.mark(e, "deleted")
                continue
            if e["kind"] == "connector_group" and n:
                out.append(check("zpa-left", f"Left in place: {e['name']}", WARN, "connectors still enrolled"))
                continue
            k = KINDS[e["kind"]]
            try:
                t.delete(e, live, k["res"], k["dele"], *args_for(e, "delete"))
                log("ok", f"Deleted {e['name']}")
            except GuardError as err:
                out.append(check("zpa-left", f"Left in place: {e['name']}", WARN, str(err)))
        if not ledger.find("zpa.provisioning_key"):
            secrets.delete(pov.id, KEY_SECRET)
        return out

    def api_proof(self, t, pov, ledger, criterion):
        snap = ((pov.read_json("discovery.json", {}) or {}).get("products") or {}).get("zpa") or {}
        if criterion["id"] in ("PA-APP-01", "PA-APP-02"):
            e = ledger.find("zpa.access_rule")
            live = self.live_object(t, e) if e else None
            if not live:
                return {"status": "fail", "detail": "the POV access rule isn't in ZPA"}
            operands = [o for c in (g(live, "conditions") or []) for o in (g(c, "operands") or [])]
            saml = snap.get("pilot_saml")
            kind = "SAML" if saml else "SCIM_GROUP"
            groups = {str(g(o, "rhs")) for o in operands if str(g(o, "object_type") or "").upper() == kind}
            want = str(saml["value"] if saml else (snap.get("pilot_group") or {}).get("id"))
            scoped = groups == {want}
            if criterion["id"] == "PA-APP-01":
                up = self.api_proof(t, pov, ledger, {"id": "PA-CON-01"})
                return {"status": "pass" if scoped and up["status"] == "pass" else "fail",
                        "detail": f"access rule {'scoped to the pilot group' if scoped else 'not scoped as approved'}; "
                                  f"{up['detail']}"}
            broad = snap.get("broad_rules") or []
            return {"status": "pass" if scoped and not broad else "fail",
                    "detail": ("only the pilot group is allowed, and no broad customer rule allows others"
                               if scoped and not broad else
                               f"rule scoped: {scoped}; broad customer rules: {', '.join(broad) or 'none'}")}
        if criterion["id"] == "PA-CON-01":
            cons = self.connectors(t, ledger)
            up = [c for c in cons if re.search(r"AUTHENTICATED|ZPN_STATUS_ONLINE|^ONLINE$|^UP$",
                                              str(g(c, "control_channel_status") or g(c, "runtime_status") or ""), re.I)]
            return {"status": "pass" if len(up) >= 2 else "fail",
                    "detail": f"{len(up)} of {len(cons)} POV connectors connected (2 needed for failover)"}
        return None

    def terraform(self, entry, live):
        if entry["kind"] not in KINDS:
            return None
        rtype, confirmed = KINDS[entry["kind"]]["tf"]
        return {"type": rtype, "confirmed": confirmed, "id": entry["id"], "name": entry["name"]}

    def customer_names(self, snap):
        names = set(snap.get("customer_names") or [])
        if snap.get("pilot_group"):
            names.add(snap["pilot_group"]["name"])
        if snap.get("pilot_saml"):
            names.add(str(snap["pilot_saml"]["value"]))
        names |= set((snap.get("app") or {}).get("domains") or [])
        return names
