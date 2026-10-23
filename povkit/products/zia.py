"""Internet Access (ZIA): the policy behind the Internet Security POV.

Reuses the AI Guard SE Demo Kit's ZIA know-how (resource names, the 31-character name limit, safe_name where ':' is
refused, SSL action bodies, tenant-aware Cloud App Control actions, the tenant-check category, rules placed at the
top), with the POV safety model on top: discovery is read-only, rules apply only to the customer's pilot group, and
every write goes through the ledger guard.

Every object kind is one row of KINDS, so adding a kind is data, not new code paths.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..core import GuardError, KitError, naming, secrets
from ..core.changelist import item
from ..core.checks import FAIL, INFO, OK, WARN, check
from ..core.ledger import Ledger
from ..tenant import g, items
from .base import Product

HERE = Path(__file__).resolve().parent

# kind: SDK resource and methods, whether it is a policy rule (pilot-scoped, ordered), how it lists, and its
# Terraform resource (name, confirmed against the provider docs). Supporting objects come first: rules use them.
KINDS = {
    "label": dict(res="rule_labels", get="get_label", add="add_label", upd="update_label", dele="delete_label",
                  lst="list_labels", rule=False, title="Rule label", tf=("zia_rule_labels", True)),
    "url_category": dict(res="url_categories", get="get_category", add="add_url_category", upd="update_url_category",
                         dele="delete_category", lst="list_categories", q={"custom_only": True}, rule=False,
                         title="URL category", tf=("zia_url_categories", False)),
    "network_service": dict(res="cloud_firewall", get="get_network_service", add="add_network_service",
                            upd="update_network_service", dele="delete_network_service", lst="list_network_services",
                            rule=False, title="Network service", tf=("zia_fw_network_service", False)),
    "department": dict(res="user_management", get="get_department", add="add_department", upd="update_department",
                       dele="delete_department", lst="list_departments", rule=False, title="Department", tf=None,
                       by_prefix=True),
    "user_group": dict(res="user_management", get="get_group", add="add_group", upd="update_group",
                       dele="delete_group", lst="list_groups", rule=False, title="User group", tf=None,
                       by_prefix=True),
    "user": dict(res="user_management", get="get_user", add="add_user", upd="update_user", dele="delete_user",
                 lst="list_users", rule=False, title="Test user", tf=("zia_user_management_users", False),
                 by_prefix=True),
    "url_filtering": dict(res="url_filtering", rule=True, title="URL filtering", tf=("zia_url_filtering_rules", True)),
    "ssl": dict(res="ssl_inspection_rules", rule=True, title="SSL inspection", tf=("zia_ssl_inspection_rule", False)),
    "cloud_app_control": dict(res="cloudappcontrol", rule=True, typed=True, title="Cloud App Control",
                              tf=("zia_cloud_app_control_rule", False)),
    "file_type": dict(res="file_type_control_rule", rule=True, title="File type control",
                      tf=("zia_file_type_control_rules", True)),
    "dlp": dict(res="dlp_web_rules", rule=True, title="DLP", tf=("zia_dlp_web_rules", False)),
    "firewall": dict(res="cloud_firewall_rules", rule=True, title="Firewall", tf=("zia_firewall_filtering_rule", True)),
    "dns": dict(res="cloud_firewall_dns", rule=True, title="DNS control", tf=("zia_firewall_dns_rule", False)),
}
for _k in KINDS.values():
    if _k["rule"]:
        _k.update(get="get_rule", add="add_rule", upd="update_rule", dele="delete_rule", lst="list_rules")
RULE_KINDS = [k for k, v in KINDS.items() if v["rule"]]
KIND_LABEL = {k: v["title"] for k, v in KINDS.items()}
ALL_METHODS = ["CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "OTHER", "POST", "PUT", "TRACE"]
BROWSERS = ["CHROME", "FIREFOX", "MSEDGE", "MSCHREDGE", "SAFARI", "OPERA"]   # ZIA isolates known browsers only
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


# The DLP engine templates Zscaler ships in every tenant. The API flags them custom_dlp_engine: true (seen in a live
# tenant, 2026-10), so names-only use cases would otherwise hide them from Claude; only other custom engines are hidden.
ZSCALER_ENGINES = {"5 or more PII Identifiers", "5 or more Credit Card Numbers", "GDPR - Low Volume", "GDPR - High Volume",
                   "CCPA - High Volume", "CCPA - Low Volume", "NIST (RMF for DoD IT) - Low Volume",
                   "NIST (RMF for DoD IT) - High Volume", "PDPA - Low Volume", "PDPA - High Volume", "PIPEDA - Low Volume",
                   "PIPEDA - High Volume", "LGPD - Low Volume", "LGPD - High Volume", "FISMA - Low Volume",
                   "FISMA - High Volume", "PII (US) - Low Volume", "PII (US) - High Volume", "Credentials and Secrets",
                   "Finance", "Legal", "Medical", "DPDPA", "SOX"}
UNSTAMPED = {"department", "user_group", "user"}   # ZIA keeps 'comments' on these, not a description: ledger + prefix
TEST_PW = "zia-test-user-{n}"


def test_domain(t):
    """The email domain this tenant's users use (from the demo kit's tenant_domain)."""
    from collections import Counter
    seen = Counter()
    try:
        rows = items(t.call("user_management", "list_users", query_params={"page_size": 1000}))
    except Exception:
        rows = []
    for u in rows:
        v = str(g(u, "email") or "")
        if "@" in v and not re.search(r"zscaler|zslogin|zscloud", v.split("@", 1)[1], re.I):
            seen[v.split("@", 1)[1].lower()] += 1
    return seen.most_common(1)[0][0] if seen else None


def gen_password(n=20):
    """Random, and meets ZIA's Hosted DB password rules (from the demo kit)."""
    import secrets as _s
    import string
    special = "!@#$%^&*-_=+"
    pool = string.ascii_letters + string.digits + special
    while True:
        pw = "".join(_s.choice(pool) for _ in range(n))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
                and any(c in special for c in pw)):
            return pw


def zid_managed(e):
    """ZIA refuses user and group changes when ZIdentity owns the users ('UNMODIFIABLE ... OneIdentityUserLogin
    enabled users will have read only access'), whatever the API role allows. From the demo kit."""
    return bool(re.search(r"UNMODIFIABLE|OneIdentity", str(e), re.I))


def key_for(kind, n):
    return f"zia.{kind}.{re.sub(r'[^a-z0-9]+', '-', n.lower()).strip('-')}"


def want_groups(it, ledger):
    """The groups a POV rule should apply to, with {ref:...} filled in from the ledger."""
    ids = ledger.ids()
    out = set()
    for x in it["body"].get("groups", []):
        x = str(x)
        out.add(ids.get(x[5:-1], x) if x.startswith("{ref:") else x)
    return out


def ledger_of(pov):
    return Ledger(pov.path("ledger.json"), pov.id, pov.prefix)


def obj_name(o):
    return str(g(o, "name") or g(o, "configured_name") or "")


def list_kind(t, kind, rule_type=None, prefix=None):
    """by_prefix kinds (users, groups, departments) are searched by the POV prefix: listing every user in a large
    tenant would be slow, and the kit only needs to see its own and lookalikes."""
    k = KINDS[kind]
    args = (rule_type,) if k.get("typed") else ()
    if k.get("by_prefix"):
        return items(t.call(k["res"], k["lst"], query_params={"search": prefix or "ZPOV"}))
    if k.get("q"):
        return items(t.call(k["res"], k["lst"], *args, query_params=k["q"]))
    return items(t.call(k["res"], k["lst"], *args))


def rules_using_group(t, group_id):
    """Names of every ZIA rule (the customer's or a POV's) that applies to this group. Read-only."""
    tpl, gid, out = template(), str(group_id), []
    for kind in RULE_KINDS:
        types_ = sorted({r["rule_type"] for r in tpl["cloud_app_control"]}) if KINDS[kind].get("typed") else [None]
        for rt in types_:
            for r in list_kind(t, kind, rt):
                ids = {str(g(x, "id") if isinstance(x, dict) else x) for x in (g(r, "groups") or [])}
                if gid in ids:
                    out.append(obj_name(r))
    return out


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

    def role_scopes(self, pov=None):
        # Placeholders: the exact ZIA role scope names are an open question in the design (confirm in a lab tenant).
        from .zid import test_mode, users_in_zidentity
        users = bool(pov and test_mode(pov.cfg) and not users_in_zidentity(pov.cfg))
        return {"discovery": [("ZIA: all policy and administration areas", "view only")],
                "apply": [("ZIA policy: URL filtering, SSL inspection, Cloud App Control, file type control, DLP web "
                           "rules, firewall and DNS control, rule labels, custom URL categories, network services",
                           "full"),
                          ("ZIA: activation", "allowed")]
                + ([("ZIA user management (for the POV's Hosted DB test users only)", "full")] if users else [])
                + [("ZIA administration, roles, authentication settings"
                    + ("" if users else ", user management"), "none")]}

    # ---------------------------------------------------------------- names
    def _names(self, pov):
        """{kind: {planned names}} for every object the template can create."""
        tpl, P = template(), pov.prefix
        out = {k: set() for k in KINDS}
        out["label"].add(naming.safe_name(naming.name(P, tpl["label"]["name"]), P))
        out["user_group"].add(naming.safe_name(naming.name(P, "pilot users"), P))
        out["department"].add(naming.safe_name(naming.name(P, "pilot users"), P))
        out["url_category"].add(naming.safe_name(naming.name(P, tpl["url_category"]["name"]), P))
        out["network_service"].add(naming.safe_name(naming.name(P, tpl["network_service"]["name"]), P))
        for kind, sect in (("url_filtering", "url_filtering"), ("url_filtering", "isolation"), ("ssl", "ssl_inspection"),
                           ("cloud_app_control", "cloud_app_control"), ("file_type", "file_type"), ("dlp", "dlp"),
                           ("firewall", "firewall"), ("dns", "dns")):
            out[kind] |= {naming.name(P, r["name"]) for r in tpl[sect]}
        return out

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
        snap["test_users"] = None
        from .zid import enabled as zid_pilot, group_name, test_count, test_mode, ZIA_GROUP_KEY
        testing = test_mode(pov.cfg)
        n_test = test_count(pov.cfg) if testing else 0
        if zid_pilot(pov.cfg):   # the POV makes its own pilot group in ZIdentity, which sends it to ZIA
            gname = group_name(pov.prefix)
            snap["pilot_group"] = {"id": "{ref:%s}" % ZIA_GROUP_KEY, "name": gname}
            checks.append(check("zia-pilot", "Pilot group", INFO, f"'{gname}', made by the POV in ZIdentity"
                                + (" with its test users" if testing else ""),
                                "ZIdentity sends it to ZIA once it has the Internet & SaaS entitlement; apply checks "
                                "and waits for it."))
        elif testing and mode == "directory":
            checks.append(check("zia-testusers", "Test users", FAIL, "this tenant signs users in from a directory",
                                "The test users have to be made in that directory. Make them there, then choose 'Use "
                                "one of the customer's groups' with their group."))
        elif testing and mode == "saml":   # as the demo kit: SAML tenants get their test users in ZIdentity
            pov.cfg.setdefault("identity", {})["users_in"] = "zidentity"
            pov.save()
            checks.append(check("zia-testusers", "Test users", FAIL, "users sign in with SAML, so they go in ZIdentity",
                                "Run the checks again: the change list now makes the test users in ZIdentity."))
        elif testing:   # as the demo kit: ZIA first; apply switches to ZIdentity if ZIA refuses
            dom = (pov.cfg.get("identity") or {}).get("test_domain") or test_domain(t)
            snap["test_users"] = {"count": n_test, "domain": dom}
            gname = naming.safe_name(naming.name(pov.prefix, "pilot users"), pov.prefix)
            snap["pilot_group"] = {"id": "{ref:zia.user_group}", "name": gname}
            checks.append(check("zia-testusers", "Test users", OK if dom else FAIL,
                                f"{n_test} made in ZIA at {dom}, with a group and department" if dom
                                else "couldn't tell the users' email domain",
                                ("If ZIA refuses because ZIdentity owns the users, apply says so and the next change "
                                 "list makes them in ZIdentity instead." if snap["zidentity"] else "")
                                if dom else "`pov-kit set identity.test_domain acme.com`"))
        elif not want:
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
        snap["dlp_engines"], snap["custom_engines"] = {}, []
        for e in items(t.call("dlp_engine", "list_dlp_engines_lite")):
            for k in ("name", "predefined_engine_name"):
                if g(e, k):
                    snap["dlp_engines"][str(g(e, k))] = g(e, "id")
            # the customer's own engines (their names can identify them; names-only use cases hide them)
            custom = g(e, "custom_dlp_engine")
            if g(e, "name") and str(g(e, "name")) not in ZSCALER_ENGINES and \
                    (custom is True or (custom is None and not g(e, "predefined_engine_name"))):
                snap["custom_engines"].append(str(g(e, "name")))
        try:
            cats = t.call("file_type_control_rule", "list_file_type_categories",
                          query_params={"enums": "FILETYPECATEGORYFORFILETYPECONTROL"})
            names = {g(c, "name") if isinstance(c, dict) else c for c in items(cats)}
            snap["file_types"] = sorted(n for n in names if n) or None
        except Exception:
            snap["file_types"] = None   # older tenants: no listing, so the template's names are sent as they are
        try:
            profiles = items(t.call("cloud_browser_isolation", "list_isolation_profiles"))
            cbi = next((p for p in profiles if g(p, "default_profile")), None) or (profiles[0] if profiles else None)
            snap["cbi"] = {"id": g(cbi, "id"), "name": g(cbi, "name"), "url": g(cbi, "url")} if cbi else None
        except Exception:
            snap["cbi"] = None
        snap["cac"] = {}
        for r in tpl["cloud_app_control"]:
            apps, actions, why = pick_actions(t, r["rule_type"], r["applications"], r["actions"])
            snap["cac"][r["name"]] = {"apps": apps, "actions": actions, "why": why}
        from .. import usecases   # accepted use cases' Cloud App Control actions are checked the same way
        snap["uc_cac"] = {}
        for key, ch in usecases.cac_wanted(pov):
            apps, actions, why = pick_actions(t, ch["rule_type"], ch["applications"], [[a] for a in ch["actions"]])
            snap["uc_cac"][key] = {"apps": apps, "actions": actions, "why": why}

        planned = self._names(pov)
        snap["customer_names"], lookalikes, taken = [], [], []
        # ZIA's copy of the POV's own ZIdentity pilot group: linked in the ledger, so it's the POV's, not a clash
        linked_ids = {e["kind"]: e["id"] for e in ledger.entries if e["state"] == "linked" and e["product"] == "zia"}
        from .zid import enabled as zid_pilot, group_name
        ours_zid = group_name(pov.prefix) if zid_pilot(pov.cfg) and ledger.find("zid.group") else None
        for kind in KINDS:
            types_ = sorted({r["rule_type"] for r in tpl["cloud_app_control"]}) if KINDS[kind].get("typed") else [None]
            rows = []
            for rt in types_:
                try:
                    rows += list_kind(t, kind, rt, pov.prefix)
                except KitError as e:
                    checks.append(check(f"zia-read-{kind}", f"{KIND_LABEL[kind]} readable", FAIL, str(e)[:160],
                                        "Give the discovery client view access to this ZIA area."))
            snap["kinds"][kind] = {"count": len(rows)}
            for r in rows:
                n = obj_name(r)
                mine = (ledger.by_id("zia", kind, g(r, "id")) is not None or linked_ids.get(kind) == str(g(r, "id"))
                        or (kind == "user_group" and n == ours_zid))   # provisioned from the POV's ZIdentity group
                if not naming.has_prefix(n, pov.prefix):
                    if not g(r, "predefined"):
                        snap["customer_names"].append(n)
                elif not mine:
                    lookalikes.append(f"'{n}' ({KIND_LABEL[kind]})")
                if n in planned[kind] and not mine:
                    taken.append(f"'{n}' ({KIND_LABEL[kind]})")
        snap["taken"] = taken
        if lookalikes:
            checks.append(check("zia-lookalike", "Objects named like the POV's, but not the POV's", INFO,
                                ", ".join(lookalikes), "The kit leaves these alone."))
        checks.append(check("zia-names", "POV names are free", FAIL if taken else OK,
                            ", ".join(taken) if taken else f"{sum(len(v) for v in planned.values())} names checked",
                            "Start the POV with a different prefix (`pov-kit new --prefix NAME`)." if taken else ""))
        if not snap["cbi"]:
            checks.append(check("zia-cbi", "Cloud Browser Isolation profile", INFO, "none in this tenant",
                                "The isolation rule (IS-CBI-01) is left out."))
        return snap, checks

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
        refs = {"@" + tpl["url_category"]["key"]: f"{{ref:zia.url_category.{tpl['url_category']['key']}}}",
                "@" + tpl["network_service"]["key"]: f"{{ref:zia.network_service.{tpl['network_service']['key']}}}"}

        def rule(kind, r, body, rule_type=None, why=None):
            n = naming.name(P, r["name"])
            out.append(item("zia", kind, key_for(kind, r["name"]), n, rule_type=rule_type, placement=placement,
                            affects=affects, criteria=r.get("criteria", []), why=why if why is not None else r.get("why", ""),
                            body=dict(scope, name=n, description=naming.describe(pid, ", ".join(r.get("criteria", []))),
                                      **body)))

        def keep_cats(r):
            ok = [refs.get(c, c) for c in r.get("url_categories", []) if c in refs or not cats or c in cats]
            gone = [c for c in r.get("url_categories", []) if c not in refs and cats and c not in cats]
            if gone:
                notes.append(f"'{naming.name(P, r['name'])}': categories not in this tenant, left out: {', '.join(gone)}")
            return ok

        # supporting objects first: the label (the canary), the tenant-check category, the network service
        lname = naming.safe_name(naming.name(P, tpl["label"]["name"]), P)
        out.append(item("zia", "label", "zia.label", lname, affects="nobody (a label only)",
                        body={"name": lname, "description": naming.describe(pid, "labels every rule this POV creates")},
                        why="Created first: if the apply client lacks write access, apply stops here with nothing "
                            "else changed."))
        tu = snap.get("test_users")
        if tu and tu.get("domain"):
            dname = naming.safe_name(naming.name(P, "pilot users"), P)
            out.append(item("zia", "department", "zia.department", dname, affects="the POV's test users only",
                            body={"name": dname, "comments": naming.describe(pid, "department for POV test users")}))
            out.append(item("zia", "user_group", "zia.user_group", grp["name"], affects="the POV's test users only",
                            why="The pilot group: the POV's own test users, since this tenant keeps users in ZIA.",
                            body={"name": grp["name"], "comments": naming.describe(pid, "POV pilot users")}))
            for n in range(1, tu["count"] + 1):
                uname = naming.safe_name(naming.name(P, f"pilot user {n}"), P)
                out.append(item("zia", "user", f"zia.user.{n}", uname, affects="this test user only",
                                why="Its password is generated at apply and kept in the SE's keychain.",
                                body={"name": uname, "email": f"zpov-pilot-{n}@{tu['domain']}",
                                      "groups": [{"id": "{ref:zia.user_group}"}],
                                      "department": {"id": "{ref:zia.department}"},
                                      "comments": naming.describe(pid, "POV test user")}))
        ident = snap.get("identity") or {}
        if ident.get("bypass_domains"):
            bname = naming.safe_name(naming.name(P, "sign-in sites"), P)
            out.append(item("zia", "url_category", "zia.url_category.sign-in", bname, affects="nobody until a rule uses it",
                            why="The customer's IdP and MFA sites, from the identity step.",
                            body={"configured_name": bname, "super_category": "USER_DEFINED",
                                  "urls": ident["bypass_domains"], "custom_category": True,
                                  "description": naming.describe(pid, "sign-in and MFA sites, never decrypted")}))
        uc = tpl["url_category"]
        ucname = naming.safe_name(naming.name(P, uc["name"]), P)
        out.append(item("zia", "url_category", f"zia.url_category.{uc['key']}", ucname, criteria=uc["criteria"],
                        affects="nobody until a rule uses it", why=uc["description"],
                        body={"configured_name": ucname, "super_category": "USER_DEFINED", "urls": uc["urls"],
                              "custom_category": True, "description": naming.describe(pid, uc["description"])}))
        ns = tpl["network_service"]
        nsname = naming.safe_name(naming.name(P, ns["name"]), P)
        out.append(item("zia", "network_service", f"zia.network_service.{ns['key']}", nsname, criteria=ns["criteria"],
                        affects="nobody until a rule uses it", why=ns["description"],
                        body={"name": nsname, "ports": [["dest", "tcp", str(p)] for p in ns["dest_tcp"]],
                              "description": naming.describe(pid, ns["description"])}))

        for r in tpl["url_filtering"]:
            c = keep_cats(r)
            if c:
                rule("url_filtering", r, dict(action=r["action"], url_categories=c, protocols=["ANY_RULE"],
                                              request_methods=["CONNECT", "GET", "HEAD"] if r["action"] == "CAUTION"
                                              else ALL_METHODS))
        for r in tpl["isolation"]:
            if not snap.get("cbi"):
                notes.append(f"'{naming.name(P, r['name'])}' left out: no Cloud Browser Isolation profile in this tenant")
                continue
            c = keep_cats(r)
            if c:
                rule("url_filtering", r, dict(action="ISOLATE", url_categories=c, protocols=["HTTPS_RULE", "HTTP_RULE"],
                                              request_methods=["CONNECT", "GET", "HEAD"], user_agent_types=BROWSERS,
                                              cbi_profile=snap["cbi"]),
                     why=f"Opens these sites in the isolation profile '{snap['cbi']['name']}'.")
        ssl_rules = list(tpl["ssl_inspection"])
        if ident.get("bypass_domains"):   # first, so the inspect rule below can never break sign-in or MFA
            refs["@sign-in"] = "{ref:zia.url_category.sign-in}"
            ssl_rules.insert(0, {"name": "Bypass sign-in", "action": "DO_NOT_DECRYPT", "url_categories": ["@sign-in"],
                                 "criteria": [], "why": "Never decrypts the customer's IdP and MFA sites."})
        for r in ssl_rules:
            body = {"action": SSL_ACTIONS[r["action"]]}
            if r.get("url_categories"):
                body["url_categories"] = keep_cats(r)
                if not body["url_categories"]:
                    continue
            rule("ssl", r, body)
        for r in tpl["cloud_app_control"]:
            n = naming.name(P, r["name"])
            got = (snap.get("cac") or {}).get(r["name"]) or {}
            if not got.get("actions"):
                notes.append(f"'{n}' left out: {got.get('why') or 'actions not checked'}")
                continue
            if got.get("why"):
                notes.append(f"'{n}': {got['why']}")
            rule("cloud_app_control", r, dict(applications=got["apps"], actions=got["actions"]), rule_type=r["rule_type"])
        for r in tpl["file_type"]:
            types_ = r["file_types"]
            if snap.get("file_types"):
                gone = [x for x in types_ if x not in snap["file_types"]]
                types_ = [x for x in types_ if x in snap["file_types"]]
                if gone:
                    notes.append(f"'{naming.name(P, r['name'])}': file types not in this tenant, left out: {', '.join(gone)}")
            if types_:
                rule("file_type", r, dict(filtering_action=r["filtering_action"], operation=r["operation"],
                                          file_types=types_, protocols=["FOHTTP_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]))
        for r in tpl["dlp"]:
            ids = [snap["dlp_engines"][e] for e in r["engines"] if e in (snap.get("dlp_engines") or {})]
            missing = [e for e in r["engines"] if e not in (snap.get("dlp_engines") or {})]
            if missing:
                notes.append(f"'{naming.name(P, r['name'])}': DLP engines not found, left out: {', '.join(missing)}")
            if ids:
                rule("dlp", r, dict(action=r["action"], dlp_engines=ids, protocols=["FTP_RULE", "HTTPS_RULE", "HTTP_RULE"],
                                    severity="RULE_SEVERITY_HIGH" if r["action"] == "BLOCK" else "RULE_SEVERITY_MEDIUM"))
        for r in tpl["firewall"]:
            rule("firewall", r, dict(action=r["action"], nw_services=[refs.get(x, x) for x in r["nw_services"]],
                                     enable_full_logging=True))
        for r in tpl["dns"]:
            rule("dns", r, dict(action=r["action"], res_categories=r["res_categories"]))

        from .. import usecases   # accepted use cases join the change list as ordinary, approved items
        uc_items, uc_notes = usecases.zia_items(pov, snap, scope, affects, placement, snap.get("uc_cac") or {})
        out += uc_items
        notes += uc_notes

        for ca in tpl["customer_actions"]:
            out.append(item("zia", "customer_action", ca["key"], ca["name"], action="customer_action",
                            criteria=ca["criteria"], why=ca["why"], console=ca["console"]))
        if snap.get("zidentity") and not snap.get("test_users"):   # ZIA's own test users need no ZIdentity entitlement
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

    def _place(self, t, it, pov=None):
        """Order 1 upward for 'top' (some tenants pin predefined rules first; the next slot is tried), last+1 for
        'bottom'. As the demo kit's _add_at_top."""
        k = KINDS[it["kind"]]
        rows = list_kind(t, it["kind"], it.get("rule_type"), pov.prefix if pov else None)
        taken = sorted(int(g(r, "order") or 0) for r in rows if int(g(r, "order") or 0) > 0)
        tries = (range(1, (taken[-1] if taken else 0) + 2) if it.get("placement") != "bottom"
                 else [(taken[-1] if taken else 0) + 1])
        args = (it["rule_type"],) if k.get("typed") else ()
        last = None
        for order in tries:
            try:
                return t.create(it["key"], k["res"], k["add"], *args, **dict(it["body"], order=order))
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
        for kind in [k for k in KINDS if not KINDS[k]["rule"]]:
            for it in [i for i in mine if i["kind"] == kind]:
                k = KINDS[kind]
                try:
                    if kind == "user":
                        n = it["key"].rsplit(".", 1)[-1]
                        pw = secrets.get(pov.id, TEST_PW.format(n=n)) or gen_password()
                        secrets.put(pov.id, TEST_PW.format(n=n), pw)
                        t.create(it["key"], k["res"], k["add"], stamped=False, **dict(it["body"], password=pw))
                    else:
                        t.create(it["key"], k["res"], k["add"], stamped=kind not in UNSTAMPED, **it["body"])
                except KitError as e:
                    if kind in UNSTAMPED and zid_managed(e):   # the demo kit's rule: ZIdentity owns the users
                        pov.cfg.setdefault("identity", {})["users_in"] = "zidentity"
                        pov.save()
                        raise KitError("This tenant keeps its users in ZIdentity, so ZIA can't hold the POV's test "
                                       "users. Make the change list again: it now creates them in ZIdentity, on "
                                       "<vanity>.zslogin.net, and the customer approves it. Nothing else was changed "
                                       "beyond what's in the ledger.") from e
                    raise
                log("ok", f"{'Already there:' if getattr(t, 'existed', False) else 'Created'} {it['name']}")
        for kind in RULE_KINDS:
            group = [i for i in mine if i["kind"] == kind]
            # placed one by one at the top, so the last created ends up first: go in reverse to keep template order
            for it in (reversed(group) if pov.cfg.get("placement", "top") == "top" else group):
                self._place(t, it, pov)
                log("ok", f"{'Already there:' if getattr(t, 'existed', False) else 'Created'} {it['name']}")
        t.activate()
        log("ok", "ZIA changes activated")

    # ---------------------------------------------------------------- live objects, drift, teardown
    def _args(self, entry):
        return (entry["rule_type"], entry["id"]) if KINDS[entry["kind"]].get("typed") else (entry["id"],)

    def live_object(self, t, entry):
        k = KINDS[entry["kind"]]
        try:
            o = t.call(k["res"], k["get"], *self._args(entry))
        except Exception as e:
            if re.search(r"\b404\b|not found|does not exist", str(e), re.I):
                return None
            raise
        if not (isinstance(o, dict) and o):
            return None
        if entry["kind"] == "user" and not naming.has_prefix(obj_name(o), naming.split_prefix(entry["name"])):
            # an API role with "User Names: Obfuscated" scrambles the name a single get returns (seen live,
            # 2026-10); the user list shows it as it is, so take the name from there, matched by ID
            rows = items(t.call(k["res"], k["lst"], query_params={"search": entry["name"]}))
            hit = next((r for r in rows if str(g(r, "id")) == str(entry["id"])), None)
            if hit and obj_name(hit):
                o = dict(o, name=obj_name(hit))
        return o

    def drift(self, t, pov, ledger, items_):
        out, missing, gone, foreign, disabled, unscoped = [], [], [], [], [], []
        mine = [i for i in items_ if i["product"] == "zia" and i["action"] == "create"]
        for it in mine:
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
            if KINDS[e["kind"]]["rule"]:
                if g(live, "state") not in (None, "ENABLED"):
                    disabled.append(it["name"])
                ids = {str(g(x, "id") if isinstance(x, dict) else x) for x in (g(live, "groups") or [])}
                if ids != want_groups(it, ledger):
                    unscoped.append(it["name"])
        out.append(check("zia-present", "POV objects present", WARN if (missing or gone) else OK,
                         "; ".join(filter(None, [f"not created yet: {', '.join(missing)}" if missing else "",
                                                 f"deleted in the console: {', '.join(gone)}" if gone else ""]))
                         or f"all {len(mine)}", "Run `pov-kit status --fix`." if (missing or gone) else "",
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
            if not KINDS[e["kind"]]["rule"]:
                continue
            missing = [x for x in it["body"].get("groups", []) if str(x).startswith("{ref:") and str(x)[5:-1] not in t.ids]
            if missing:   # the group it should apply to isn't there yet (apply recreates it, then this runs again)
                log("info", f"{it['name']}: waiting for its pilot group before re-scoping it")
                continue
            ids = {str(g(x, "id") if isinstance(x, dict) else x) for x in (g(live, "groups") or [])}
            if g(live, "state") not in (None, "ENABLED") or ids != want_groups(it, ledger):
                k = KINDS[e["kind"]]
                t.update(e, live, k["res"], k["upd"], *self._args(e), **dict(it["body"], order=g(live, "order")))
                log("ok", f"Restored {it['name']}")
                changed = True
        if changed:
            t.activate()
        return changed

    def teardown(self, t, pov, ledger, log):
        self.guard_activation(t, "deleted")
        out, deleted = [], 0
        for e in ledger.newest_first("zia"):   # rules before the label, category and service they use
            live = self.live_object(t, e)
            if live is None:
                ledger.mark(e, "deleted")
                log("info", f"{e['name']} was already gone")
                continue
            if e["state"] == "adopted" and not getattr(pov, "include_adopted", False):
                out.append(check("zia-adopted", f"Kept: {e['name']}", INFO, "built by hand and adopted",
                                 "Run teardown again and answer yes to delete adopted objects too."))
                continue
            k = KINDS[e["kind"]]
            try:
                t.delete(e, dict(live, name=obj_name(live)), k["res"], k["dele"], *self._args(e))
                if e["kind"] == "user":
                    secrets.delete(pov.id, TEST_PW.format(n=e["key"].rsplit(".", 1)[-1]))
                deleted += 1
                log("ok", f"Deleted {e['name']}")
            except GuardError as err:
                out.append(check("zia-left", f"Left in place: {e['name']}", WARN, str(err)))
        if deleted:
            t.activate()
            log("ok", "ZIA changes activated")
        out.append(check("zia-teardown", "ZIA POV objects removed", OK if not out else WARN, f"{deleted} deleted"))
        return out

    def terraform(self, entry, live):
        if entry["kind"] not in KINDS or not KINDS[entry["kind"]].get("tf"):
            return None
        rtype, confirmed = KINDS[entry["kind"]]["tf"]
        return {"type": rtype, "confirmed": confirmed, "id": entry["id"], "name": entry["name"]}

    def customer_names(self, snap):
        names = set(snap.get("customer_names") or [])
        if snap.get("pilot_group"):
            names.add(snap["pilot_group"]["name"])
        return names
