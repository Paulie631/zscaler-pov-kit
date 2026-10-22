"""The identity step: one picture of who the pilot users are and how they sign in, across every product.

Runs after the products' own discovery (read-only, like them) and checks what no single product can:
  - how users sign in: ZIA's mode (Hosted DB, SAML from an outside IdP, directory sync), ZIdentity, ZPA's IdPs
  - each pilot user (`pilot_emails`) exists in ZIA and is in the pilot group
  - ZIdentity entitlements: Internet & SaaS for ZIA, Private Access for ZPA. ZIdentity's API reads them but can't
    grant them (a demo-kit lesson), so a missing one is a customer action with the fix spelled out
  - the sign-in sites of the customer's IdP and MFA, which ZIA's module keeps out of SSL inspection so the POV's
    inspect rule can't break sign-in
Ported from the demo kit's zid_find / zid_services. Read-only: it never changes users, groups or entitlements.
"""
from __future__ import annotations

import re

from .core import KitError
from .core.checks import FAIL, INFO, OK, WARN, check
from .tenant import g, items

ZIA_SERVICE = re.compile(r"\bZIA\b|internet\s*(&|and)\s*saas|internet access", re.I)
ZPA_SERVICE = re.compile(r"\bZPA\b|private\s*access|private\s*app", re.I)
# Sign-in and MFA sites to keep out of SSL inspection, by IdP. Suggested, editable (`set identity.bypass_domains`);
# Microsoft 365 also has ZIA's own one-click configuration, which the customer may already use.
IDP_DOMAINS = {
    "okta": [".okta.com", ".oktacdn.com", ".okta-emea.com", ".oktapreview.com"],
    "entra": ["login.microsoftonline.com", "login.microsoft.com", "login.live.com", ".msauth.net", ".msftauth.net",
              "aadcdn.msftauthimages.net", "device.login.microsoftonline.com"],
    "ping": [".pingidentity.com", ".pingone.com", ".pingone.eu"],
    "duo": [".duosecurity.com", ".duo.com"],
    "google": ["accounts.google.com", ".gstatic.com"],
    "onelogin": [".onelogin.com"],
    "zidentity": [".zslogin.net"],
}
IDP_HINT = {"okta": r"okta", "entra": r"entra|azure|microsoft|aad|\bms\b", "ping": r"ping", "duo": r"duo",
            "google": r"google|workspace", "onelogin": r"onelogin"}


def icfg(pov):
    return pov.cfg.get("identity") or {}


def which_idps(names, zidentity):
    found = [k for k, pat in IDP_HINT.items() if any(re.search(pat, str(n or ""), re.I) for n in names)]
    if zidentity:
        found.append("zidentity")
    return found


def zid_services(t, user_id):
    """Service names a ZIdentity user is entitled to, or None if unreadable (from the demo kit)."""
    try:
        body = t.call("zid.user_entitlement", "get_service_entitlement", user_id)
    except Exception:
        return None
    names = []

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k in ("serviceName", "service_name", "name", "displayName", "display_name") and isinstance(v, str):
                    names.append(v)
                else:
                    walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(body)
    return names


def discover(t, pov, snaps):
    """-> (identity snapshot, checks). `t` is the read-only client."""
    c, checks = icfg(pov), []
    zia, zpa = snaps.get("zia") or {}, snaps.get("zpa") or {}
    mode = (zia.get("auth") or {}).get("mode")
    zid = bool(zia.get("zidentity"))
    emails = [e.strip().lower() for e in pov.cfg.get("pilot_emails") or [] if e.strip()]
    idp_names = [i.get("name") for i in zpa.get("idps") or []] + [c.get("idp")]
    idps = sorted(set(which_idps(idp_names, zid)))
    snap = {"mode": mode, "zidentity": zid, "idps": idps, "emails": emails, "users": []}

    how = {"hosted": "ZIA's own user list (Hosted DB)", "saml": "SAML from an outside IdP",
           "directory": "a synced directory (AD/LDAP)", None: "unknown"}[mode]
    parts = [f"ZIA: {how}"] + (["ZIdentity in front"] if zid else [])
    if zpa.get("pilot_group"):
        parts.append(f"ZPA: SCIM group from {zpa['pilot_group'].get('idp')}")
    elif zpa.get("pilot_saml"):
        parts.append(f"ZPA: SAML attribute {zpa['pilot_saml']['name']}")
    checks.append(check("id-signin", "How pilot users sign in", INFO, "; ".join(parts)))
    if (zia.get("test_users") or {}).get("count"):
        checks.append(check("id-testusers", "Pilot users", INFO,
                            f"{zia['test_users']['count']} test users the POV creates in ZIA's Hosted DB",
                            "They exist only in ZIA, so ZPA (SCIM or SAML from the IdP) can't use them."))

    if not emails:
        checks.append(check("id-emails", "Pilot users named", WARN, "no pilot_emails yet",
                            "`pov-kit set pilot_emails a@acme.com,b@acme.com`, so the kit can check each user is in "
                            "the pilot group and entitled."))
        return snap, checks

    grp = (zia.get("pilot_group") or {})
    missing, outside, unentitled = [], [], []
    for e in emails:
        u = {"email": e}
        if "zia" in pov.products:
            rows = items(t.call("user_management", "list_users", query_params={"search": e}))
            hit = next((r for r in rows if str(g(r, "email") or "").lower() == e), None)
            u["zia"] = bool(hit)
            if not hit:
                missing.append(e)
            elif grp.get("id") and not str(grp["id"]).startswith("{ref:"):
                gids = {str(g(x, "id")) for x in (g(hit, "groups") or [])}
                if str(grp["id"]) not in gids:
                    outside.append(e)
        if zid:
            try:
                rows = items(t.call("zid.users", "list_users", query_params={"login_name": e}))
            except KitError:
                rows = []
            zu = next((r for r in rows if str(g(r, "login_name") or "").lower() == e), None)
            names = zid_services(t, g(zu, "id")) if zu else None
            need = []
            if zu is None:
                made = c.get("pilot") == "create" and c.get("create_users") == "yes"
                need.append("new: the POV creates them" if made else "not in ZIdentity")
            elif names is not None:
                if {"zia", "zcc", "casb"} & set(pov.products) and not any(ZIA_SERVICE.search(n) for n in names):
                    need.append("Internet & SaaS")
                if "zpa" in pov.products and not any(ZPA_SERVICE.search(n) for n in names):
                    need.append("Private Access")
            u["entitlements"] = names
            if need:
                unentitled.append(f"{e} ({', '.join(need)})")
        snap["users"].append(u)

    made_here = str(grp.get("id") or "").startswith("{ref:")   # the POV makes the group (and maybe the users)
    if "zia" in pov.products and made_here and c.get("pilot") == "create":
        checks.append(check("id-zia-users", "Pilot users are in ZIA", INFO if missing else OK,
                            f"not yet: {', '.join(missing)}" if missing else f"all {len(emails)}",
                            "ZIdentity provisions them to ZIA with the POV's group, once it's entitled."
                            if missing else ""))
    elif "zia" in pov.products:
        checks.append(check("id-zia-users", "Pilot users are in ZIA", WARN if missing else OK,
                            f"missing: {', '.join(missing)}" if missing else f"all {len(emails)}",
                            "With SAML or SCIM, users appear in ZIA after provisioning or their first sign-in. "
                            "Have each one sign in to Client Connector once." if missing else ""))
        if grp.get("name") and not made_here:
            checks.append(check("id-zia-group", f"Pilot users are in '{grp['name']}'", WARN if outside else OK,
                                f"not in the group: {', '.join(outside)}" if outside else "all found ones are",
                                "Add them to the group in the customer's directory; the POV rules only apply to "
                                "members." if outside else ""))
    from .products.zid import enabled as zid_pilot
    if zid and zid_pilot(pov.cfg):   # the group is the POV's own: its entitlement is a customer action after apply
        checks.append(check("id-entitlements", "ZIdentity entitlements", INFO if unentitled else OK,
                            "; ".join(unentitled) if unentitled else "every pilot user is entitled",
                            "After apply creates the POV's pilot group, give it its entitlements in ZIdentity (a "
                            "customer action in the change list)." if unentitled else "",
                            console="zid.entitlements"))
    elif zid:
        checks.append(check("id-entitlements", "ZIdentity entitlements", FAIL if unentitled else OK,
                            "; ".join(unentitled) if unentitled else "every pilot user is entitled",
                            "ZIdentity's API can read entitlements but not grant them. In ZIdentity, assign the "
                            "missing service entitlement to the pilot group (or the users), then rerun preflight."
                            if unentitled else "", console="zid.entitlements"))

    doms = c.get("bypass_domains") or None   # an empty list (a blank form field) means "use the IdP's own sites"
    if doms is None:
        doms = sorted({d for i in idps for d in IDP_DOMAINS.get(i, [])})
    snap["bypass_domains"] = doms
    if "zia" in pov.products:
        checks.append(check("id-bypass", "Sign-in sites kept out of SSL inspection", INFO if doms else WARN,
                            ", ".join(doms) if doms else "no IdP recognised",
                            "Choose the identity provider in the Pilot users step (or `pov-kit set identity.idp okta`), "
                            "or list its sign-in domains, so inspecting the pilot group can't break sign-in or MFA."
                            if not doms else ""))
    return snap, checks
