"""ZIdentity: the POV's own pilot group, when the kit makes one instead of using an existing one.

Two ways in (Pilot users step), both in the change list, so nothing is written before the customer approves it:
  - "Create one for the POV" (`identity.pilot create`): a group '<prefix> - pilot users' with the customer's own
    ZIdentity users added to it (only added, never changed); in labs, users who don't exist yet created too.
  - "Test users made by the kit" (`identity.pilot test`), in a tenant that keeps its users in ZIdentity: like the SE
    demo kit, the kit first makes its test users in ZIA (products/zia.py); when ZIA refuses because ZIdentity owns the
    users, they're made here instead, on ZIdentity's own domain (<vanity>.zslogin.net), where ZIdentity can give them
    a password even when the company domain signs in through an IdP such as Okta.
The group is stamped with the POV ID in its description; the users the kit creates are named '<prefix>: <login>'.

ZIdentity only sends users and groups to ZIA once they have the Internet & SaaS entitlement, which its API can't
grant: in tenants that entitle chosen users or groups (common with Okta), that's a customer action. Apply checks the
entitlement first and stops at once if it's missing (as the demo kit does), otherwise waits up to three minutes for
ZIA's copy of the group. ZIA's copy belongs to ZIdentity, so the ledger only links it ('linked': its ID fills the
rules, and the kit never changes or deletes it). Apply picks up where it left off on the next run.
Teardown deletes the users the POV created, takes the remaining members out of the group (ZIdentity refuses to
delete a group with members), then deletes the group, after every rule that used it is gone.
"""
from __future__ import annotations

import re
import time

from ..core import GuardError, KitError, naming
from ..core.changelist import item
from ..core.checks import FAIL, INFO, OK, WARN, check
from ..tenant import g, items
from .base import Product

ZIA_GROUP_KEY = "zid.zia_group"   # the ledger link to ZIA's copy of the group; rules reference {ref:zid.zia_group}
WAIT = (5, 10, 15, 30, 30, 30, 30, 30)   # seconds between looks for ZIA's copy of the group (3 minutes, as the
                                         # demo kit waits for its ZIdentity test user)
TEST_LOGIN = "{prefix}-pilot-{n}"        # kit-made test users: zpov-pilot-1@<domain>, as products/zia.py names them


def ident(cfg):
    return cfg.get("identity") or {}


def test_mode(cfg):
    """Test users made by the kit: chosen in the Pilot users step, or an older POV's identity.test_users count."""
    ic = ident(cfg)
    return ic.get("pilot") == "test" or (ic.get("pilot") != "create" and int(ic.get("test_users") or 0) > 0)


def test_count(cfg):
    return max(1, min(10, int(ident(cfg).get("test_users") or 1)))


def users_in_zidentity(cfg):
    """Set by hand, or learned when ZIA refused to create users because ZIdentity owns them (the demo kit's rule)."""
    return ident(cfg).get("users_in") == "zidentity"


def zid_domain(cfg):
    v = str(cfg.get("vanity_domain") or "").strip().lower()
    v = re.sub(r"\.zslogin\.net$", "", v)
    return f"{v}.zslogin.net" if v else None


def test_emails(cfg):
    dom = zid_domain(cfg)
    prefix = str(cfg.get("prefix") or naming.DEFAULT_PREFIX).lower()
    return [f"{TEST_LOGIN.format(prefix=prefix, n=n)}@{dom}" for n in range(1, test_count(cfg) + 1)] if dom else []


def enabled(cfg):
    if not {"zia", "zcc", "casb", "zpa"} & set(cfg.get("products") or []):
        return False
    return ident(cfg).get("pilot") == "create" or (test_mode(cfg) and users_in_zidentity(cfg))


def group_name(prefix):
    return naming.safe_name(naming.name(prefix, "pilot users"), prefix)


def user_name(prefix, email):
    return naming.name(prefix, email.split("@", 1)[0], limit=64)


def slug(email):
    return re.sub(r"[^a-z0-9]+", "-", email.lower()).strip("-")


def zid_login(u):
    return str(g(u, "login_name") or g(u, "primary_email") or "").lower()


class ZID(Product):
    name, title, phase = "zid", "ZIdentity pilot group", "v1"

    def role_scopes(self, pov=None):
        new = bool(pov and ((pov.cfg.get("identity") or {}).get("create_users") == "yes" or test_mode(pov.cfg)))
        return {"discovery": [("ZIdentity: users and groups", "view only")],
                "apply": [("ZIdentity: groups" + (" and users" if new else "") +
                           " (the POV's pilot group" + (" and new pilot users" if new else "") + " only)", "full")]}

    # ---------------------------------------------------------------- discover
    def discover(self, t, pov):
        ic = pov.cfg.get("identity") or {}
        testing = test_mode(pov.cfg)
        new_ok = testing or ic.get("create_users") == "yes"
        gname = group_name(pov.prefix)
        snap = {"group": gname, "members": [], "new": []}
        checks = []
        try:
            t.call("zid.users", "list_users", query_params={"limit": 1})
        except KitError as e:
            checks.append(check("zid-read", "ZIdentity readable", FAIL, str(e)[:160],
                                "Give the API client view access to ZIdentity users and groups, or name an existing "
                                "pilot group instead (Pilot users step)."))
            snap["readable"] = False
            return snap, checks
        snap["readable"] = True
        emails = (test_emails(pov.cfg) if testing else
                  [e.strip().lower() for e in pov.cfg.get("pilot_emails") or [] if e.strip()])
        if testing and not emails:
            checks.append(check("zid-members", "Test users' domain", FAIL, "no vanity domain",
                                "Connect first: the test users go on <vanity>.zslogin.net."))
        elif not emails:
            checks.append(check("zid-members", "Pilot users named", FAIL, "none yet",
                                "List the pilot users' emails in the Pilot users step."))
        missing = []
        from .zia import ledger_of
        led = ledger_of(pov)
        for e in emails:
            rows = items(t.call("zid.users", "list_users", query_params={"login_name": e}))
            hit = next((r for r in rows if zid_login(r) == e), None)
            made = led.find(f"zid.user.{slug(e)}")
            if hit and made and made["id"] == str(g(hit, "id")):
                missing.append(e)   # the POV made this user: still planned as new, so the approved list holds
            elif hit:
                snap["members"].append({"email": e, "id": str(g(hit, "id"))})
            else:
                missing.append(e)
        if missing and new_ok:
            snap["new"] = missing
            checks.append(check("zid-new", "New pilot users", INFO, ", ".join(missing),
                                "The POV creates them in ZIdentity; set their passwords there after apply "
                                "(Administration → Authentication → Directory → Users)."))
        elif missing:
            checks.append(check("zid-members", "Pilot users are in ZIdentity", FAIL, f"not found: {', '.join(missing)}",
                                "Use the users' sign-in names as ZIdentity shows them, or (lab tenants) tick 'Create "
                                "the ones that don't exist' in the Pilot users step."))
        elif emails:
            checks.append(check("zid-members", "Pilot users are in ZIdentity", OK, f"all {len(emails)}"))
        # a group by the POV's name that isn't in this POV's ledger: someone else's, or another POV's
        rows, off = [], 0
        while True:   # partial-match filter, paged: every group whose name contains the POV's
            page = items(t.call("zid.groups", "list_groups", query_params={"name[like]": gname, "limit": 1000,
                                                                           "offset": off}))
            rows += page
            if len(page) < 1000:
                break
            off += 1000
        clash = [r for r in rows if str(g(r, "name")) == gname]
        mine = led.find("zid.group")
        if clash and not (mine and any(str(g(r, "id")) == mine["id"] for r in clash)):
            checks.append(check("zid-name", "POV group name is free", FAIL, f"'{gname}' already exists in ZIdentity",
                                "Another POV or a person made it. Delete it in ZIdentity if it's left over, or give "
                                "this POV another prefix."))
        else:
            checks.append(check("zid-name", "POV group name is free", OK, gname))
        return snap, checks

    # ---------------------------------------------------------------- plan
    def plan(self, pov, snap):
        if not snap.get("readable"):
            return [], ["No ZIdentity items: ZIdentity wasn't readable in discovery."]
        P, pid, gname = pov.prefix, pov.id, snap["group"]
        who = len(snap["members"]) + len(snap["new"])
        out = [item("zid", "group", "zid.group", gname, affects=f"its {who} pilot user{'s' * (who != 1)} only",
                    why="The pilot group every POV rule is scoped to. ZIdentity sends it to ZIA once it's entitled.",
                    body={"name": gname, "description": naming.describe(pid, "POV pilot users"),
                          "service_entitlement_enabled": True, "admin_entitlement_enabled": False})]
        for e in snap["new"]:
            n = user_name(P, e)
            out.append(item("zid", "user", f"zid.user.{slug(e)}", n, affects="this new user only",
                            why=("A test user made by the kit, on ZIdentity's own domain so ZIdentity can give it a password."
                 if test_mode(pov.cfg) else "A lab pilot user who didn't exist in ZIdentity."),
                            body={"login_name": e, "primary_email": e, "display_name": n, "status": True}))
        if snap["members"] or snap["new"]:
            out.append(item("zid", "members", "zid.group.members", f"{gname}: members",
                            affects="adds users to the POV's group; their other groups are untouched",
                            why="Existing users are only added to the group, never changed.",
                            body={"group": "{ref:zid.group}",
                                  "users": [m["id"] for m in snap["members"]]
                                  + [f"{{ref:zid.user.{slug(e)}}}" for e in snap["new"]],
                                  "emails": [m["email"] for m in snap["members"]] + list(snap["new"])}))
        svc = []
        if {"zia", "zcc", "casb"} & set(pov.products):
            svc.append("Internet & SaaS")
        if "zpa" in pov.products:
            svc.append("Private Access")
        out.append(item("zid", "customer_action", "zid.ca.entitlement",
                        f"Give '{gname}' the {' and '.join(svc)} entitlement{'s' * (len(svc) > 1)}",
                        action="customer_action", console="zid.entitlements",
                        why="ZIdentity only sends users and groups to ZIA once they're entitled, and its API can't "
                            "grant entitlements. Needed where the tenant entitles chosen users or groups rather than "
                            "everyone (common with Okta); apply says so if it is."))
        if snap["new"]:
            out.append(item("zid", "customer_action", "zid.ca.passwords", "Set the new pilot users' passwords",
                            action="customer_action", console="zid.users",
                            why="In ZIdentity (Administration → Authentication → Directory → Users), set each new "
                                "user's password. ZIdentity's API can't, and the kit never handles these passwords."))
        return out, [f"Pilot group: the POV creates '{gname}' in ZIdentity."]

    # ---------------------------------------------------------------- apply
    def apply(self, t, pov, items_, log):
        mine = {i["key"]: i for i in items_ if i["product"] == "zid" and i["action"] == "create"}
        if "zid.group" not in mine:
            return
        gi = mine["zid.group"]
        gid = t.create("zid.group", "zid.groups", "add_group", **gi["body"])
        log("ok", f"Created {gi['name']} in ZIdentity")
        for key, it in mine.items():
            if it["kind"] == "user":
                t.create(key, "zid.users", "add_user", stamped=False, **it["body"])
                log("ok", f"Created {it['name']} in ZIdentity")
        m = mine.get("zid.group.members")
        if m:
            want = [str(t.ids.get(u[5:-1], u)) if str(u).startswith("{ref:") else str(u) for u in m["body"]["users"]]
            have = {str(g(u, "id")) for u in items(t.call("zid.groups", "list_group_users_details", gid))}
            add = [u for u in want if u not in have]
            if add:
                entry = t.ledger.find("zid.group")
                t.update(entry, self.live_object(t, entry), "zid.groups", "add_users_to_group", gid, id=add)
                log("ok", f"Added {len(add)} pilot user{'s' * (len(add) != 1)} to {gi['name']}")
        if not ({"zia", "zcc", "casb"} & set(pov.products)) or t.ids.get(ZIA_GROUP_KEY):
            return
        entitle = (f"In ZIdentity, give the group '{gi['name']}' the Internet & SaaS entitlement (Zscaler Help: "
                   "'Assigning Entitlements to Users and User Groups'; it's the change list's customer action), then "
                   "click Apply again: it carries on from here and nothing is created twice.")
        for wait in (0,) + WAIT:   # ZIdentity sends the group to ZIA once it's entitled (usually within a minute)
            time.sleep(wait)
            rows = items(t.call("user_management", "list_groups", query_params={"search": gi["name"]}))
            hit = next((r for r in rows if str(g(r, "name")) == gi["name"]), None)
            if hit:
                t.link(ZIA_GROUP_KEY, "zia", "user_group", g(hit, "id"), gi["name"])
                log("ok", f"ZIA sees {gi['name']}")
                return
            if not wait and not self._entitled(t, m):   # an unentitled group never reaches ZIA: say so now
                raise KitError(f"The pilot group and its users are ready in ZIdentity, but they don't have the "
                               f"Internet & SaaS entitlement, so ZIdentity won't send them to ZIA. {entitle}")
            log("info", f"Waiting for ZIdentity to send {gi['name']} to ZIA (usually under a minute)…")
        raise KitError(f"The pilot group is ready in ZIdentity, but ZIA doesn't have it after three minutes. Check "
                       f"it has the Internet & SaaS entitlement. {entitle}")

    def _entitled(self, t, members_item):
        """True when any member has the Internet & SaaS entitlement, or it can't be told (then apply waits)."""
        from ..identity import ZIA_SERVICE, zid_services
        ids = [str(t.ids.get(u[5:-1], u)) if str(u).startswith("{ref:") else str(u)
               for u in ((members_item or {}).get("body") or {}).get("users", [])][:3]
        if not ids:
            return True
        seen = [zid_services(t, i) for i in ids]
        return any(n is None or any(ZIA_SERVICE.search(x) for x in n) for n in seen)

    # ---------------------------------------------------------------- live objects, drift, teardown
    def live_object(self, t, entry):
        res, get = ("zid.groups", "get_group") if entry["kind"] == "group" else ("zid.users", "get_user")
        try:
            o = t.call(res, get, entry["id"])
        except Exception as e:
            if re.search(r"\b404\b|not found|does not exist", str(e), re.I):
                return None
            raise
        if not (isinstance(o, dict) and o):
            return None
        return dict(o, id=str(g(o, "id")), name=g(o, "name") or g(o, "display_name") or "",
                    description=g(o, "description") or "")

    def drift(self, t, pov, ledger, items_):
        out = []
        e = ledger.find("zid.group")
        if not e:
            return [check("zid-present", "Pilot group in ZIdentity", WARN, "not created yet", "Run apply.")]
        live = self.live_object(t, e)
        if live is None:
            return [check("zid-present", "Pilot group in ZIdentity", FAIL, "deleted in the console",
                          "Run `pov-kit status --fix` to recreate it, then grant its entitlements again.", fixable=True)]
        m = next((i for i in items_ if i["key"] == "zid.group.members"), None)
        if m:
            have = {str(g(u, "id")) for u in items(t.call("zid.groups", "list_group_users_details", e["id"]))}
            ids = {x["key"]: x["id"] for x in ledger.active()}
            want = {ids.get(u[5:-1], u) if str(u).startswith("{ref:") else str(u) for u in m["body"]["users"]}
            gone = sorted(want - have)
            out.append(check("zid-members", "Pilot users in the POV's group", WARN if gone else OK,
                             f"{len(gone)} removed in the console" if gone else f"all {len(want)}",
                             "Run `pov-kit status --fix` to add them back." if gone else "", fixable=bool(gone)))
        linked = ledger.linked(ZIA_GROUP_KEY)
        if {"zia", "zcc", "casb"} & set(pov.products):
            out.append(check("zid-zia", "ZIA has the pilot group", OK if linked else WARN,
                             linked["name"] if linked else "not yet",
                             "" if linked else "Give the group the Internet & SaaS entitlement in ZIdentity, then click "
                             "Apply again."))
        return out

    def fix_drift(self, t, pov, ledger, items_, log):
        e = ledger.find("zid.group")
        if e and self.live_object(t, e) is None:
            ledger.mark(e, "deleted")
            link = ledger.linked(ZIA_GROUP_KEY)
            if link:
                ledger.mark(link, "deleted")
            log("info", "The pilot group was deleted in ZIdentity; apply recreates it")
        return False   # apply (run by status --fix) re-adds members and recreates what's missing

    def in_use(self, t, ledger):
        """Why the pilot group can't go yet: other POV objects still in the ledger, or any ZIA rule (a POV rule
        renamed and so kept, or one of the customer's) that still applies to ZIA's copy of it. Deleting the group
        then would leave such a rule pointing at a group that no longer exists."""
        # ZIA rules are checked live below (a renamed one stays in the ledger but is the customer's now); other
        # products' objects that teardown couldn't remove may still use the group, so they keep it too
        others = [e["name"] for e in ledger.active() if e["product"] not in ("zid", "zia")]
        if others:
            return f"{len(others)} other POV object{'s' * (len(others) != 1)} still in the tenant"
        link = ledger.linked(ZIA_GROUP_KEY)
        if link:
            from .zia import rules_using_group
            try:
                users = rules_using_group(t, link["id"])
            except KitError as e:
                return f"couldn't check which ZIA rules use it ({str(e)[:100]})"
            if users:
                return f"ZIA rules still apply to it: {', '.join(users[:5])}{'…' if len(users) > 5 else ''}"
        return ""

    def teardown(self, t, pov, ledger, log):
        out, deleted = [], 0
        why = self.in_use(t, ledger)
        if why and ledger.find("zid.group"):
            return [check("zid-left", "Kept: the POV's ZIdentity pilot group", WARN, why,
                          "Remove those first (or point the rules at another group), then run teardown again.")]
        for e in ledger.newest_first("zid"):   # users, then the group
            live = self.live_object(t, e)
            if live is None:
                ledger.mark(e, "deleted")
                continue
            res, dele = ("zid.groups", "delete_group") if e["kind"] == "group" else ("zid.users", "delete_user")
            try:
                if e["kind"] == "group":   # ZIdentity refuses to delete a group with members: take them out first
                    left = [str(g(u, "id")) for u in items(t.call("zid.groups", "list_group_users_details", e["id"]))]
                    for uid in left:
                        t.update(e, live, "zid.groups", "remove_user_from_group", e["id"], uid)
                    if left:
                        log("ok", f"Took {len(left)} member{'s' * (len(left) != 1)} out of {e['name']} "
                                  "(the users themselves are unchanged)")
                t.delete(e, live, res, dele, e["id"])
                deleted += 1
                log("ok", f"Deleted {e['name']} from ZIdentity")
            except (GuardError, KitError) as err:
                out.append(check("zid-left", f"Left in place: {e['name']}", WARN, str(err)[:300]))
        link = ledger.linked(ZIA_GROUP_KEY)
        if link and not ledger.find("zid.group"):
            ledger.mark(link, "deleted")   # ZIdentity removes ZIA's copy itself
        out.append(check("zid-teardown", "ZIdentity pilot group removed", OK if not out else WARN, f"{deleted} deleted"))
        return out

    def customer_names(self, snap):
        return {m["email"] for m in snap.get("members") or []} | set(snap.get("new") or [])
