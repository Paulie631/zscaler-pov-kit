"""ZIdentity: the POV's own pilot group, when the customer would rather the kit make one than name an existing one.

Opt-in (`identity.pilot create`, or "Create one for the POV" in the Pilot users step). In the change list, like
everything else, so nothing is written before the customer approves it:
  - a ZIdentity group '<prefix> - pilot users' (stamped with the POV ID in its description)
  - the pilot users put in it: existing ZIdentity users are only added (never changed); users who don't exist yet
    are created only when `identity.create_users yes` (lab tenants), named '<prefix>: <login>'
  - the customer actions ZIdentity's API can't do: granting the group its service entitlements (Internet & SaaS,
    Private Access) where the tenant entitles chosen groups, setting new users' passwords, and one pilot user signing
    in once (ZIA learns ZIdentity users and their groups at sign-in, not before: seen in a live tenant, 2026-10)

ZIA then has the group (after that first sign-in), and the POV rules use it. ZIA's copy of the group belongs to ZIdentity,
so the ledger only links it ('linked': its ID fills the rules, and the kit never changes or deletes it). Apply waits
for it briefly; until a member has signed in, apply stops after this step and picks up where it left off next time.
Teardown deletes the users the POV created and the group (ZIdentity then removes them from ZIA), after every rule
that used the group is gone.
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
WAIT = (5, 10)                    # seconds between looks for ZIA's copy of the group during apply (it comes with a
                                  # member's first sign-in, so a long wait rarely helps)


def enabled(cfg):
    return ((cfg.get("identity") or {}).get("pilot") == "create"
            and bool({"zia", "zcc", "casb", "zpa"} & set(cfg.get("products") or [])))


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
        new = bool(pov and ((pov.cfg.get("identity") or {}).get("create_users") == "yes"))
        return {"discovery": [("ZIdentity: users and groups", "view only")],
                "apply": [("ZIdentity: groups" + (" and users" if new else "") +
                           " (the POV's pilot group" + (" and new pilot users" if new else "") + " only)", "full")]}

    # ---------------------------------------------------------------- discover
    def discover(self, t, pov):
        ic = pov.cfg.get("identity") or {}
        new_ok = ic.get("create_users") == "yes"
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
        emails = [e.strip().lower() for e in pov.cfg.get("pilot_emails") or [] if e.strip()]
        if not emails:
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
                                "The POV creates them in ZIdentity; set their passwords there after apply."))
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
                    why="The pilot group every POV rule is scoped to. ZIA gets it when a member first signs in.",
                    body={"name": gname, "description": naming.describe(pid, "POV pilot users"),
                          "service_entitlement_enabled": True, "admin_entitlement_enabled": False})]
        for e in snap["new"]:
            n = user_name(P, e)
            out.append(item("zid", "user", f"zid.user.{slug(e)}", n, affects="this new user only",
                            why="A lab pilot user who didn't exist in ZIdentity.",
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
                        why="ZIdentity's API can't grant entitlements. Needed where the tenant entitles chosen users "
                            "or groups rather than everyone."))
        if {"zia", "zcc", "casb"} & set(pov.products):
            out.append(item("zid", "customer_action", "zid.ca.signin", "One pilot user signs in once",
                            action="customer_action", console="zcc.enrolled_devices",
                            why="ZIA learns ZIdentity users and their groups when they sign in. Until one member of "
                                f"'{gname}' signs in (Client Connector, or the ZIA sign-in page), ZIA doesn't have the "
                                "group, so apply stops after creating it and carries on once it's there."))
        if snap["new"]:
            out.append(item("zid", "customer_action", "zid.ca.passwords", "Set the new pilot users' passwords",
                            action="customer_action", console="zid.users",
                            why="In ZIdentity → Users, reset each new user's password, or send them the activation "
                                "email. The kit never handles their passwords."))
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
        for wait in (0,) + WAIT:   # ZIA has the group once a member has signed in
            time.sleep(wait)
            rows = items(t.call("user_management", "list_groups", query_params={"search": gi["name"]}))
            hit = next((r for r in rows if str(g(r, "name")) == gi["name"]), None)
            if hit:
                t.link(ZIA_GROUP_KEY, "zia", "user_group", g(hit, "id"), gi["name"])
                log("ok", f"ZIA sees {gi['name']}")
                return
            log("info", f"Looking for {gi['name']} in ZIA…")
        raise KitError(f"The pilot group is ready in ZIdentity, but ZIA doesn't have it yet. In ZIdentity, give "
                       f"'{gi['name']}' its Internet & SaaS entitlement if your tenant needs it, then have one pilot "
                       "user sign in once (Client Connector, or the ZIA sign-in page): ZIA learns ZIdentity groups at "
                       "sign-in. Then click Apply again: it carries on from here and nothing is created twice.")

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
                             "" if linked else "Have one pilot user sign in once (and grant the group's entitlement if "
                             "your tenant needs it), then click Apply again."))
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
                t.delete(e, live, res, dele, e["id"])
                deleted += 1
                log("ok", f"Deleted {e['name']} from ZIdentity")
            except GuardError as err:
                out.append(check("zid-left", f"Left in place: {e['name']}", WARN, str(err)))
        link = ledger.linked(ZIA_GROUP_KEY)
        if link and not ledger.find("zid.group"):
            ledger.mark(link, "deleted")   # ZIdentity removes ZIA's copy itself
        out.append(check("zid-teardown", "ZIdentity pilot group removed", OK if not out else WARN, f"{deleted} deleted"))
        return out

    def customer_names(self, snap):
        return {m["email"] for m in snap.get("members") or []} | set(snap.get("new") or [])
