"""Client Connector: a Windows app profile for the pilot group, with its own Z-Tunnel 2.0 forwarding profile.

Both are copies of the tenant's default Windows profiles, never edits of them. Some tenants' Client Connector API
refuses new forwarding profiles with a bare 400 (a demo-kit lesson), so both items are create-or-adopt: on a 400
the kit prints the exact spec, a person builds it in the console, and `status --fix` adopts it by exact name.
Client Connector profiles carry no description, so ownership rests on the ledger ID and the prefix.
"""
from __future__ import annotations

import re

from ..core import GuardError, KitError, naming
from ..core.changelist import item
from ..core.checks import FAIL, INFO, OK, WARN, check
from ..tenant import g, items
from .base import Product

ZCC_TUNNEL = 1   # forwardingProfileActions.actionType for "Tunnel" (from the demo kit)
FWD_DROP = {"id", "groups", "users", "deviceGroups", "groupNames", "userNames", "deviceGroupNames", "policyToken",
            "trustedNetworkIds", "trustedNetworks", "trustedSubnets", "trustedGateways", "trustedDhcpServers",
            "trustedDNSServers", "trustedEgressIps", "trustedDnsSearchDomains", "hostnameIpMapping"}
BY_HAND = ("Build it by hand in the Client Connector portal, then run `pov-kit status --fix`, which finds it by exact "
           "name and adopts it: 1) Forwarding profile named exactly '{fwd}': a copy of '{src_fwd}' with ZIA action "
           "Tunnel and Z-Tunnel 2.0 on every network type. 2) Windows app profile named exactly '{app}': a copy of "
           "'{src_app}' for group '{group}' only, Install Zscaler SSL Certificate on, forwarding profile '{fwd}', and "
           "no broader profile above it in the order.")


def names(prefix):
    return (naming.safe_name(naming.name(prefix, "Z-Tunnel 2.0"), prefix),
            naming.safe_name(naming.name(prefix, "pilot devices"), prefix))


def bare_400(e):
    return bool(re.search(r"\b400\b|bad request", str(e), re.I))


class ZCC(Product):
    name, title, phase = "zcc", "Client Connector", "v1"

    def role_scopes(self):
        return {"discovery": [("Client Connector portal", "view only")],
                "apply": [("Client Connector: app profiles and forwarding profiles", "full")]}

    def _list(self, t, resource, **q):
        return items(t.call(resource, "list_by_company", query_params=q or None))

    def discover(self, t, pov):
        snap, checks = {}, []
        try:
            fwds = self._list(t, "zcc.forwarding_profile")
            apps = self._list(t, "zcc.web_policy", device_type="windows")
        except Exception as e:
            return {"readable": False}, [check("zcc-read", "Client Connector readable", FAIL, str(e)[:160],
                                               "Give the discovery client view access to the Client Connector portal.")]
        default_app = next((a for a in apps if re.search(r"default", str(g(a, "name")), re.I)), None) or \
            (sorted(apps, key=lambda a: int(g(a, "ruleOrder") or 0))[-1] if apps else None)
        src_fwd = next((f for f in fwds if str(g(f, "id")) == str(g(default_app or {}, "forwardingProfileId"))), None)
        snap.update(readable=True, fwd_count=len(fwds), app_count=len(apps),
                    source_app={"id": g(default_app, "id"), "name": g(default_app, "name")} if default_app else None,
                    source_fwd={"id": g(src_fwd, "id"), "name": g(src_fwd, "name")} if src_fwd else None,
                    customer_names=[str(g(x, "name")) for x in fwds + apps
                                    if not naming.has_prefix(g(x, "name"), pov.prefix)])
        checks.append(check("zcc-source", "Default Windows profiles found to copy", OK if src_fwd else WARN,
                            f"{snap['source_app']['name']} / {snap['source_fwd']['name']}" if src_fwd else
                            "no default Windows app profile with a forwarding profile",
                            "" if src_fwd else "The POV profiles will be built by hand (the change list prints the "
                            "spec).", console="zcc.app_profiles"))
        fwd_name, app_name = names(pov.prefix)
        from ..core.ledger import Ledger
        led = Ledger(pov.path("ledger.json"), pov.id, pov.prefix)
        ours = {e["id"] for e in led.active("zcc")}
        clash = [n for n in (fwd_name, app_name)
                 if any(g(x, "name") == n and str(g(x, "id")) not in ours for x in fwds + apps)]
        if clash:
            checks.append(check("zcc-names", "POV profile names", INFO, ", ".join(clash) + " already exist",
                                "If someone built them for this POV, `status --fix` adopts them after apply."))
        return snap, checks

    def plan(self, pov, snap, zia_snap=None):
        if not snap.get("readable"):
            return [], ["No Client Connector items: the portal wasn't readable in discovery."]
        grp = (zia_snap or {}).get("pilot_group") or {}
        fwd_name, app_name = names(pov.prefix)
        src_app, src_fwd = snap.get("source_app") or {}, snap.get("source_fwd") or {}
        spec = BY_HAND.format(fwd=fwd_name, app=app_name, src_fwd=src_fwd.get("name", "the default forwarding profile"),
                              src_app=src_app.get("name", "the default Windows app profile"),
                              group=grp.get("name", "the pilot group"))
        affects = f"devices of members of '{grp.get('name', '?')}' only"
        return [
            item("zcc", "forwarding_profile", "zcc.fwd", fwd_name, action="create_or_adopt", affects=affects,
                 criteria=["IS-ZCC-02"], spec=spec, body={
                     "name": fwd_name, "copy_of": src_fwd.get("id"), "zia_action": "Tunnel, Z-Tunnel 2.0, every network type"}),
            item("zcc", "app_profile", "zcc.app", app_name, action="create_or_adopt", affects=affects,
                 criteria=["IS-ZCC-01", "IS-ZCC-02"], spec=spec, body={
                     "name": app_name, "copy_of": src_app.get("id"), "groups": [grp.get("id")],
                     "install_ssl_certs": True, "forwarding_profile": "{ref:zcc.fwd}"}),
            item("zcc", "customer_action", "zcc.ca.devices",
                 f"Pilot devices have Client Connector installed and signed in as members of '{grp.get('name', '?')}'",
                 action="customer_action", criteria=["IS-ZCC-01"], console="zcc.enrolled_devices",
                 why="Installing software on the customer's devices is the customer's job."),
        ], ["Client Connector profiles are copies of the tenant's defaults; the defaults themselves aren't changed."]

    # ---- apply: copy the source forwarding profile, switch it to Z-Tunnel 2.0, save under the POV name
    def apply(self, t, pov, items_, log):
        by = {i["key"]: i for i in items_ if i["product"] == "zcc"}
        fwd_it = by.get("zcc.fwd")
        if not fwd_it:
            return
        fwds = self._list(t, "zcc.forwarding_profile")
        src = next((f for f in fwds if str(g(f, "id")) == str(fwd_it["body"]["copy_of"])), None)
        if not src:
            raise KitError("The forwarding profile the change list copies is gone. Run `pov-kit plan` again.")
        body = {k: v for k, v in src.items() if k not in FWD_DROP}
        body["name"] = fwd_it["name"]
        for a in body.get("forwardingProfileActions") or []:
            a.update(actionType=ZCC_TUNNEL, enablePacketTunnel=1)

        def find_id(_):
            return next((g(f, "id") for f in self._list(t, "zcc.forwarding_profile") if g(f, "name") == fwd_it["name"]), None)
        try:
            t.create("zcc.fwd", "zcc.forwarding_profile", "update_forwarding_profile", extract_id=find_id,
                     stamped=False, **body)
            log("ok", f"Created {fwd_it['name']}")
        except GuardError:
            raise
        except KitError as e:
            if not bare_400(e):
                raise
            log("warn", "Client Connector refused the new forwarding profile (bare 400). " + fwd_it["spec"])
            return
        # The app profile write (web_policy_edit) is ported from the demo kit's setup_zcc in v0.2; until then
        # it is built by hand from the spec and adopted.
        log("warn", "The Windows app profile isn't automated yet (step 1 below is done). " + by["zcc.app"]["spec"])

    def adopt_by_name(self, t, pov, items_, log):
        """status --fix: adopt hand-built profiles that match the change list's exact names."""
        lists = {"forwarding_profile": self._list(t, "zcc.forwarding_profile"),
                 "app_profile": self._list(t, "zcc.web_policy", device_type="windows")}
        for it in items_:
            if it["product"] != "zcc" or it["action"] != "create_or_adopt" or t.ledger.find(it["key"]):
                continue
            hit = next((x for x in lists[it["kind"]] if g(x, "name") == it["name"]), None)
            if hit:
                t.adopt(it["key"], {"id": g(hit, "id"), "name": g(hit, "name")})
                log("ok", f"Adopted {it['name']} (built by hand)")

    def live_object(self, t, entry):
        res = "zcc.forwarding_profile" if entry["kind"] == "forwarding_profile" else "zcc.web_policy"
        q = {} if entry["kind"] == "forwarding_profile" else {"device_type": "windows"}
        return next((x for x in self._list(t, res, **q) if str(g(x, "id")) == entry["id"]), None)

    def drift(self, t, pov, ledger, items_):
        want = [i for i in items_ if i["product"] == "zcc" and i["action"] == "create_or_adopt"]
        missing = [i["name"] for i in want if not ledger.find(i["key"])]
        gone = [e["name"] for e in ledger.active("zcc") if self.live_object(t, e) is None]
        return [check("zcc-present", "POV Client Connector profiles", WARN if (missing or gone) else OK,
                      "; ".join(filter(None, [f"not created or adopted: {', '.join(missing)}" if missing else "",
                                              f"deleted in the portal: {', '.join(gone)}" if gone else ""]))
                      or f"all {len(want)}", "Build them from the change list's spec, then `pov-kit status --fix`."
                      if (missing or gone) else "", fixable=bool(missing))]

    def teardown(self, t, pov, ledger, log):
        out = []
        for e in ledger.newest_first("zcc"):   # the app profile before the forwarding profile it uses
            live = self.live_object(t, e)
            if live is None:
                ledger.mark(e, "deleted")
                continue
            if e["state"] == "adopted" and not getattr(pov, "include_adopted", False):
                out.append(check("zcc-adopted", f"Kept: {e['name']}", INFO, "built by hand and adopted",
                                 "Run teardown again and answer yes to delete adopted objects too."))
                continue
            res, meth = (("zcc.forwarding_profile", "delete_forwarding_profile") if e["kind"] == "forwarding_profile"
                         else ("zcc.web_policy", "delete_web_policy"))
            try:
                t.delete(e, {"id": g(live, "id"), "name": g(live, "name")}, res, meth, e["id"])
                log("ok", f"Deleted {e['name']}")
            except GuardError as err:
                out.append(check("zcc-left", f"Left in place: {e['name']}", WARN, str(err)))
        return out

    def customer_names(self, snap):
        return set(snap.get("customer_names") or [])
