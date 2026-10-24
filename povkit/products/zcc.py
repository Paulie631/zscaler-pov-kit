"""Client Connector: Windows and macOS app profiles for the pilot group, with their own Z-Tunnel 2.0 forwarding profile.

Both are copies of the tenant's default Windows profiles, never edits of them. Ported from the AI Guard SE Demo Kit's
setup_zcc: the forwarding profile copies the ZIA settings of a Z-Tunnel 2.0 profile the customer already has, if
any, and otherwise switches a copy of the default's to Tunnel + Z-Tunnel 2.0; when Client Connector answers a bare
400, it tries plainer copies (no trusted-network conditions, no Unified Tunnel settings...) down to a minimal one.
The Windows app profile copies the default, scoped to the pilot group, installs the Zscaler certificate, uses that
forwarding profile, and goes first in the order; both are read back to show what Client Connector stored.

Some tenants refuse even the minimal profile (a demo-kit lesson), so both items stay create-or-adopt: the kit prints
the exact spec, a person builds it in the console, and `status --fix` adopts it by exact name. Client Connector
profiles carry no description, so ownership rests on the ledger ID and the prefix.
"""
from __future__ import annotations

import re

from ..core import GuardError, KitError, naming
from ..core.changelist import item
from ..core.checks import FAIL, INFO, OK, WARN, check
from ..tenant import g, items
from .base import Product

ZCC_TUNNEL = 1   # forwardingProfileActions.actionType for "Tunnel"; Z-Tunnel 2.0 adds enablePacketTunnel = 1
DROP = {"id", "groups", "users", "deviceGroups", "groupNames", "userNames", "deviceGroupNames", "policyToken",
        "createdBy", "editedBy", "lastModification", "lastModifiedBy", "lastModifiedTime"}
TRUSTED = {"trustedNetworkIds", "trustedNetworks", "trustedSubnets", "trustedGateways", "trustedDhcpServers",
           "trustedEgressIps", "dnsServers", "dnsSearchDomains", "hostname", "resolvedIpsForHostname",
           "conditionType", "predefinedTrustedNetworks", "predefinedTnAll", "skipTrustedCriteriaMatch",
           "trustedDNSServers", "trustedDnsSearchDomains", "hostnameIpMapping"}
CORE_ACTION = ("networkType", "actionType", "enablePacketTunnel", "primaryTransport", "allowTLSFallback",
               "tunnel2FallbackType", "DTLSTimeout", "UDPTimeout", "TLSTimeout", "mtuForZadapter", "systemProxy",
               "systemProxyData")
FWD_DROP = DROP | TRUSTED


def is_z2(a):
    return int(a.get("actionType") or 0) == ZCC_TUNNEL and int(a.get("enablePacketTunnel") or 0) == 1


def z2_actions(fwds, fwd_name, base_actions):
    """Copy a Z-Tunnel 2.0 profile the customer already has (known to work in this tenant), else switch a copy of
    the default's actions to Tunnel + Z-Tunnel 2.0. -> (actions, how)"""
    ref = next((f for f in fwds if g(f, "name") != fwd_name and (f.get("forwardingProfileActions") or [])
                and all(int(a.get("enablePacketTunnel") or 0) == 1 for a in f["forwardingProfileActions"])), None)
    if ref:
        return [dict(a) for a in ref["forwardingProfileActions"]], f"copied the tunnel settings of '{g(ref, 'name')}'"
    acts = [dict(a) for a in base_actions]
    for a in acts:
        a.update(actionType=ZCC_TUNNEL, enablePacketTunnel=1)
    return acts, "set every network type to Tunnel with Z-Tunnel 2.0"


def clean_fwd(fwd):
    out = {k: v for k, v in fwd.items() if k not in TRUSTED}
    out["evaluateTrustedNetwork"] = 0
    for key in ("forwardingProfileActions", "forwardingProfileZpaActions"):
        if isinstance(out.get(key), list):
            out[key] = [{k: v for k, v in dict(a).items() if k not in ("id", "forwardingProfileId")}
                        for a in out[key] if isinstance(a, dict)]
    return out


def minimal_fwd(name, actions):
    nets = sorted({int(a.get("networkType") or 0) for a in actions if isinstance(a, dict)}) or [0, 1, 2, 3]
    by = {int(a.get("networkType") or 0): a for a in actions if isinstance(a, dict)}
    acts = []
    for n in nets:
        a = {k: v for k, v in dict(by.get(n) or {}).items() if k in CORE_ACTION}
        a.update(networkType=n, actionType=ZCC_TUNNEL, enablePacketTunnel=1)
        a.setdefault("primaryTransport", 1)
        acts.append(a)
    return {"name": name, "active": 1, "evaluateTrustedNetwork": 0, "forwardingProfileActions": acts}


def fwd_tries(fwd, src_fwd, name):
    """Progressively plainer bodies for a forwarding profile, as the demo kit's _save_fwd tries them."""
    plain = clean_fwd(fwd)
    base = [dict(a) for a in (src_fwd or {}).get("forwardingProfileActions") or []]
    for a in base:
        a.update(actionType=ZCC_TUNNEL, enablePacketTunnel=1)
    no_ut = {k: v for k, v in plain.items() if k not in ("unifiedTunnel", "enableUnifiedTunnel")}
    no_zpa = {k: v for k, v in no_ut.items() if k not in ("forwardingProfileZpaActions", "enableLWFDriver")}
    tries = [("as copied", fwd), ("without trusted-network conditions and copied ids", plain)]
    if base:
        tries.append(("from the default profile's actions", clean_fwd(dict(plain, forwardingProfileActions=base))))
    return tries + [("without the Unified Tunnel settings", no_ut),
                    ("without the Unified Tunnel and ZPA tunnel settings", no_zpa),
                    ("as a minimal Z-Tunnel 2.0 profile", minimal_fwd(name, plain.get("forwardingProfileActions") or []))]
BY_HAND = ("Build it by hand in the Client Connector portal, then Status > Fix drift, which finds it by exact "
           "name and adopts it: 1) Forwarding profile named exactly '{fwd}': a copy of '{src_fwd}' with ZIA action "
           "Tunnel and Z-Tunnel 2.0 on every network type. 2) Windows app profile named exactly '{app}': a copy of "
           "'{src_app}' for group '{group}' only, Install Zscaler SSL Certificate on, forwarding profile '{fwd}', and "
           "no broader profile above it in the order. 3) Mac pilot devices: the same app profile under macOS, named "
           "exactly '{mac}' (same group, certificate and forwarding profile).")


# the app profile per OS: (key, list device_type, policy field, install-certificate field, device type, label)
OSES = (("zcc.app", "windows", "windowsPolicy", "installSslCerts", "DEVICE_TYPE_WINDOWS", "Windows"),
        ("zcc.app.macos", "macos", "macPolicy", "installCerts", "DEVICE_TYPE_MACOS", "macOS"))
OS_OF = {o[0]: o for o in OSES}


def names(prefix, pov_id):
    """Each POV's own profile names: the POV ID's last part keeps two POVs with the same prefix apart."""
    tag = pov_id.rsplit("-", 1)[-1]
    return (naming.safe_name(naming.name(prefix, f"Z-Tunnel 2.0 {tag}"), prefix),
            naming.safe_name(naming.name(prefix, f"pilot devices {tag}"), prefix))


def mac_name(prefix, pov_id):
    tag = pov_id.rsplit("-", 1)[-1]
    return naming.safe_name(naming.name(prefix, f"pilot Macs {tag}"), prefix)


NESTED_IDS = re.compile(r"^(id|.*ProfileId|.*PolicyId|.*_id)$")


def strip_ids(o, top=True):
    """Remove every ID copied from the source profile. Client Connector's save calls create or update, so an ID left
    in a body (the profile's, or a nested action's) could edit the customer's own profile instead of making ours."""
    if isinstance(o, dict):
        return {k: strip_ids(v, False) for k, v in o.items() if not (k == "id" if top else NESTED_IDS.match(k))}
    if isinstance(o, list):
        return [strip_ids(x, False) for x in o]
    return o


def carries_ids(o, top=True):
    if isinstance(o, dict):
        return any((k == "id" if top else bool(NESTED_IDS.match(k))) or carries_ids(v, False) for k, v in o.items())
    if isinstance(o, list):
        return any(carries_ids(x, False) for x in o)
    return False


def new_id(before, rows, name):
    """The ID of the one profile with this name that wasn't there before the save; None if that isn't exactly one."""
    hits = [g(x, "id") for x in rows if g(x, "name") == name and str(g(x, "id")) not in before]
    return hits[0] if len(hits) == 1 else None


def bare_400(e):
    return bool(re.search(r"\b400\b|bad request", str(e), re.I))


class ZCC(Product):
    name, title, phase = "zcc", "Client Connector", "v1"

    def role_scopes(self, pov=None):
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
        try:
            mac_apps = self._list(t, "zcc.web_policy", device_type="macos")
        except Exception:   # noqa: BLE001 - macOS profiles are a bonus: the Windows ones still work
            mac_apps = []
        mac_default = next((a for a in mac_apps if re.search(r"default", str(g(a, "name")), re.I)), None) or \
            (sorted(mac_apps, key=lambda a: int(g(a, "ruleOrder") or 0))[-1] if mac_apps else None)
        snap["source_apps"] = {"macos": {"id": g(mac_default, "id"), "name": g(mac_default, "name")}} if mac_default else {}
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
        fwd_name, app_name = names(pov.prefix, pov.id)
        from ..core.ledger import Ledger
        led = Ledger(pov.path("ledger.json"), pov.id, pov.prefix)
        ours = {e["id"] for e in led.active("zcc")}
        clash = [n for n in (fwd_name, app_name)
                 if any(g(x, "name") == n and str(g(x, "id")) not in ours for x in fwds + apps)]
        if clash:
            checks.append(check("zcc-names", "POV profile names", INFO, ", ".join(clash) + " already exist",
                                "Apply won't create a profile over one with the same name. If someone built them "
                                "by hand for this POV, `status --fix` adopts them; otherwise rename or delete them."))
        return snap, checks

    def plan(self, pov, snap, zia_snap=None):
        if not snap.get("readable"):
            return [], ["No Client Connector items: the portal wasn't readable in discovery."]
        grp = (zia_snap or {}).get("pilot_group") or {}
        fwd_name, app_name = names(pov.prefix, pov.id)
        src_app, src_fwd = snap.get("source_app") or {}, snap.get("source_fwd") or {}
        spec = BY_HAND.format(fwd=fwd_name, app=app_name, mac=mac_name(pov.prefix, pov.id), group=grp.get("name", "the pilot group"),
                              src_fwd=src_fwd.get("name") or "your usual forwarding profile (or a new one)",
                              src_app=src_app.get("name") or "your usual Windows app profile (or a new one)")
        if not src_fwd:
            spec = spec.replace("a copy of 'your usual forwarding profile (or a new one)'",
                                "a new profile (this tenant has no default to copy)")
        if not src_app:
            spec = spec.replace("a copy of 'your usual Windows app profile (or a new one)'",
                                "a new profile (this tenant has no default to copy)")
        affects = f"devices of members of '{grp.get('name', '?')}' only"
        return [
            item("zcc", "forwarding_profile", "zcc.fwd", fwd_name, action="create_or_adopt", affects=affects,
                 criteria=["IS-ZCC-02"], spec=spec, body={
                     "name": fwd_name, "copy_of": src_fwd.get("id"), "zia_action": "Tunnel, Z-Tunnel 2.0, every network type"}),
            item("zcc", "app_profile", "zcc.app", app_name, action="create_or_adopt", affects=affects,
                 criteria=["IS-ZCC-01", "IS-ZCC-02"], spec=spec, body={
                     "name": app_name, "copy_of": src_app.get("id"), "groups": [grp.get("id")],
                     "install_ssl_certs": True, "forwarding_profile": "{ref:zcc.fwd}"}),
            *([item("zcc", "app_profile", "zcc.app.macos", mac_name(pov.prefix, pov.id), action="create_or_adopt",
                    affects=affects,
                    criteria=["IS-ZCC-01", "IS-ZCC-02", "IS-FW-01", "IS-DNS-01"], spec=spec, body={
                        "name": mac_name(pov.prefix, pov.id), "os": "macos", "copy_of": (snap.get("source_apps") or {})["macos"]["id"],
                        "groups": [grp.get("id")], "install_ssl_certs": True, "forwarding_profile": "{ref:zcc.fwd}"},
                    why="Mac pilot devices: the same profile under macOS, so their firewall and DNS traffic goes "
                        "through Z-Tunnel 2.0 too.")]
              if (snap.get("source_apps") or {}).get("macos") else []),
            item("zcc", "customer_action", "zcc.ca.devices",
                 f"Pilot devices have Client Connector installed and signed in as members of '{grp.get('name', '?')}'",
                 action="customer_action", criteria=["IS-ZCC-01"], console="zcc.enrolled_devices",
                 why="Installing software on the customer's devices is the customer's job."),
        ], ["Client Connector profiles are copies of the tenant's defaults; the defaults themselves aren't changed."]

    # ---- apply: the forwarding profile (plainer copies on a bare 400), then the app profile that uses it
    def apply(self, t, pov, items_, log):
        by = {i["key"]: i for i in items_ if i["product"] == "zcc"}
        fwd_it = by.get("zcc.fwd")
        if not fwd_it:
            return
        fwds = self._list(t, "zcc.forwarding_profile")
        if not t.ledger.find("zcc.fwd"):
            if any(g(f, "name") == fwd_it["name"] for f in fwds):
                log("warn", f"A forwarding profile named '{fwd_it['name']}' already exists and isn't in this POV's "
                            "ledger, so the kit won't create another. If it was built for this POV, `pov-kit status "
                            "--fix` adopts it; otherwise rename or delete it.")
                return
            if not fwd_it["body"].get("copy_of"):   # discovery found no default profile to copy (preflight warned)
                log("warn", "No default forwarding profile to copy, so the Client Connector profiles are built by "
                            "hand to this spec, then Status → Fix drift adopts them by name. " + fwd_it["spec"])
                return
            src = next((f for f in fwds if str(g(f, "id")) == str(fwd_it["body"]["copy_of"])), None)
            if not src:
                raise KitError("The forwarding profile the change list copies is gone. Run `pov-kit plan` again.")
            body = {k: v for k, v in src.items() if k not in DROP}
            acts, how = z2_actions(fwds, fwd_it["name"], body.get("forwardingProfileActions") or [])
            body.update(name=fwd_it["name"], forwardingProfileActions=acts)
            before = {str(g(f, "id")) for f in fwds}

            def find_id(_):
                return new_id(before, self._list(t, "zcc.forwarding_profile"), fwd_it["name"])
            last = None
            for i, (how2, b) in enumerate(fwd_tries(body, src, fwd_it["name"])):
                b = strip_ids(b)
                if carries_ids(b):   # belt and braces: never send a body that could name an existing profile
                    raise GuardError("A forwarding-profile body still carries an ID; nothing was sent.")
                try:
                    t.create("zcc.fwd", "zcc.forwarding_profile", "update_forwarding_profile", extract_id=find_id,
                             stamped=False, **b)
                    log("ok", f"Created {fwd_it['name']} ({how}" + (f"; saved {how2}" if i else "") + ")")
                    last = None
                    break
                except GuardError:
                    raise
                except KitError as e:
                    last = e
                    if not bare_400(e):
                        raise
            if last is not None:
                log("warn", "Client Connector refused every version of the forwarding profile, down to a minimal "
                            "Z-Tunnel 2.0 one (bare 400). " + fwd_it["spec"])
                return
        for key in (o[0] for o in OSES):
            it = by.get(key)
            if it and not t.ledger.find(key):
                self._app(t, it, fwd_it, log)

    def _app(self, t, app_it, fwd_it, log):
        key, dev, field, cert, dtype, label = OS_OF[app_it["key"]]
        gid = (app_it["body"].get("groups") or [None])[0]
        if isinstance(gid, str) and gid.startswith("{ref:"):   # the kit's own pilot group (Hosted DB test users)
            gid = t.ids.get(gid[5:-1])
        apps = self._list(t, "zcc.web_policy", device_type=dev)
        src = next((a for a in apps if str(g(a, "id")) == str(app_it["body"].get("copy_of"))), None)
        fwd_id = t.ids.get("zcc.fwd")
        if not (src and gid and fwd_id):
            log("warn", f"The {label} app profile wasn't made (no default profile to copy, no pilot group, or no "
                        "forwarding profile). " + app_it["spec"])
            return
        if any(g(a, "name") == app_it["name"] for a in apps):
            log("warn", f"A {label} app profile named '{app_it['name']}' already exists and isn't in this POV's ledger, "
                        "so the kit won't create another. If it was built for this POV, Status > Fix drift adopts it.")
            return
        app = strip_ids({k: v for k, v in src.items() if k not in DROP | {"forwardingProfileId"}})
        pol = dict(app.get(field) or {})
        pol[cert] = 1
        app.update(name=app_it["name"], active=1, groupAll=0, groupIds=[int(gid)], userIds=[], ruleOrder=1,
                   deviceType=app.get("deviceType") or dtype, **{field: pol})
        if carries_ids(app):
            raise GuardError("The app-profile body still carries an ID; nothing was sent.")
        app["forwardingProfileId"] = fwd_id   # ours, set after the check: the only ID the body may carry
        before = {str(g(a, "id")) for a in apps}

        def find_app(_):
            return new_id(before, self._list(t, "zcc.web_policy", device_type=dev), app_it["name"])
        try:
            t.create(key, "zcc.web_policy", "web_policy_edit", extract_id=find_app, stamped=False, **app)
        except GuardError:
            raise
        except KitError as e:
            log("warn", f"Client Connector refused the {label} app profile ({str(e)[:120]}). " + app_it["spec"])
            return
        log("ok", f"Created {app_it['name']} for {label} (pilot group only, installs the Zscaler certificate, "
                  "Z-Tunnel 2.0)")
        self.verify(t, app_it["name"], fwd_it["name"], gid, log, os_key=key)

    def verify(self, t, app_name, fwd_name, gid, log, os_key="zcc.app"):
        """Read both back: Client Connector's API can accept fields it then ignores."""
        _, dev, field, cert, _, _ = OS_OF[os_key]
        f = next((x for x in self._list(t, "zcc.forwarding_profile") if g(x, "name") == fwd_name), None)
        pols = self._list(t, "zcc.web_policy", device_type=dev)
        a = next((x for x in pols if g(x, "name") == app_name), None)
        acts = (f or {}).get("forwardingProfileActions") or []
        z2 = [x for x in acts if is_z2(x)]
        log("ok" if f and acts and len(z2) == len(acts) else "warn",
            f"{fwd_name}: Z-Tunnel 2.0 on {len(z2)} of {len(acts)} network types" if f else f"{fwd_name}: not found")
        if not a:
            log("warn", f"{app_name}: not found after saving")
            return False
        groups = [int(g(x, "id")) for x in (a.get("groups") or []) if g(x, "id")] or \
            [int(x) for x in (a.get("groupIds") or []) if x]
        ahead = [g(x, "name") for x in pols if int(g(x, "ruleOrder") or 0) < int(g(a, "ruleOrder") or 0)
                 and int(g(x, "active") or 0) == 1]
        good = str(g(a, "forwardingProfileId")) == str(g(f or {}, "id")) and int(gid) in groups and \
            int((a.get(field) or {}).get(cert) or 0) == 1
        log("ok" if good and not ahead else "warn",
            f"{app_name}: order {g(a, 'ruleOrder')}, pilot group {'yes' if int(gid) in groups else 'NO'}, "
            f"forwarding profile {'yes' if str(g(a, 'forwardingProfileId')) == str(g(f or {}, 'id')) else 'NO'}"
            + (f"; profiles ahead of it: {', '.join(map(str, ahead))}" if ahead else ""))
        return good and not ahead

    def adopt_by_name(self, t, pov, items_, log):
        """status --fix: adopt hand-built profiles that match the change list's exact names."""
        fwds = self._list(t, "zcc.forwarding_profile")
        for it in items_:
            if it["product"] != "zcc" or it["action"] != "create_or_adopt" or t.ledger.find(it["key"]):
                continue
            pool = fwds if it["kind"] == "forwarding_profile" else \
                self._list(t, "zcc.web_policy", device_type=OS_OF.get(it["key"], OSES[0])[1])
            hit = next((x for x in pool if g(x, "name") == it["name"]), None)
            if hit:
                t.adopt(it["key"], {"id": g(hit, "id"), "name": g(hit, "name")})
                log("ok", f"Adopted {it['name']} (built by hand)")

    def live_object(self, t, entry):
        if entry["kind"] == "forwarding_profile":
            return next((x for x in self._list(t, "zcc.forwarding_profile") if str(g(x, "id")) == entry["id"]), None)
        oses = [OS_OF[entry["key"]]] if entry["key"] in OS_OF else OSES   # a recovered profile: either OS
        for o in oses:
            hit = next((x for x in self._list(t, "zcc.web_policy", device_type=o[1]) if str(g(x, "id")) == entry["id"]),
                       None)
            if hit:
                return hit
        return None

    def drift(self, t, pov, ledger, items_):
        want = [i for i in items_ if i["product"] == "zcc" and i["action"] == "create_or_adopt"]
        missing = [i["name"] for i in want if not ledger.find(i["key"])]
        gone = [e["name"] for e in ledger.active("zcc") if self.live_object(t, e) is None]
        return [check("zcc-present", "POV Client Connector profiles", WARN if (missing or gone) else OK,
                      "; ".join(filter(None, [f"not created or adopted: {', '.join(missing)}" if missing else "",
                                              f"deleted in the portal: {', '.join(gone)}" if gone else ""]))
                      or f"all {len(want)}", "Build them by hand (Finish setup has the steps and exact names), then Status > Fix drift adopts them."
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

    def api_proof(self, t, pov, ledger, criterion):
        if criterion["id"] == "IS-ZCC-02":
            have = [e for e in (ledger.find("zcc.fwd"), ledger.find("zcc.app")) if e]
            live = [e for e in have if self.live_object(t, e) is not None]
            return {"status": "pass" if len(live) == 2 else "fail",
                    "detail": f"{len(live)} of 2 POV profiles in the Client Connector portal"}
        if criterion["id"] == "IS-ZCC-01":
            try:
                devs = items(t.call("zcc.devices", "list_devices", query_params={"page_size": 500}))
            except KitError as e:
                return {"status": "incomplete", "detail": f"device list unreadable: {str(e)[:100]}"}
            from ..device_setup import users   # named pilot users and the POV's own test users
            emails = set(users(pov))
            mine = [d for d in devs if str(g(d, "user_name") or g(d, "user") or "").lower() in emails] if emails else []
            on = [d for d in mine if re.search(r"registered|^1$", str(g(d, "registration_state") or ""), re.I)]
            if not emails:
                return {"status": "incomplete", "detail": "name the pilot users: `pov-kit set pilot_emails a@acme.com,b@acme.com`"}
            return {"status": "pass" if on else "fail", "detail": f"{len(on)} of {len(mine)} pilot devices registered"}
        return None

    def customer_names(self, snap):
        return set(snap.get("customer_names") or [])
