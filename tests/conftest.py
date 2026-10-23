"""A fake customer tenant (ZIA + Client Connector) that records every call, so tests can prove what the kit did
and did not touch."""
import copy
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from povkit.core import KitError, secrets  # noqa: E402
from povkit.core import pov as povs  # noqa: E402

RULE_RES = {"url_filtering": "url_filtering", "ssl_inspection_rules": "ssl", "dlp_web_rules": "dlp",
            "cloudappcontrol": "cloud_app_control", "file_type_control_rule": "file_type",
            "cloud_firewall_rules": "firewall", "cloud_firewall_dns": "dns"}


class FakeTenant:
    def __init__(self):
        self.calls, self.writes = [], []
        self.next_id = 1000
        self.activation = "ACTIVE"
        self.zidentity = False
        self.zcc_fwd_400 = False      # refuse every forwarding profile (bare 400)
        self.zcc_fwd_refusals = 0     # refuse this many attempts first, then accept (plainer copies get through)
        self.zcc_app_400 = False
        self.saml = True
        self.groups = [{"id": 77, "name": "POV Pilot"}, {"id": 78, "name": "Everyone"}]
        self.rules = {"url_filtering": [{"id": 1, "name": "Corp: Block adult", "order": 1, "state": "ENABLED",
                                         "groups": [{"id": 78}], "description": "customer rule"}],
                      "ssl": [{"id": 2, "name": "Corp: Inspect all", "order": 1, "state": "ENABLED"}],
                      "dlp": [], "cloud_app_control": [], "label": [], "file_type": [], "firewall": [], "dns": [],
                      "url_category": [], "network_service": []}
        self.file_types = ["FTCATEGORY_WINDOWS_EXECUTABLES", "FTCATEGORY_MSI"]
        self.cbi = [{"id": "cbi-1", "name": "Default isolation", "url": "https://cbi.example", "defaultProfile": True}]
        self.cats = ["GAMBLING", "ANONYMIZER", "SOCIAL_NETWORKING", "FINANCE", "HEALTH", "OTHER_GAMES"]
        # as a live tenant returns them: Zscaler's named templates are flagged custom; predefined ones have no name
        self.engines = [{"id": 61, "name": "5 or more Credit Card Numbers", "customDlpEngine": True},
                        {"id": 63, "name": None, "predefinedEngineName": "PCI", "customDlpEngine": False},
                        {"id": 62, "name": "Acme Project Falcon", "customDlpEngine": True}]
        self.actions = {"FILE_SHARE": ["BLOCK_FILE_SHARE_UPLOAD", "ALLOW_FILE_SHARE_UPLOAD"],
                        "AI_ML": ["BLOCK_AI_ML_WEB_USE", "ALLOW_AI_ML_WEB_USE"]}
        self.fwds = [{"id": 5, "name": "Default", "forwardingProfileActions": [{"networkType": 0, "actionType": 2}]}]
        self.apps = [{"id": 9, "name": "Default Windows", "forwardingProfileId": 5, "ruleOrder": 1}]
        # ZPA, AI Guard, ZDX, CASB: one list per resource, with a customer object in each where it matters
        self.store = {
            "zpa.app_connector_groups": [{"id": "70001", "name": "Corp connectors", "connectors": []}],
            "zpa.provisioning": [], "zpa.server_groups": [], "zpa.segment_groups": [],
            "zpa.application_segment": [{"id": "70002", "name": "Corp intranet", "domainNames": ["intranet.acme.com"]}],
            "zpa.policies": [{"id": "70003", "name": "Corp: engineering", "action": "ALLOW",
                              "conditions": [{"operands": [{"objectType": "APP", "rhs": "70002"}]}]}],
            "aiguard.policies": [{"id": 501, "name": "Corp AI policy", "inputDetectorPolicies": [], "outputDetectorPolicies": []}],
            "aiguard.llm_applications": [{"id": 502, "name": "Corp chatbot"}],
            "aiguard.llm_application_credentials": [],
            "aiguard.policy_match_rules": [{"id": 503, "name": "Corp chatbot rule", "ruleOrder": 1}],
            "zdx.troubleshooting": [], "casb_dlp_rules": [{"id": 601, "name": "Corp SaaS DLP", "order": 1}],
        }
        self.idps = [{"id": "idp1", "name": "Okta"}]
        self.departments = [{"id": 81, "name": "Sales"}]
        self.zid_users = [{"id": "z1", "loginName": "jane@acme.com"}, {"id": "z2", "loginName": "raj@acme.com"}]
        self.zid_groups = []
        self.zid_provisions = True    # ZIdentity provisions its groups to ZIA (once entitled, in a real tenant)
        self.zid_entitle_new = True   # new ZIdentity users get Internet & SaaS (a tenant that entitles everyone)
        self.zia_users_zid_managed = False   # ZIA refuses user/group writes: ZIdentity owns the users
        self.obfuscate_user_names = False    # a single get scrambles user names (seen in a live tenant)
        self.entitlements = {"z1": ["Internet & SaaS", "Private Access"], "z2": ["Internet & SaaS"]}
        self.users = [{"id": 91, "name": "Jane Roe", "email": "jane@acme.com", "groups": [{"id": 77}]},
                      {"id": 92, "name": "Raj Patel", "email": "raj@acme.com", "groups": [{"id": 78}]}]
        self.scim = [{"id": "sg1", "name": "POV Pilot"}, {"id": "sg2", "name": "Everyone"}]
        self.zdx_devices = [{"id": "d1", "name": "PILOT-LAPTOP-1", "userEmail": "jane@acme.com"}]
        self.saas_tenants = [{"tenantId": 55, "tenantName": "Acme M365"}]

    def _id(self):
        self.next_id += 1
        return self.next_id

    def call(self, resource, method, *a, **kw):
        self.calls.append((resource, method))
        write = not re.match(r"(list|get|search|status)", method)
        if write:
            self.writes.append((resource, method, a, copy.deepcopy(kw)))
        if resource == "activate":
            if method == "status":
                return {"status": self.activation}
            return {"status": "ACTIVE"}
        if resource == "authentication_settings":
            return {"orgAuthType": "SAFECHANNEL_DIR", "samlEnabled": self.saml}
        if resource == "zid.users":
            if not self.zidentity:
                raise KitError("401 not ZIdentity")
            if method == "add_user":
                if any(u["loginName"] == kw["login_name"] for u in self.zid_users):
                    raise KitError("409 user exists")
                o = {"id": f"zu{self._id()}", "loginName": kw["login_name"], "displayName": kw.get("display_name")}
                self.zid_users.append(o)
                if self.zid_entitle_new:   # a tenant that entitles everyone
                    self.entitlements[o["id"]] = ["Internet & SaaS"]
                return copy.deepcopy(o)
            if method in ("get_user", "delete_user"):
                hit = next((u for u in self.zid_users if u["id"] == str(a[0])), None)
                if hit is None:
                    raise KitError("404 not found")
                if method == "delete_user":
                    self.zid_users.remove(hit)
                    for g in self.zid_groups:
                        g["members"] = [m for m in g["members"] if m != hit["id"]]
                    return {}
                return copy.deepcopy(hit)
            ln = str((kw.get("query_params") or {}).get("login_name", "")).lower()
            return [u for u in self.zid_users if not ln or u["loginName"] == ln]
        if resource == "zid.groups":
            if not self.zidentity:
                raise KitError("401 not ZIdentity")
            if method == "list_groups":
                q = kw.get("query_params") or {}
                assert "name" not in q, "ZIdentity filters groups with name[like]"
                n = str(q.get("name[like]") or "").lower()
                return copy.deepcopy([g for g in self.zid_groups if n in g["name"].lower()])
            if method == "add_group":
                o = dict(kw, id=f"zg{self._id()}", members=[])
                self.zid_groups.append(o)
                return copy.deepcopy(o)
            hit = next((g for g in self.zid_groups if g["id"] == str(a[0])), None)
            if hit is None:
                raise KitError("404 not found")
            if method == "get_group":
                return copy.deepcopy(hit)
            if method == "list_group_users_details":
                return [{"id": m} for m in hit["members"]]
            if method == "add_users_to_group":
                hit["members"] += [str(x) for x in kw["id"] if str(x) not in hit["members"]]
                return {}
            if method == "remove_user_from_group":
                hit["members"] = [m for m in hit["members"] if m != str(a[1])]
                return {}
            if method == "delete_group" and hit["members"]:   # as live ZIdentity answers (2026-10)
                raise KitError("409 Resource in use - Group cannot be deleted because it is associated with one or "
                               "more users.")
            if method == "delete_group":
                self.zid_groups.remove(hit)
                self.groups = [g for g in self.groups if g.get("_zid") != hit["id"]]   # ZIdentity deprovisions it
                return {}
        if resource == "zid.user_entitlement":
            return {"services": [{"serviceName": n} for n in self.entitlements.get(str(a[0]), [])]}
        if resource == "zpa.saml_attributes":
            return [{"id": "sa1", "name": "memberOf"}, {"id": "sa2", "name": "department"}]
        if resource == "user_management":
            return self._users(method, a, kw)
        if resource == "url_categories":
            if method == "list_categories" and not (kw.get("query_params") or {}).get("custom_only"):
                return [{"id": c} for c in self.cats] + copy.deepcopy(self.rules["url_category"])
            return self._crud("url_category", method, a, kw)
        if resource == "cloud_firewall":
            return self._crud("network_service", method, a, kw)
        if resource == "file_type_control_rule" and method == "list_file_type_categories":
            return [{"name": n} for n in self.file_types]
        if resource == "cloud_browser_isolation":
            return copy.deepcopy(self.cbi)
        if resource == "dlp_engine":
            return self.engines
        if resource == "cloudappcontrol" and method == "list_available_actions":
            return self.actions.get(a[0], [])
        if resource == "rule_labels":
            return self._crud("label", method, a, kw)
        if resource in RULE_RES:
            if resource == "cloudappcontrol":
                a = a[1:]   # rule type first
            return self._crud(RULE_RES[resource], method, a, kw)
        if resource == "zcc.forwarding_profile":
            if method == "list_by_company":
                return copy.deepcopy(self.fwds)
            if method == "update_forwarding_profile":
                if self.zcc_fwd_400:
                    raise KitError("400 Bad Request")
                if self.zcc_fwd_refusals:
                    self.zcc_fwd_refusals -= 1
                    raise KitError("400 Bad Request")
                self.fwds.append(dict(kw, id=self._id()))
                return {"success": "true"}
            if method == "delete_forwarding_profile":
                self.fwds = [f for f in self.fwds if str(f["id"]) != str(a[0])]
                return {}
        if resource == "zcc.web_policy":
            if method == "list_by_company":
                return copy.deepcopy(self.apps)
            if method == "web_policy_edit":
                if self.zcc_app_400:
                    raise KitError("400 Bad Request")
                self.apps.append(dict(kw, id=self._id()))
                return {"success": "true"}
            if method == "delete_web_policy":
                self.apps = [x for x in self.apps if str(x["id"]) != str(a[0])]
                return {}
        if resource == "zpa.enrollment_certificates":
            return [{"id": "c1", "name": "Connector"}, {"id": "c2", "name": "Root"}]
        if resource == "zpa.idp":
            return copy.deepcopy(self.idps)
        if resource == "zpa.scim_groups":
            q = (kw.get("query_params") or {}).get("search", "")
            return [x for x in self.scim if q.lower() in x["name"].lower()]
        if resource == "zdx.apps":
            return [{"id": "app7", "name": "Microsoft 365"}]
        if resource == "zdx.devices":
            if method == "get_device_apps":
                return [{"id": "app7", "score": 87}]
            return copy.deepcopy(self.zdx_devices)
        if resource == "zcc.devices":
            return [{"userName": "jane@acme.com", "registrationState": "Registered"}]
        if resource == "saas_security_api":
            return copy.deepcopy(self.saas_tenants) if method == "list_casb_tenant_lite" else [{"tenantId": 55}]
        if resource in self.store:
            return self._generic(resource, method, a, kw)
        raise AssertionError(f"fake tenant has no {resource}.{method}")

    def _users(self, method, a, kw):
        kind = next(k for k in ("department", "group", "user") if k in method)
        rows = {"department": self.departments, "group": self.groups, "user": self.users}[kind]
        if kind == "group" and self.zid_provisions:
            for zg in self.zid_groups:
                if not any(g.get("_zid") == zg["id"] for g in self.groups):
                    self.groups.append({"id": self._id(), "name": zg["name"], "_zid": zg["id"]})
        if method.startswith("list"):
            q = str((kw.get("query_params") or {}).get("search", "")).lower()
            return copy.deepcopy([r for r in rows if q in r["name"].lower() or q in str(r.get("email", "")).lower()])
        if method.startswith("add") and self.zia_users_zid_managed:
            raise KitError("400 UNMODIFIABLE: OneIdentityUserLogin enabled users will have read only access")
        if method.startswith("add"):
            if any(r["name"] == kw["name"] for r in rows):
                raise KitError("400 duplicate name")
            o = dict(kw, id=self._id())
            rows.append(o)
            return copy.deepcopy(o)
        hit = next((r for r in rows if str(r["id"]) == str(a[0])), None)
        if hit is None:
            raise KitError("404 not found")
        if method.startswith("get"):
            o = copy.deepcopy(hit)
            if kind == "user" and self.obfuscate_user_names:   # as an API role with "User Names: Obfuscated"
                o["name"] = "Olxr3vbStYtuaih/hOJ+diQ0BBDX+BtWahf2pe85xSU="
            return o
        if method.startswith("delete"):
            rows.remove(hit)
            return {}
        hit.update(kw)
        return copy.deepcopy(hit)

    def _generic(self, res, method, a, kw):
        rows = self.store[res]
        zpa = res.startswith("zpa.")
        ids = {str(r["id"]) for r in rows}

        def find():
            want = next((str(x) for x in a if str(x) in ids), None)
            hit = next((r for r in rows if str(r["id"]) == want), None)
            if hit is None:
                raise KitError("404 not found")
            return hit
        if method.startswith("list"):
            return copy.deepcopy(rows)
        if method.startswith(("add", "start")):
            o = dict(kw)
            if method == "add_access_rule_v2":   # positional name and action; conditions as the API returns them
                o.update(name=a[0], action=a[1].upper(), conditions=[
                    {"operands": [{"objectType": c[0].upper(), "rhs": v[1] if isinstance(v, (list, tuple)) else v}
                                  for v in c[1]]} for c in kw.get("conditions", [])])
            if method == "start_deeptrace":
                o.update(device_id=a[0], name=kw.get("session_name"))
            new_id = str(self._id()) if zpa else self._id()
            o["id"] = new_id
            rows.append(o)
            out = copy.deepcopy(o)
            if method == "add_provisioning_key":
                out["provisioningKey"] = "3|fake-provisioning-secret"
            if method == "add_credential":
                out["key"] = "fake-detection-key"
            if method == "start_deeptrace":
                out = {"trace_id": new_id}
            return out
        if method.startswith("get"):
            return copy.deepcopy(find())
        if method.startswith(("update", "reorder")):
            hit = find()
            hit.update(kw)
            if method == "reorder_rule":
                hit["ruleOrder"] = a[-1]
            return copy.deepcopy(hit)
        if method.startswith("delete"):
            hit = find()
            if res == "zpa.app_connector_groups" and hit.get("connectors"):
                raise KitError("400 connector group has connectors")
            rows.remove(hit)
            return {}
        raise AssertionError(f"{res}.{method}")

    def _crud(self, kind, method, a, kw):
        rows = self.rules[kind]
        if method.startswith("list"):
            return copy.deepcopy(rows)
        if method.startswith("get"):
            hit = next((r for r in rows if str(r["id"]) == str(a[0])), None)
            if not hit:
                raise KitError("404 not found")
            return copy.deepcopy(hit)
        if method.startswith("add"):
            nm = kw.get("name") or kw.get("configured_name")
            if any((r.get("name") or r.get("configured_name")) == nm for r in rows):
                raise KitError("400 duplicate name")
            o = dict(kw, id=self._id())
            if "order" in kw:   # insert: rules at or below shift down one
                for r in rows:
                    if int(r.get("order") or 0) >= kw["order"]:
                        r["order"] += 1
            rows.append(o)
            return copy.deepcopy(o)
        if method.startswith("update"):
            hit = next(r for r in rows if str(r["id"]) == str(a[0]))
            hit.update(kw)
            return copy.deepcopy(hit)
        if method.startswith("delete"):
            self.rules[kind] = [r for r in rows if str(r["id"]) != str(a[0])]
            return {}
        raise AssertionError(method)

    def by_name(self, kind, name):
        return next((r for r in self.rules[kind] if (r.get("name") or r.get("configured_name")) == name), None)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(povs, "BASE", tmp_path)
    monkeypatch.setattr(povs, "POVS", tmp_path / "povs")
    monkeypatch.setattr(povs, "CURRENT", tmp_path / "current")
    store = {}
    monkeypatch.setattr(secrets, "get", lambda pid, n: store.get((pid, n)))
    monkeypatch.setattr(secrets, "put", lambda pid, n, v: store.__setitem__((pid, n), v))
    monkeypatch.setattr(secrets, "delete", lambda pid, n: store.pop((pid, n), None) is not None)
    return store


@pytest.fixture
def tenant():
    return FakeTenant()


@pytest.fixture
def pov(home):
    p = povs.new("Acme Corp", ["zia", "zcc"])
    p.cfg["pilot_group"] = "POV Pilot"
    p.cfg["vanity_domain"] = "acme"
    p.save()
    return p


@pytest.fixture
def pov_all(home):
    p = povs.new("Acme Corp", ["zia", "zcc", "zpa", "aiguard", "zdx", "casb"])
    p.cfg.update(pilot_group="POV Pilot", vanity_domain="acme", pilot_emails=["jane@acme.com"],
                 zpa={"domains": ["pov-app.acme.internal"], "tcp_ports": ["443"], "app_name": "HR portal"})
    p.save()
    return p


@pytest.fixture
def tenant_for(tenant):
    return lambda pov, which: tenant


def pytest_terminal_summary(terminalreporter):
    """On GitHub Actions, each failure also becomes an annotation, readable from the run's API without the log."""
    import os
    if not os.getenv("GITHUB_ACTIONS"):
        return
    for rep in terminalreporter.stats.get("failed", []) + terminalreporter.stats.get("error", []):
        msg = str(getattr(rep, "longrepr", "") or "").strip().splitlines()
        tail = " | ".join(m.strip() for m in msg[-6:])[:900].replace("%", "%25").replace("\r", "").replace("\n", " ")
        terminalreporter.write_line(f"::error title={rep.nodeid}::{tail}")
