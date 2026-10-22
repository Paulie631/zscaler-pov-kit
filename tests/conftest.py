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
            "cloudappcontrol": "cloud_app_control"}


class FakeTenant:
    def __init__(self):
        self.calls, self.writes = [], []
        self.next_id = 1000
        self.activation = "ACTIVE"
        self.zidentity = False
        self.zcc_fwd_400 = False
        self.groups = [{"id": 77, "name": "POV Pilot"}, {"id": 78, "name": "Everyone"}]
        self.rules = {"url_filtering": [{"id": 1, "name": "Corp: Block adult", "order": 1, "state": "ENABLED",
                                         "groups": [{"id": 78}], "description": "customer rule"}],
                      "ssl": [{"id": 2, "name": "Corp: Inspect all", "order": 1, "state": "ENABLED"}],
                      "dlp": [], "cloud_app_control": [], "label": []}
        self.cats = ["GAMBLING", "ANONYMIZER", "SOCIAL_NETWORKING", "FINANCE", "HEALTH"]
        self.engines = [{"id": 61, "name": "5 or more Credit Card Numbers"}]
        self.actions = {"FILE_SHARE": ["BLOCK_FILE_SHARE_UPLOAD", "ALLOW_FILE_SHARE_UPLOAD"],
                        "AI_ML": ["BLOCK_AI_ML_WEB_USE", "ALLOW_AI_ML_WEB_USE"]}
        self.fwds = [{"id": 5, "name": "Default", "forwardingProfileActions": [{"networkType": 0, "actionType": 2}]}]
        self.apps = [{"id": 9, "name": "Default Windows", "forwardingProfileId": 5, "ruleOrder": 1}]

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
            return {"orgAuthType": "SAFECHANNEL_DIR", "samlEnabled": True}
        if resource == "zid.users":
            if not self.zidentity:
                raise KitError("401 not ZIdentity")
            return []
        if resource == "user_management" and method == "list_groups":
            q = (kw.get("query_params") or {}).get("search", "")
            return [g for g in self.groups if q.lower() in g["name"].lower()]
        if resource == "url_categories":
            return [{"id": c} for c in self.cats]
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
                self.fwds.append(dict(kw, id=self._id()))
                return {"success": "true"}
            if method == "delete_forwarding_profile":
                self.fwds = [f for f in self.fwds if str(f["id"]) != str(a[0])]
                return {}
        if resource == "zcc.web_policy":
            if method == "list_by_company":
                return copy.deepcopy(self.apps)
            if method == "delete_web_policy":
                self.apps = [x for x in self.apps if str(x["id"]) != str(a[0])]
                return {}
        raise AssertionError(f"fake tenant has no {resource}.{method}")

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
            if any(r["name"] == kw["name"] for r in rows):
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
        return next((r for r in self.rules[kind] if r["name"] == name), None)


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
def tenant_for(tenant):
    return lambda pov, which: tenant
