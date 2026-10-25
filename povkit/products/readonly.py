"""Products a POV shows rather than configures: the kit reads them (never writes) and proves their criteria from what
the tenant already has. External Attack Surface Management (EASM) and Business Insights.

Each is a product like the others (discovery, checks, criteria, API proofs), with no change-list items and nothing to
tear down. Methods are from zscaler-sdk-python 1.11 (zeasm.organizations/findings/lookalike_domains, zbi.reports);
field names are read defensively until the lab test plan confirms them.
"""
from __future__ import annotations

import re

from ..core import KitError
from ..core.changelist import item
from ..core.checks import FAIL, OK, WARN, check
from ..tenant import g, items
from .base import Product


def _rows(res):
    """A list, a {results: [...]} object, or any object holding one list."""
    if isinstance(res, dict) and isinstance(res.get("results"), list):
        return res["results"]
    return items(res)


def _denied(e):
    return bool(re.search(r"\b40[13]\b|not authori|forbidden|not subscribed|not entitled", str(e), re.I))


class ReadOnlyProduct(Product):
    STEPS: list = []   # (key, title, criteria, why): what the customer does, so the product has something to show

    def plan(self, pov, snap):
        if not snap.get("readable"):
            return [], [f"Nothing to check for {self.title} until it's readable (see the preflight check)."]
        return [item(self.name, "customer_action", f"{self.name}.ca.{k}", title, action="customer_action",
                     criteria=crit, why=why) for k, title, crit, why in self.STEPS], []

    def apply(self, t, pov, items_, log):
        return None

    def drift(self, t, pov, ledger, items_):
        return []

    def teardown(self, t, pov, ledger, log):
        return []

    def live_object(self, t, entry):
        return None

    def _read_check(self, e, area):
        return check(f"{self.name}-read", f"{self.title} readable", FAIL,
                     "the API client has no role for it, or the tenant doesn't have it" if _denied(e) else str(e)[:160],
                     f"Give the POV's API client view access to {area} (Administration › API › OneAPI › API Clients), "
                     "or take the product out of the POV.", console="oneapi.clients")


class EASM(ReadOnlyProduct):
    name, title, phase = "easm", "External Attack Surface (EASM)", "v3"
    STEPS = [("org", "The customer's domains are added to EASM", ["EA-FND-01", "EA-LKA-01"],
              "EASM scans what's registered to the customer's domains; the first results take a day or two.")]

    def role_scopes(self, pov=None):
        return {"discovery": [("External Attack Surface Management", "view only")], "apply": []}

    def discover(self, t, pov):
        try:
            orgs = _rows(t.call("zeasm.organizations", "list_organizations"))
        except KitError as e:
            return {"readable": False}, [self._read_check(e, "EASM")]
        snap = {"readable": True, "orgs": [{"id": str(g(o, "id")), "name": g(o, "name")} for o in orgs if g(o, "id")]}
        return snap, [check("easm-orgs", "EASM organization set up", OK if snap["orgs"] else WARN,
                            ", ".join(str(o["name"]) for o in snap["orgs"]) or "none",
                            "" if snap["orgs"] else "Set up the customer's organization and domains in EASM; the first "
                            "scan then finds their exposed assets.")]

    def _org(self, pov, t):
        snap = ((pov.read_json("discovery.json", {}) or {}).get("products") or {}).get("easm") or {}
        orgs = snap.get("orgs") or [{"id": str(g(o, "id")), "name": g(o, "name")}
                                    for o in _rows(t.call("zeasm.organizations", "list_organizations")) if g(o, "id")]
        if not orgs:
            raise KitError("no EASM organization yet")
        return orgs[0]

    def api_proof(self, t, pov, ledger, criterion):
        cid = criterion["id"]
        if cid not in ("EA-FND-01", "EA-LKA-01"):
            return None
        try:
            org = self._org(pov, t)
            if cid == "EA-FND-01":
                rows = _rows(t.call("zeasm.findings", "list_findings", org["id"]))
                sev = {}
                for f in rows:
                    k = str(g(f, "severity") or g(f, "risk") or "unrated").lower()
                    sev[k] = sev.get(k, 0) + 1
                parts = ", ".join(f"{n} {k}" for k, n in sorted(sev.items(), key=lambda x: -x[1]))
                return {"status": "pass" if rows else "incomplete",
                        "detail": f"{len(rows)} findings for {org['name']}" + (f" ({parts})" if parts else "")
                        if rows else f"no findings yet for {org['name']}: the first scan may still be running"}
            rows = _rows(t.call("zeasm.lookalike_domains", "list_lookalike_domains", org["id"]))
            return {"status": "pass" if rows else "incomplete",
                    "detail": f"{len(rows)} lookalike domains tracked for {org['name']}" if rows else
                    f"no lookalike domains listed yet for {org['name']}"}
        except KitError as e:
            return {"status": "incomplete", "detail": f"EASM not readable: {str(e)[:140]}"}


class BusinessInsights(ReadOnlyProduct):
    name, title, phase = "zbi", "Business Insights", "v3"

    def role_scopes(self, pov=None):
        return {"discovery": [("Business Insights (reports)", "view only")], "apply": []}

    def discover(self, t, pov):
        try:
            reps = _rows(t.call("zbi.reports", "list_reports"))
        except KitError as e:
            return {"readable": False}, [self._read_check(e, "Business Insights")]
        return {"readable": True, "reports": len(reps)}, [
            check("zbi-reports", "Business Insights reports", OK if reps else WARN, f"{len(reps)} available",
                  "" if reps else "Reports appear after Business Insights has a few days of the customer's traffic.")]

    def api_proof(self, t, pov, ledger, criterion):
        if criterion["id"] != "BI-RPT-01":
            return None
        try:
            reps = _rows(t.call("zbi.reports", "list_reports"))
        except KitError as e:
            return {"status": "incomplete", "detail": f"Business Insights not readable: {str(e)[:140]}"}
        names = [str(g(r, "name") or g(r, "report_name") or g(r, "type") or "") for r in reps]
        return {"status": "pass" if reps else "incomplete",
                "detail": f"{len(reps)} reports available" + (f" ({', '.join(n for n in names[:4] if n)})" if names else "")
                if reps else "no reports yet: they appear after a few days of traffic"}


def _count(rows, *keys):
    """How many rows have any of these fields true-ish (e.g. connected / online)."""
    up = 0
    for r in rows:
        v = next((g(r, k) for k in keys if g(r, k) is not None), None)
        if v is True or str(v).upper() in ("CONNECTED", "ONLINE", "ACTIVE", "UP", "RUNNING", "HEALTHY", "ENABLED"):
            up += 1
    return up


class Microsegmentation(ReadOnlyProduct):
    """Zscaler Microsegmentation (ZMS): agents on the customer's servers, then policy between them. The agents are
    installed by the customer (the console gives the command); the kit reads what they report and the rules set."""
    name, title, phase = "zms", "Microsegmentation", "v3"
    STEPS = [("agents", "The Microsegmentation agent runs on 2 or 3 of the customer's test servers", ["MS-AGT-01"],
              "Microsegmentation > Agents > Add gives the command for each OS; their flows show within the hour."),
             ("policy", "A policy rule between two of those servers", ["MS-POL-01"],
              "Built from the flows the agents saw, with the customer: allow what the app needs, nothing else.")]

    def role_scopes(self, pov=None):
        return {"discovery": [("Microsegmentation", "view only")], "apply": []}

    def _cid(self, pov):
        cid = str(pov.cfg.get("customer_id") or "")
        if not cid:
            raise KitError("Microsegmentation needs the ZPA customer ID (Setup › Connect).")
        return cid

    def _agents(self, t, pov):
        return _rows(t.call("zms.agents", "list_agents", self._cid(pov), page_size=100))

    def discover(self, t, pov):
        try:
            agents = self._agents(t, pov)
        except KitError as e:
            return {"readable": False}, [self._read_check(e, "Microsegmentation")]
        up = _count(agents, "connection_status", "status", "connected")
        snap = {"readable": True, "agents": len(agents), "connected": up}
        return snap, [check("zms-agents", "Microsegmentation agents", OK if up else WARN,
                            f"{len(agents)} installed, {up} connected",
                            "" if up else "Install the agent on two or three of the customer's test servers "
                            "(Microsegmentation › Agents › Add shows the command for each OS).")]

    def api_proof(self, t, pov, ledger, criterion):
        cid = criterion["id"]
        if cid not in ("MS-AGT-01", "MS-POL-01"):
            return None
        try:
            if cid == "MS-AGT-01":
                agents = self._agents(t, pov)
                up = _count(agents, "connection_status", "status", "connected")
                return {"status": "pass" if up else "incomplete",
                        "detail": f"{up} of {len(agents)} agents connected" if agents else "no agents installed yet"}
            rules = _rows(t.call("zms.policy_rules", "list_policy_rules", self._cid(pov), fetch_all=True))
            names = [str(g(r, "name") or "") for r in rules]
            return {"status": "pass" if rules else "incomplete",
                    "detail": f"{len(rules)} policy rules" + (f" ({', '.join(n for n in names[:3] if n)})" if names else "")
                    if rules else "no policy rules yet: set one between two app zones or resource groups"}
        except KitError as e:
            return {"status": "incomplete", "detail": f"Microsegmentation not readable: {str(e)[:140]}"}


class CloudConnector(ReadOnlyProduct):
    """Cloud & Branch Connector (ZTW): the customer deploys the connector VMs (or appliance) from the provisioning
    template; the kit reads the groups and forwarding rules to prove workloads go through Zscaler."""
    name, title, phase = "ztw", "Cloud & Branch Connector", "v3"
    STEPS = [("deploy", "A Cloud Connector runs in the customer's test VPC or VNet", ["CC-GRP-01"],
              "From a provisioning template (Cloud Connector > Provisioning Templates) with the cloud's own template, "
              "such as AWS CloudFormation; the workloads' route table then points at it."),
             ("forward", "A forwarding rule sends the workloads' traffic to ZIA", ["CC-FWD-01"],
              "Cloud Connector > Forwarding Control: a rule for the test workloads' subnet.")]

    def role_scopes(self, pov=None):
        return {"discovery": [("Cloud & Branch Connector", "view only")], "apply": []}

    def discover(self, t, pov):
        try:
            groups = _rows(t.call("ztw.ec_groups", "list_ec_groups"))
        except KitError as e:
            return {"readable": False}, [self._read_check(e, "Cloud & Branch Connector")]
        snap = {"readable": True, "groups": [{"id": str(g(x, "id")), "name": g(x, "name"),
                                              "vms": len(g(x, "ec_vms") or g(x, "ecVMs") or [])} for x in groups]}
        return snap, [check("ztw-groups", "Connector groups", OK if groups else WARN,
                            ", ".join(f"{x['name']} ({x['vms']} VMs)" for x in snap["groups"]) or "none",
                            "" if groups else "Deploy a connector from a provisioning template (Cloud Connector › "
                            "Provisioning Templates), e.g. the AWS CloudFormation one in the customer's test VPC.")]

    def api_proof(self, t, pov, ledger, criterion):
        cid = criterion["id"]
        if cid not in ("CC-GRP-01", "CC-FWD-01"):
            return None
        try:
            if cid == "CC-GRP-01":
                groups = _rows(t.call("ztw.ec_groups", "list_ec_groups"))
                vms = [v for x in groups for v in (g(x, "ec_vms") or g(x, "ecVMs") or [])]
                up = _count(vms, "operational_state", "status", "state")
                return {"status": "pass" if up else "incomplete",
                        "detail": f"{len(groups)} groups, {up} of {len(vms)} connector VMs running" if groups
                        else "no connector deployed yet"}
            rules = [r for r in _rows(t.call("ztw.forwarding_rules", "list_rules"))
                     if not g(r, "default_rule") and str(g(r, "name") or "").lower() not in ("default", "default rule")]
            fwd = sorted({str(g(r, "forward_method") or g(r, "type") or "") for r in rules} - {""})
            return {"status": "pass" if rules else "incomplete",
                    "detail": f"{len(rules)} forwarding rules" + (f" ({', '.join(fwd)})" if fwd else "")
                    if rules else "only the default forwarding rule: add one that sends the workloads' traffic to ZIA"}
        except KitError as e:
            return {"status": "incomplete", "detail": f"Cloud & Branch Connector not readable: {str(e)[:140]}"}
