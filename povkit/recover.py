"""Rebuild a POV's ledger from the tenant, when the laptop that held it is gone and no backup exists.

Every object the kit creates carries the POV prefix in its name, and most also carry 'zpov:<pov-id>' in their
description. The sweep reads every product (read-only) and sorts what it finds:

  stamp      prefix and this POV's stamp: certainly this POV's. Recorded as owned.
  name only  prefix, but a kind with no description (Client Connector profiles, provisioning keys, AI Guard apps,
             keys and rules) or a description someone cleared. Probably this POV's. Recorded as adopted, so teardown
             keeps it unless the SE says yes to adopted objects too.
  other POV  prefix and another POV's stamp. Never recorded.

Nothing is written to the tenant. `--write` records the finds in the ledger; until then it's a report.
ZDX deep traces aren't swept: they end on their own within an hour.
"""
from __future__ import annotations

import re

from .core import KitError, naming
from .core.guard import ReadOnlyTenant
from .core.ledger import ADOPTED, OWNED, Ledger
from .tenant import g, items

# Cloud App Control rule types to look through when the POV's own config is gone
CAC_TYPES = ["AI_ML", "FILE_SHARE", "WEBMAIL", "SOCIAL_NETWORKING", "INSTANT_MESSAGING", "STREAMING_MEDIA",
             "BUSINESS_PRODUCTIVITY", "CONSUMER", "ENTERPRISE_COLLABORATION", "SYSTEM_AND_DEVELOPMENT", "DNS_OVER_HTTPS",
             "HOSTING_PROVIDER", "IT_SERVICES", "SALES_AND_MARKETING", "HUMAN_RESOURCES", "LEGAL", "HEALTH_CARE", "FINANCE"]
OTHER_STAMP = re.compile(r"zpov:([a-z0-9-]+)")


def _desc(o):
    return str(g(o, "description") or g(o, "comments") or "")


def _sort(pov_id, prefix, product, kind, rows, rule_type=None, name_of=lambda o: str(g(o, "name") or g(o, "configured_name") or "")):
    out = []
    for o in rows:
        n = name_of(o)
        if not naming.has_prefix(n, prefix) or g(o, "id") in (None, ""):
            continue
        d = _desc(o)
        stamp = OTHER_STAMP.search(d)
        proof = "stamp" if naming.has_stamp(d, pov_id) else "other POV" if stamp else "name only"
        out.append({"product": product, "kind": kind, "id": str(g(o, "id")), "name": n, "rule_type": rule_type,
                    "proof": proof, "other": stamp.group(1) if proof == "other POV" else None})
    return out


def sweep(t, pov_id, prefix, product_names, cac_types=None):
    """Read-only. -> (finds, problems)"""
    from .products import aiguard, casb, zia, zpa
    finds, problems = [], []

    def safe(label, fn):
        try:
            return fn()
        except KitError as e:
            problems.append(f"{label}: {str(e)[:120]}")
            return []

    if "zia" in product_names:
        for kind, k in zia.KINDS.items():
            types_ = (cac_types or CAC_TYPES) if k.get("typed") else [None]
            for rt in types_:
                rows = safe(f"ZIA {k['title']}" + (f" {rt}" if rt else ""), lambda kind=kind, rt=rt: zia.list_kind(t, kind, rt, prefix))
                finds += _sort(pov_id, prefix, "zia", kind, rows, rt, zia.obj_name)
    if "zpa" in product_names:
        for kind, (res, meth) in zpa.LISTS.items():
            finds += _sort(pov_id, prefix, "zpa", kind, safe(f"ZPA {kind}", lambda res=res, meth=meth: items(t.call(res, meth))))
        finds += _sort(pov_id, prefix, "zpa", "access_rule",
                       safe("ZPA access rules", lambda: items(t.call("zpa.policies", "list_rules", "access"))))
        finds += _sort(pov_id, prefix, "zpa", "provisioning_key",
                       safe("ZPA provisioning keys", lambda: items(t.call("zpa.provisioning", "list_provisioning_keys",
                                                                           zpa.KEY_TYPE))))
    if "aiguard" in product_names:
        for kind, k in aiguard.KINDS.items():
            finds += _sort(pov_id, prefix, "aiguard", kind,
                           safe(f"AI Guard {k['title']}", lambda k=k: items(t.call(k["res"], k["lst"]))))
    if "casb" in product_names:
        finds += _sort(pov_id, prefix, "casb", "casb_dlp_rule",
                       safe("CASB DLP rules", lambda: items(t.call("casb_dlp_rules", "list_rules", casb.RULE_TYPE))),
                       casb.RULE_TYPE)
    if "zcc" in product_names:
        finds += _sort(pov_id, prefix, "zcc", "forwarding_profile",
                       safe("Client Connector forwarding profiles",
                            lambda: items(t.call("zcc.forwarding_profile", "list_by_company"))))
        finds += _sort(pov_id, prefix, "zcc", "app_profile",
                       safe("Client Connector app profiles",
                            lambda: items(t.call("zcc.web_policy", "list_by_company", query_params={"device_type": "windows"}))))
    seen, unique = set(), []
    for f in finds:   # a rule can show up under more than one listing
        if (f["product"], f["kind"], f["id"]) not in seen:
            seen.add((f["product"], f["kind"], f["id"]))
            unique.append(f)
    return unique, problems


def run(pov, tenant_for, write=False):
    """Sweep the tenant for this POV's objects. -> (finds with 'status', problems)"""
    t = ReadOnlyTenant(tenant_for(pov, "discovery"))
    cac = None
    plan = pov.read_json("plan.json", {}) or {}
    if plan.get("items"):
        cac = sorted({i["rule_type"] for i in plan["items"] if i["kind"] == "cloud_app_control" and i.get("rule_type")}) or None
    finds, problems = sweep(t, pov.id, pov.prefix, pov.products, cac)
    led = Ledger(pov.path("ledger.json"), pov.id, pov.prefix)
    by_name = {(i["product"], i["kind"], i["name"]): i["key"] for i in plan.get("items") or []}
    for f in finds:
        if f["proof"] == "other POV":
            f["status"] = f"left alone: POV {f['other']}'s"
            continue
        if led.by_id(f["product"], f["kind"], f["id"]):
            f["status"] = "already in the ledger"
            continue
        key = by_name.get((f["product"], f["kind"], f["name"])) or f"recovered.{f['product']}.{f['kind']}.{f['id']}"
        state = OWNED if f["proof"] == "stamp" else ADOPTED
        f["status"] = f"{'recorded' if write else 'would record'} as {state}"
        if write:
            led.record(key, f["product"], f["kind"], f["id"], f["name"], rule_type=f.get("rule_type"), state=state,
                       stamped=f["proof"] == "stamp")
    if write:
        pov.log("recover", f"recover: {sum(1 for f in finds if f['status'].startswith('recorded'))} objects recorded")
        if pov.cfg.get("state") in (None, "new"):
            pov.cfg["state"] = "recovered"
            pov.save()
        from . import backup
        backup.save(pov)
    return finds, problems
