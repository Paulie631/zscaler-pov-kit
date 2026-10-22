"""Guarded tenant clients. Product modules never get a raw client.

ReadOnlyTenant   discovery and drift: refuses any call that isn't a read, before it leaves the laptop.
LedgerTenant     apply and teardown: creates only items in the approved change list (recording each in the
                 ledger at once), and updates or deletes only objects the ledger owns, checked against the
                 live object. Reads pass through.
"""
from __future__ import annotations

import re

from . import GuardError
from .changelist import resolve_refs

READ = re.compile(r"^(list|get|search|status)")


def is_read(method: str) -> bool:
    return bool(READ.match(method))


# Products whose API takes integer IDs in request bodies (Client Connector too, as the demo kit sends them).
# ZPA and the others take IDs as strings.
INT_IDS = {"zia", "aiguard", "zcc"}


def native(v, product="zia"):
    s = str(v)
    return int(s) if product in INT_IDS and s.isdigit() else s


class ReadOnlyTenant:
    mode = "read-only"

    def __init__(self, tenant):
        self._t = tenant

    def call(self, resource, method, *a, **kw):
        if not is_read(method):
            raise GuardError(f"Discovery is read-only: refused {resource}.{method}. Nothing was sent.")
        return self._t.call(resource, method, *a, **kw)


class LedgerTenant:
    mode = "ledger-only"

    def __init__(self, tenant, ledger, approved_items: list[dict]):
        self._t = tenant
        self.ledger = ledger
        self.approved = {i["key"]: i for i in approved_items}
        # IDs keep their native type ({ref:...} fills ZIA bodies, whose IDs are integers); the ledger stores text
        self.ids = {e["key"]: native(e["id"], e["product"]) for e in ledger.active()}

    def call(self, resource, method, *a, **kw):
        if not is_read(method):
            raise GuardError(f"Writes go through create()/delete(), never call(): refused {resource}.{method}.")
        return self._t.call(resource, method, *a, **kw)

    def create(self, key: str, resource: str, method: str, *a, extract_id=lambda r: r.get("id"), stamped=True, **body):
        """Create an approved item. Returns its ID. An item already in the ledger is not created twice."""
        it = self.approved.get(key)
        if not it or it["action"] not in ("create", "create_or_adopt"):
            raise GuardError(f"'{key}' isn't a create in the approved change list. Nothing was sent.")
        done = self.ledger.find(key)
        if done:
            return done["id"]
        body = resolve_refs(body, self.ids)
        out = self._t.call(resource, method, *a, **body)
        obj_id = extract_id(out if isinstance(out, dict) else {})
        if obj_id in (None, ""):
            raise GuardError(f"{resource}.{method} returned no ID for '{key}'; check the tenant by hand before "
                             "rerunning apply.")
        self.ledger.record(key, it["product"], it["kind"], obj_id, body.get("name") or it["name"],
                           rule_type=it.get("rule_type"), stamped=stamped)
        self.ids[key] = native(obj_id, it["product"])
        return str(obj_id)

    # tenant-wide writes the kit may make: only activation, and only after the product's activation guard passed
    ALLOWED_WRITES = {("activate", "activate")}

    def activate(self, resource="activate", method="activate"):
        if (resource, method) not in self.ALLOWED_WRITES:
            raise GuardError(f"refused {resource}.{method}: not an allowed tenant-wide write.")
        return self._t.call(resource, method)

    def adopt(self, key: str, live: dict):
        """Record an object a person built by hand to the change list's spec, found by exact name."""
        it = self.approved.get(key)
        if not it or it["action"] != "create_or_adopt":
            raise GuardError(f"'{key}' can't be adopted: it isn't a create-or-adopt item in the approved list.")
        if (live.get("name") or "") != it["name"]:
            raise GuardError(f"Won't adopt '{live.get('name')}': the change list names it exactly '{it['name']}'.")
        e = self.ledger.record(key, it["product"], it["kind"], live["id"], it["name"], rule_type=it.get("rule_type"),
                               state="adopted", stamped=False)
        self.ids[key] = native(e["id"], it["product"])
        return e

    def delete(self, entry: dict, live: dict, resource: str, method: str, *a):
        """Delete one ledger object after checking all three ownership tests against the live object."""
        ok, why = self.ledger.owns(entry["product"], entry["kind"], live)
        if not ok:
            raise GuardError(f"Left '{live.get('name') or entry['name']}' alone: {why}.")
        self._t.call(resource, method, *a)
        self.ledger.mark(entry, "deleted")

    def update(self, entry: dict, live: dict, resource: str, method: str, *a, **body):
        """Fix drift on one ledger object (same three tests)."""
        ok, why = self.ledger.owns(entry["product"], entry["kind"], live)
        if not ok:
            raise GuardError(f"Won't change '{live.get('name') or entry['name']}': {why}.")
        return self._t.call(resource, method, *a, **resolve_refs(body, self.ids))
