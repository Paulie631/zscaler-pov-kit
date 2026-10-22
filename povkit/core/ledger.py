"""The ownership ledger: the only record of what this POV created in the customer's tenant.

An object is the kit's to change or delete only when all three hold:
  1. its ID is in this POV's ledger with state 'owned' or 'adopted',
  2. its live name still carries the prefix,
  3. its live description still carries the 'zpov:<pov-id>' stamp (for kinds that have a description).
Anything that fails a test is left alone and reported.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from . import naming

OWNED, ADOPTED, HANDED_OVER, DELETED = "owned", "adopted", "handed_over", "deleted"
ACTIVE = (OWNED, ADOPTED)
# A linked object isn't the kit's: another system made it for the POV (ZIA's copy of the ZIdentity pilot group).
# Its ID fills {ref:...} in bodies, but the kit never changes or deletes it, so it is never "active".
LINKED = "linked"


class Ledger:
    def __init__(self, path: Path, pov_id: str, prefix: str):
        self.path = Path(path)
        self.pov_id = pov_id
        self.prefix = prefix
        self.entries: list[dict] = []
        if self.path.exists():
            self.entries = json.loads(self.path.read_text(encoding="utf-8")).get("entries", [])

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"pov_id": self.pov_id, "prefix": self.prefix, "entries": self.entries}, indent=2),
                       encoding="utf-8")
        tmp.replace(self.path)   # never leave a half-written ledger

    def record(self, key: str, product: str, kind: str, obj_id, name: str, rule_type=None, state=OWNED,
               stamped=True) -> dict:
        """Called right after a create (or an adoption) succeeds, before anything else happens."""
        if not naming.has_prefix(name, self.prefix):
            raise ValueError(f"refusing to record '{name}': it lacks the prefix '{self.prefix}'")
        e = {"key": key, "product": product, "kind": kind, "rule_type": rule_type, "id": str(obj_id), "name": name,
             "state": state, "stamped": stamped, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        self.entries = [x for x in self.entries if not (x["key"] == key and x["state"] in ACTIVE + (LINKED,))] + [e]
        self.save()
        return e

    def find(self, key: str) -> dict | None:
        return next((e for e in reversed(self.entries) if e["key"] == key and e["state"] in ACTIVE), None)

    def by_id(self, product: str, kind: str, obj_id) -> dict | None:
        return next((e for e in reversed(self.entries) if e["product"] == product and e["kind"] == kind
                     and e["id"] == str(obj_id) and e["state"] in ACTIVE), None)

    def linked(self, key: str) -> dict | None:
        return next((e for e in reversed(self.entries) if e["key"] == key and e["state"] == LINKED), None)

    def ids(self) -> dict:
        """{item key: ID} for {ref:...} placeholders: the POV's own objects and the ones linked to it."""
        return {e["key"]: e["id"] for e in self.entries if e["state"] in ACTIVE + (LINKED,)}

    def active(self, product: str | None = None) -> list[dict]:
        return [e for e in self.entries if e["state"] in ACTIVE and (product is None or e["product"] == product)]

    def owns(self, product: str, kind: str, live: dict) -> tuple[bool, str]:
        """All three ownership tests against the object as it is in the tenant now. -> (ok, why not)."""
        e = self.by_id(product, kind, live.get("id"))
        if not e:
            return False, "not in this POV's ledger"
        live_name = live.get("name") or live.get("configured_name") or ""
        if not naming.has_prefix(live_name, self.prefix):
            return False, f"renamed to '{live_name}' (no '{self.prefix}' prefix)"
        if e.get("stamped", True) and not naming.has_stamp(live.get("description", ""), self.pov_id):
            return False, f"description no longer carries '{naming.stamp(self.pov_id)}'"
        return True, ""

    def mark(self, entry: dict, state: str):
        entry["state"] = state
        entry[f"{state}_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.save()

    def newest_first(self, product: str | None = None) -> list[dict]:
        return list(reversed(self.active(product)))
