"""What every product module implements. The core hands each method a guarded client (core/guard.py), never a raw
one: ReadOnlyTenant for discover and drift, LedgerTenant for apply and teardown."""
from __future__ import annotations

import json
from pathlib import Path

from ..core import KitError

CATALOG = Path(__file__).resolve().parent.parent / "catalog"


def load_catalog() -> list[dict]:
    out = []
    for f in sorted(CATALOG.glob("*.json")):
        data = json.loads(f.read_text(encoding="utf-8"))
        for c in data["criteria"]:
            out.append(dict(c, product=c.get("product") or data["product"]))
    return out


class Product:
    name = ""          # 'zia'
    title = ""         # 'Internet Access (ZIA)'
    phase = "v1"
    ready = True       # False: catalog and role scopes only; the lifecycle methods raise

    # ---- access
    def role_scopes(self, pov=None) -> dict:
        """{'discovery': [(area, access)], 'apply': [(area, access)]}, written into the role spec."""
        raise NotImplementedError

    # ---- lifecycle
    def discover(self, t, pov) -> tuple[dict, list[dict]]:
        """Read-only snapshot of what the plan needs, plus checks. -> (snapshot, checks)."""
        raise NotImplementedError

    def plan(self, pov, snap) -> tuple[list[dict], list[str]]:
        """Change-list items and notes, computed from the snapshot alone (no tenant calls), so the same tenant
        state always gives the same plan and the same hash. -> (items, notes)."""
        raise NotImplementedError

    def apply(self, t, pov, items, log) -> None:
        raise NotImplementedError

    def drift(self, t, pov, ledger, items) -> list[dict]:
        raise NotImplementedError

    def teardown(self, t, pov, ledger, log) -> list[dict]:
        """Delete this product's ledger objects. -> checks (what was deleted, what was left and why)."""
        raise NotImplementedError

    def live_object(self, t, entry) -> dict | None:
        """The object as the tenant has it now (for ownership checks and the Terraform export)."""
        raise NotImplementedError

    def terraform(self, entry, live) -> dict | None:
        """{'type': 'zia_...', 'confirmed': bool, 'attrs': {...}} for one ledger object, or None if not exportable."""
        return None

    # ---- evidence
    def customer_names(self, snap) -> set[str]:
        """Names of the customer's own objects in the snapshot, for the diagnostics redactor."""
        return set()

    def criteria(self) -> list[dict]:
        return [c for c in load_catalog() if c["product"] == self.name]


class NotReady(Product):
    ready = False

    def _later(self, *a, **kw):
        raise KitError(f"{self.title} arrives in {self.phase}; this version has its criteria and role scopes only.")

    discover = plan = apply = drift = teardown = live_object = _later
