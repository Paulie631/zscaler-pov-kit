"""The change list: every change the POV will make, approved by the customer and bound by its hash.

Items are one of:
  create          the kit creates this object (body shown in full)
  create_or_adopt the kit tries to create it; if the tenant refuses (the Client Connector bare 400), a person
                  builds it by hand to the printed spec and `status --fix` adopts it by exact name
  customer_action a change to something the customer owns; the kit never does it, it only checks it was done

A body may reference another item's ID as "{ref:<item key>}", filled in at apply time. The hash covers the
placeholders, so the approved list is fixed even though IDs aren't known yet.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import KitError

ACTIONS = ("create", "create_or_adopt", "customer_action")


def item(product, kind, key, name, action="create", body=None, rule_type=None, placement=None, affects="",
         criteria=(), why="", console=None, spec=""):
    assert action in ACTIONS, action
    return {"key": key, "product": product, "kind": kind, "rule_type": rule_type, "name": name, "action": action,
            "body": body or {}, "placement": placement, "affects": affects, "criteria": list(criteria),
            "why": why, "console": console, "spec": spec}


def canonical(items: list[dict]) -> str:
    return json.dumps(items, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def digest(items: list[dict]) -> str:
    return hashlib.sha256(canonical(items).encode("utf-8")).hexdigest()


class ChangeList:
    def __init__(self, pov_dir: Path):
        self.dir = Path(pov_dir)
        self.plan_file = self.dir / "plan.json"
        self.approval_file = self.dir / "approval.json"

    def write(self, items: list[dict], notes: list[str]) -> str:
        h = digest(items)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.plan_file.write_text(json.dumps({"hash": h, "items": items, "notes": notes,
                                             "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, indent=2),
                                  encoding="utf-8")
        if self.approval_file.exists() and self.approval()["hash"] != h:
            self.approval_file.unlink()   # a different plan needs a fresh approval
        return h

    def plan(self) -> dict:
        if not self.plan_file.exists():
            raise KitError("No change list yet. Run `pov-kit plan` first.")
        return json.loads(self.plan_file.read_text(encoding="utf-8"))

    def approve(self, by: str, note: str = "") -> dict:
        by = (by or "").strip()
        if not by:
            raise KitError("Say who approved it: `pov-kit approve --by \"Name, title\"`.")
        p = self.plan()
        if digest(p["items"]) != p["hash"]:
            raise KitError("plan.json was edited after it was written. Run `pov-kit plan` again.")
        rec = {"hash": p["hash"], "by": by, "note": note, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        self.approval_file.write_text(json.dumps(rec, indent=2), encoding="utf-8")
        return rec

    def approve_file(self, path) -> dict:
        """An approval the customer made on the change-list page (plan.html): checked against this plan's hash."""
        try:
            rec = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise KitError(f"Couldn't read the approval file: {e}") from e
        if rec.get("format") != "zpov-approval-1":
            raise KitError("That isn't an approval file from the change-list page.")
        p = self.plan()
        if rec.get("hash") != p["hash"]:
            raise KitError("This approval is for a different change list (the plan changed after the customer saw "
                           "it). Send them the current plan.html and ask again.")
        by = f"{str(rec.get('by') or '').strip()}, {str(rec.get('title') or '').strip()}".strip(", ")
        if not rec.get("by") or not rec.get("title"):
            raise KitError("The approval file has no name or title.")
        out = self.approve(by, str(rec.get("note") or ""))
        out.update(via="customer page", email=str(rec.get("email") or "")[:200], customer_at=str(rec.get("at") or "")[:40])
        self.approval_file.write_text(json.dumps(out, indent=2), encoding="utf-8")
        return out

    def approval(self) -> dict | None:
        if not self.approval_file.exists():
            return None
        return json.loads(self.approval_file.read_text(encoding="utf-8"))

    def require_approved(self, fresh_items: list[dict]) -> dict:
        """apply's gate: the plan re-made from the tenant as it is now must be the one the customer approved."""
        a = self.approval()
        if not a:
            raise KitError("The change list isn't approved yet. Show the customer `plan.html`, then run "
                           "`pov-kit approve --by \"Name, title\"`.")
        h = digest(fresh_items)
        if h != a["hash"]:
            old = {i["key"]: i for i in self.plan()["items"]}
            new = {i["key"]: i for i in fresh_items}
            diff = ([f"added: {k}" for k in new.keys() - old.keys()] + [f"removed: {k}" for k in old.keys() - new.keys()]
                    + [f"changed: {k}" for k in new.keys() & old.keys() if canonical([new[k]]) != canonical([old[k]])])
            raise KitError("The tenant changed since the customer approved the change list, so the plan is different "
                           f"({'; '.join(sorted(diff)) or 'order changed'}). Nothing was applied. Run `pov-kit plan` "
                           "and get it approved again.")
        return a


def resolve_refs(body, ids: dict):
    """Swap '{ref:<key>}' strings (anywhere in the body) for the IDs created so far."""
    if isinstance(body, dict):
        return {k: resolve_refs(v, ids) for k, v in body.items()}
    if isinstance(body, list):
        return [resolve_refs(v, ids) for v in body]
    if isinstance(body, str) and body.startswith("{ref:") and body.endswith("}"):
        key = body[5:-1]
        if key not in ids:
            raise KitError(f"'{key}' hasn't been created yet, so nothing that uses it can be.")
        return ids[key]
    return body
