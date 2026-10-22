"""Delete a POV from this laptop, after verifying it's safe to.

Deleting forgets the POV: its folder (settings, ledger, approval, report, logs, recordings), its keychain secrets,
its Claude Desktop entry and its encrypted backup. The ledger is the only record of what the POV created in the
customer's tenant, so a POV that may still have objects there is never deleted:

  verify(pov, tenant_for)  read-only. Every object the ledger still lists as the POV's is looked up in the tenant;
                           ones already gone are marked deleted. Anything still there (or unreadable) blocks the
                           delete, with the way out (tear down, or hand over as Terraform).
  delete(pov, confirm)     runs the ledger check again and needs the POV's ID typed back as `confirm`.
"""
from __future__ import annotations

import shutil

from . import products
from .core import KitError, pov as povs, secrets
from .core.guard import ReadOnlyTenant
from .core.ledger import Ledger


def _ledger(pov):
    return Ledger(pov.path("ledger.json"), pov.id, pov.prefix)


def verify(pov, tenant_for=None):
    """-> {ok, blockers, removes, still_there}. Reads the tenant only if the ledger still lists objects."""
    led = _ledger(pov)
    blockers, still = [], []
    active = led.active()
    if active:
        t = None
        if tenant_for:
            try:
                t = ReadOnlyTenant(tenant_for(pov, "discovery"))
            except KitError as e:
                blockers.append(f"Couldn't sign in to check the tenant ({str(e)[:120]}).")
        for e in active:
            p = products.REGISTRY.get(e["product"])
            if t is None or p is None:
                still.append(e["name"])
                continue
            try:
                live = p.live_object(t, e)
            except Exception:
                still.append(e["name"])   # unreadable counts as still there
                continue
            if live is None:
                led.mark(e, "deleted")
            else:
                still.append(e["name"])
        if still:
            blockers.append(f"{len(still)} POV object{'s are' if len(still) > 1 else ' is'} still in the customer's "
                            f"tenant (or couldn't be checked). Remove them first (Handover → Remove the POV), or hand "
                            f"them over as Terraform, then delete.")
    removes = [f"the POV folder ({pov.dir})", "its secrets in the keychain"]
    from . import backup
    if (pov.cfg.get("mcp") or {}).get("installed"):
        removes.append("its Claude Desktop entry")
    d = backup.folder()
    if d and (d / f"{pov.id}.zpovbak").exists():
        removes.append(f"its encrypted backup ({d / (pov.id + '.zpovbak')})")
    handed = sum(1 for e in led.entries if e["state"] == "handed_over")
    notes = [f"{handed} object{'s' * (handed != 1)} handed over as Terraform stay in the tenant: they're the "
             "customer's now."] if handed else []
    return {"ok": not blockers, "blockers": blockers, "removes": removes, "still_there": still, "notes": notes,
            "id": pov.id, "customer": pov.cfg.get("customer"), "state": pov.cfg.get("state")}


def delete(pov, confirm, tenant_for=None):
    if (confirm or "").strip() != pov.id:
        raise KitError(f"Type the POV's ID ({pov.id}) to confirm. Nothing was deleted.")
    v = verify(pov, tenant_for)
    if not v["ok"]:
        raise KitError("Not deleted: " + " ".join(v["blockers"]))
    from . import backup, mcp, usecases
    try:
        mcp.remove(pov)
    except Exception:
        pass   # a missing or unreadable Claude Desktop config never blocks the delete
    gone = secrets.delete_all(pov.id, usecases.secret_names(pov))
    d = backup.folder()
    if d and (d / f"{pov.id}.zpovbak").exists():
        (d / f"{pov.id}.zpovbak").unlink()
    shutil.rmtree(pov.dir)
    if povs.CURRENT.exists() and povs.CURRENT.read_text(encoding="utf-8").strip() == pov.id:
        povs.CURRENT.unlink()
    return {"deleted": pov.id, "secrets": len(gone)}
