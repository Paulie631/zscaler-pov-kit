"""The role spec for the POV's two OneAPI clients, for whoever creates them (customer admin or SE)."""
from __future__ import annotations

from . import products
from .console import path_for


def render(pov) -> str:
    sel = products.selected(pov.products)
    out = [f"# API clients for POV {pov.id} ({pov.cfg['customer']})", "",
           "Create two OneAPI clients. " + path_for("oneapi.clients") + ".",
           "Give each a secret, then hand the client IDs and secrets to the SE, who enters them with",
           "`pov-kit connect --discovery` and `pov-kit connect --apply` (secrets go straight to the keychain).", ""]
    for which, when in (("discovery", "now, for the whole POV"),
                        ("apply", "only after you approve the change list; delete it at handover")):
        out += [f"## ZPOV {pov.id} {which}", f"Create it {when}.", "", "| Product area | Access |", "| --- | --- |"]
        for p in sel:
            for area, access in p.role_scopes().get(which, []):
                out.append(f"| {area} | {access} |")
        out.append("")
    out += ["Scope names above follow the design; confirm them against your console's role editor.",
            "The apply client never needs administration, role, user-management or authentication rights."]
    return "\n".join(out) + "\n"
