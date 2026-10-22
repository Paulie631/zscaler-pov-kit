"""The role spec for the POV's OneAPI client(s), for whoever creates them (customer admin or SE).

Single-client mode (the default): one client with view access to everything in scope and write access to only the
object types in the change list. Separate mode: a view-only discovery client now, and an apply client after approval.
"""
from __future__ import annotations

from . import products
from .console import path_for


def render(pov) -> str:
    sel = products.selected(pov.products)
    single = pov.cfg.get("client_mode", "single") == "single"
    out = [f"# API client{'' if single else 's'} for POV {pov.id} ({pov.cfg['customer']})", "",
           f"Create {'one OneAPI client' if single else 'two OneAPI clients'}. {path_for('oneapi.clients')}.",
           "Give it a secret, then hand the client ID and secret to the SE, who enters them in the console's Setup tab"
           " (or `pov-kit connect`). The secret goes straight to the keychain.", ""]
    if single:
        out += [f"## ZPOV {pov.id}", "Create it at kickoff; delete it at handover. The kit only writes after you "
                "approve the change list, and only the object types listed under full access.", "",
                "| Product area | Access |", "| --- | --- |"]
        for p in sel:
            out += [f"| {area} | {access} |" for area, access in p.role_scopes(pov).get("discovery", [])]
            out += [f"| {area} | {access} |" for area, access in p.role_scopes(pov).get("apply", [])]
        out.append("")
    else:
        for which, when in (("discovery", "now, for the whole POV"),
                            ("apply", "only after you approve the change list; delete it at handover")):
            out += [f"## ZPOV {pov.id} {which}", f"Create it {when}.", "", "| Product area | Access |", "| --- | --- |"]
            for p in sel:
                out += [f"| {area} | {access} |" for area, access in p.role_scopes(pov).get(which, [])]
            out.append("")
    out += [f"## Optional: ZPOV {pov.id} read-only", "Only if the SE asks for Claude Desktop's read-only access to the "
            "tenant during the POV (`pov-kit mcp`). View only, everything in scope; delete it at handover.", "",
            "| Product area | Access |", "| --- | --- |"]
    for p in sel:
        out += [f"| {area} | {access} |" for area, access in p.role_scopes(pov).get("discovery", [])]
    out.append("")
    out += ["Scope names above follow the design; confirm them against your console's role editor.",
            "The kit never needs administration, role, user-management or authentication rights."]
    return "\n".join(out) + "\n"
