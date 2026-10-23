"""How to resolve each error or blocker: detailed, step-by-step fixes from fixes.json.

`find(ids, detail)` picks the fix for a check (or a 'Steps for people' key) and its message. `for_error(msg)` does
the same for an error with no check behind it (a failed call, a job that stopped). A 403 from a product becomes
'give the API client a <product> role', built from the 'roles' table.

The result is a plain dict: id, title, who, where, search, verified, steps, done. Only text: nothing here calls the
tenant.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

FILE = Path(__file__).with_name("fixes.json")
FORBIDDEN = re.compile(r"\b403\b|forbidden|not authori[sz]ed|access denied|insufficient (permission|scope)|has no [\w ()&-]{1,40}role", re.I)

# a check ID's product, by prefix ('zpa-read' -> zpa); 'id-*' checks read ZIdentity
ID_PRODUCT = {"zia": "zia", "zpa": "zpa", "zdx": "zdx", "zcc": "zcc", "zid": "zid", "id": "zid", "aiguard": "aiguard",
              "casb": "casb", "setup.zdx_role": "zdx", "setup.zpa_customer_id": "zpa"}


@lru_cache(maxsize=1)
def catalog():
    return json.loads(FILE.read_text(encoding="utf-8"))


def _console(key):
    from .console import paths
    p = paths().get(key) if key else None
    if not p:
        return {}
    return {"where": p.get("path") or "", "search": p.get("search") or ("" if p.get("path") else p.get("page")),
            "verified": bool(p.get("verified"))}


def _shape(fid, e):
    out = {"id": fid, "title": e["title"], "who": e.get("who", ""), "steps": list(e["steps"]), "done": e.get("done", ""),
           "where": "", "search": e.get("search", ""), "verified": False}
    out.update({k: v for k, v in _console(e.get("console")).items() if v or k == "verified"})
    if e.get("search"):
        out["search"] = e["search"]
    return out


def _id_ok(pattern, ids):
    """'zpa-*' matches by prefix, '*-left' by suffix, anything else exactly."""
    if pattern.startswith("*"):
        return any(i.endswith(pattern[1:]) for i in ids)
    if pattern.endswith("*"):
        return any(i.startswith(pattern[:-1]) for i in ids)
    return pattern in ids


def _hit(m, ids, detail):
    """How well one match line fits: an exact ID beats a wildcard ID, and an ID beats message text alone."""
    score = 0
    if m.get("check"):
        if not _id_ok(m["check"], ids):
            return 0
        score += 2 if "*" in m["check"] else 4
    if m.get("detail"):
        if not re.search(m["detail"], detail or "", re.I):
            return 0
        score += 1
    return score


def product_of(ids, detail=""):
    """Which product an error is about: from the check ID, else from the API resource in the message."""
    for i in ids:
        if i in ID_PRODUCT:
            return ID_PRODUCT[i]
        head = re.split(r"[-.]", i, maxsplit=1)[0]
        if head in ID_PRODUCT and head != "setup":
            return ID_PRODUCT[head]
    for name, r in catalog()["roles"].items():
        if re.search(r["pattern"], detail or "", re.I):
            return name
    return None


def role_fix(product):
    """'Give the API client a <product> role', for a 403 from that product."""
    c = catalog()
    r = c["roles"].get(product)
    if not r:
        return None
    steps = [s.format(name=r["name"], note=r.get("note", "")) for s in c["role_steps"]]
    return {"id": f"role-{product}", "title": f"Give the API client a {r['name']} role", "who": "customer admin",
            "steps": [s for s in steps if s.strip()], "done": f"{r['name']} is readable: the check passes.",
            **_console("oneapi.clients"), "search": "API Clients"}


def find(ids, detail="", pov_id=None):
    """The fix for a check or step. ids: its check ID(s) or step key(s), most specific first. -> dict or None."""
    ids = [i for i in ([ids] if isinstance(ids, str) else ids or []) if i]
    detail = str(detail or "")
    if FORBIDDEN.search(detail):
        prod = product_of(ids, detail)
        if prod:
            return _sub(role_fix(prod), pov_id)
    best = {False: (None, 0), True: (None, 0)}   # specific fixes, then fallbacks only when nothing specific fits
    for fid, e in catalog()["fixes"].items():
        s = max((_hit(m, ids, detail) for m in e.get("match", [])), default=0)
        fb = bool(e.get("fallback"))
        if s > best[fb][1]:
            best[fb] = ((fid, e), s)
    pick = best[False][0] or best[True][0]
    return _sub(_shape(*pick), pov_id) if pick else None


def for_error(msg, pov_id=None):
    """The fix for an error message with no check behind it. None when nothing specific fits."""
    return find([], msg, pov_id)


def _sub(f, pov_id):
    if not f or not pov_id:
        return f
    rep = lambda s: s.replace("<pov-id>", pov_id)   # noqa: E731
    return {**f, "steps": [rep(s) for s in f["steps"]], "done": rep(f["done"])}


def as_text(f, indent="         "):
    """A fix as numbered plain text (the CLI and copied reports)."""
    if not f:
        return ""
    lines = [f"{indent}how to fix: {f['title']}" + (f" ({f['who']})" if f.get("who") else "")]
    if f.get("where"):
        lines.append(f"{indent}  where: {f['where']}")
    elif f.get("search"):
        lines.append(f"{indent}  console search: {f['search']}")
    lines += [f"{indent}  {n}. {s}" for n, s in enumerate(f["steps"], 1)]
    if f.get("done"):
        lines.append(f"{indent}  done when: {f['done']}")
    return "\n".join(lines)
