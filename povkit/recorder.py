"""Recording real API traffic during the lab run, so the offline tests check the kit against Zscaler's real responses
instead of the fake tenant's guesses.

  pov-kit record on        every API call this POV makes is saved to recordings/<date>.jsonl in the POV folder:
                           the call, its arguments and the response, with secrets masked and the customer's names
                           and emails replaced (the diagnostics redactor). It stays on the laptop.
  pov-kit record export    turns the recordings into one fixture for the repository: tests/fixtures/<name>.jsonl. The
                           export keeps every field name and value type and Zscaler's own values (enums, numbers,
                           booleans, the kit's own prefixed names) and replaces every other string, so no customer
                           data goes into the repository.

tests/test_replay.py then holds the kit to each fixture: every field the fake tenant answers with must exist in the
real response (so the kit can't depend on a field Zscaler doesn't send), and discovery and planning must run against
the recorded responses without crashing.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from .core.redact import Redactor

MAX_ITEMS = 25
SECRET = re.compile(r"(secret|password|token|provisioning_?key|^key$|api_?key|private|authorization|cookie)", re.I)
ENUM = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
ROOT = Path(__file__).resolve().parent.parent


def enabled(pov):
    return bool(pov.cfg.get("record"))


def _redactor(pov):
    from . import products
    snap = (pov.read_json("discovery.json", {}) or {}).get("products") or {}
    names = {pov.cfg.get("customer") or "", pov.cfg.get("pilot_group") or ""}
    for p in products.selected(pov.products):
        if p.name in snap:
            try:
                names |= p.customer_names(snap[p.name])
            except Exception:
                pass
    return Redactor(names, pov.prefix)


def _trim(o, depth=0):
    if depth > 10:
        return "…"
    if isinstance(o, list):
        return [_trim(x, depth + 1) for x in o[:MAX_ITEMS]]
    if isinstance(o, dict):
        return {k: _trim(v, depth + 1) for k, v in o.items()}
    return o


def unsecret(o):
    if isinstance(o, dict):
        return {k: ("<secret>" if SECRET.search(str(k)) and v else unsecret(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [unsecret(x) for x in o]
    return o


def write(pov, resource, method, a, kw, out=None, error=None):
    """Called by Tenant.call when recording is on. Best effort: never breaks the call it records."""
    try:
        red = _redactor(pov)
        rec = {"t": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "resource": resource, "method": method,
               "args": red(unsecret(_trim(list(a)))), "kwargs": red(unsecret(_trim(kw))),
               "response": red(unsecret(_trim(out))) if error is None else None, "error": str(error)[:300] if error else None}
        d = pov.path("recordings")
        d.mkdir(exist_ok=True)
        with (d / f"{time.strftime('%Y-%m-%d', time.gmtime())}.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except Exception:
        pass


def shape(o, prefix, key=None):
    """Keep structure, field names, types and Zscaler's own values; replace every other string."""
    if isinstance(o, dict):
        return {k: ("<secret>" if SECRET.search(str(k)) else shape(v, prefix, k)) for k, v in o.items()}
    if isinstance(o, list):
        return [shape(x, prefix, key) for x in o]
    if isinstance(o, str):
        if ENUM.match(o) or o.startswith((prefix + ":", prefix + " -", "zpov:", "{ref:")) or o in ("", "…"):
            return o
        if re.fullmatch(r"\d+", o):
            return o
        return "<str>"
    return o


def export(pov, name, out_dir=None):
    d = pov.path("recordings")
    files = sorted(d.glob("*.jsonl")) if d.exists() else []
    if not files:
        from .core import KitError
        raise KitError("No recordings yet. `pov-kit record on`, then run discover, plan, apply, status and teardown.")
    out_dir = Path(out_dir) if out_dir else ROOT / "tests" / "fixtures"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{re.sub(r'[^a-z0-9-]+', '-', name.lower()).strip('-')}.jsonl"
    seen, n = set(), 0
    with out.open("w", encoding="utf-8") as f:
        for src in files:
            for line in src.read_text(encoding="utf-8").splitlines():
                rec = json.loads(line)
                sig = (rec["resource"], rec["method"], json.dumps(shape(rec.get("response"), pov.prefix), sort_keys=True))
                if sig in seen:
                    continue
                seen.add(sig)
                f.write(json.dumps({"resource": rec["resource"], "method": rec["method"],
                                    "args": shape(rec["args"], pov.prefix), "kwargs": shape(rec["kwargs"], pov.prefix),
                                    "response": shape(rec.get("response"), pov.prefix),
                                    "error": "<error>" if rec.get("error") else None}) + "\n")
                n += 1
    return out, n
