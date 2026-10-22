"""A diagnostics zip for the kit owner: no secrets, and none of the customer's own object names or policy."""
from __future__ import annotations

import io
import json
import platform
import sys
import zipfile

from . import VERSION, products
from .core.redact import Redactor, mask

LOG_LINES = 5000


def build(pov) -> bytes:
    snap = (pov.read_json("discovery.json", {}) or {}).get("products", {})
    names = set()
    for p in products.selected(pov.products):
        if p.name in snap:
            names |= p.customer_names(snap[p.name])
    red = Redactor(names, pov.prefix)
    ledger = pov.read_json("ledger.json", {"entries": []})
    states = {}
    for e in ledger["entries"]:
        states[e["state"]] = states.get(e["state"], 0) + 1
    plan = pov.read_json("plan.json", {}) or {}
    about = {"kit": VERSION, "os": platform.platform(), "python": sys.version.split()[0], "pov": pov.id,
             "products": pov.products, "state": pov.cfg.get("state"), "prefix": pov.prefix,
             "placement": pov.cfg.get("placement"),
             "clients": {k: mask((v or {}).get("client_id", "")) for k, v in (pov.cfg.get("clients") or {}).items()},
             "ledger": states, "plan": {"hash": (plan.get("hash") or "")[:12], "items": len(plan.get("items", []))},
             "approved": bool(pov.read_json("approval.json"))}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("about.json", json.dumps(about, indent=2))
        z.writestr("ledger.json", json.dumps(red(ledger), indent=2))   # the POV's own objects only
        log = pov.path("activity.jsonl")
        if log.exists():
            lines = log.read_text(encoding="utf-8", errors="replace").splitlines()[-LOG_LINES:]
            out = []
            for line in lines:
                try:
                    out.append(json.dumps(red(json.loads(line))))
                except ValueError:
                    out.append(json.dumps({"unparsed": red.text(line)}))
            z.writestr("activity.jsonl", "\n".join(out) + "\n")
    return buf.getvalue()
