"""An executive summary of the POV, written by Claude (through AI Guard) from the results alone.

What goes to Claude: each criterion's ID, title, product, result, and the proofs' short details, with the
customer's names and emails taken out (the same redactor as the diagnostics zip), plus the products and dates.
No discovery snapshot, no policy, no customer name: the summary says "the customer" and the report adds the name.
Because none of the tenant's data goes, this doesn't need the use-case agreement; it does need the AI Guard proxy key.

The summary is saved in the POV (summary.json) and opens the evidence report. An SE edits it by asking again with
a note ("lead with the ZPA results"), or by not using it.
"""
from __future__ import annotations

import json
import time

from . import ai, evidence, products
from .core import KitError
from .core.redact import Redactor

SYSTEM = """You write the executive summary that opens a Zscaler proof-of-value (POV) report for the customer's
leadership. You get the POV's success criteria and their results. Be plain and specific; never overstate: a
criterion that is incomplete or failed is not proved. Don't invent numbers, products or results. Say "the customer",
not a name. Call the write_summary tool with:
  headline: one sentence, what the POV showed overall
  proved: up to 6 short bullets, each naming what was shown to work (cite criterion IDs in brackets)
  open: what is not proved yet or failed, and what it would take (cite IDs); [] if nothing
  value: up to 4 bullets on what this means for the business (risk reduced, effort saved), only where the results
         support it
  next_steps: up to 4 bullets, starting with how to finish the POV (handover: teardown or the Terraform export)"""

TOOL = {"name": "write_summary", "description": "The POV report's executive summary.",
        "input_schema": {"type": "object", "required": ["headline", "proved", "open", "value", "next_steps"],
                         "properties": {k: ({"type": "string"} if k == "headline" else
                                            {"type": "array", "items": {"type": "string"}})
                                        for k in ("headline", "proved", "open", "value", "next_steps")}}}


def facts(pov):
    snap = (pov.read_json("discovery.json", {}) or {}).get("products") or {}
    names = {pov.cfg.get("customer") or "", pov.cfg.get("pilot_group") or "", pov.cfg.get("vanity_domain") or ""}
    for p in products.selected(pov.products):
        if p.name in snap:
            names |= p.customer_names(snap[p.name])
    red = Redactor(names, pov.prefix)
    rows = evidence.evaluate(pov)
    return {"products": [products.get(p).title for p in pov.products],
            "started": pov.cfg.get("created", "")[:10], "ends": pov.cfg.get("ends"),
            "criteria": [{"id": r["criterion"]["id"], "title": red.text(r["criterion"]["title"]),
                          "product": r["criterion"]["product"], "result": r["status"],
                          "proofs": {k: red.text(v.get("detail") or v.get("status")) for k, v in r["proofs"].items()}}
                         for r in rows]}


def write(pov, note=""):
    f = facts(pov)
    if not f["criteria"]:
        raise KitError("No criteria to summarize yet.")
    msg = "POV results (JSON):\n" + json.dumps(f) + (f"\n\nThe SE asks: {note.strip()}" if note.strip() else "")
    used, text = ai.ask(pov, SYSTEM, msg, max_tokens=2000, tool=TOOL, needs_consent=False)
    if used is None:
        from .usecases import parse
        used = parse(text)
    clean = {"headline": str(used.get("headline") or "")[:400]}
    for k in ("proved", "open", "value", "next_steps"):
        clean[k] = [str(x)[:400] for x in (used.get(k) or [])][:6]
    out = dict(clean, at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               results={c["id"]: c["result"] for c in f["criteria"]}, model=(pov.cfg.get("ai") or {}).get("model") or ai.DEFAULT_MODEL)
    pov.write_json("summary.json", out)
    pov.log("report", "executive summary written by Claude through AI Guard")
    return out


def current(pov):
    """The saved summary, and whether the results changed since it was written."""
    s = pov.read_json("summary.json")
    if not s:
        return None, False
    now = {r["criterion"]["id"]: r["status"] for r in evidence.evaluate(pov)}
    return s, now != s.get("results")
