"""Competitive land mines: vendor-neutral success criteria where the Zscaler platform stands apart, each one a test.

competitive.json holds, per differentiator: a title, `why` and `ask` (customer-facing, never naming a vendor), the
criteria that prove it, and `se` notes per competitor that are for the SE only, drafted from public positioning and
NOT verified. Those notes go to the console's SE view only: never the report, the vendor sheet, exports or anything
sent to Claude.

- bake-off pack: the differentiators' criteria for this POV's products, proposed at scoping (added to the POV)
- the vendor sheet: "ask every vendor to show this", for the customer to keep (neutral)
- badges: which criteria are differentiators, with the one-line why
- the report's "Where Zscaler stood apart": each differentiator and how its criteria came out
"""
from __future__ import annotations

import html
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent / "competitive.json"


def load():
    return json.loads(DATA.read_text(encoding="utf-8"))


def _catalog(pov):
    from .products import base
    return {c["id"]: c for c in base.load_catalog() if c["product"] in pov.products}


def for_pov(pov):
    """The differentiators this POV's products can prove, each with its criteria (id, title, lab_check)."""
    cat = _catalog(pov)
    out = []
    for d in load()["differentiators"]:
        crit = [{"id": c, "title": cat[c]["title"], "lab_check": cat[c].get("lab_check")} for c in d["criteria"] if c in cat]
        if crit:
            out.append({"id": d["id"], "title": d["title"], "why": d["why"], "ask": d["ask"], "criteria": crit})
    return out


def badges(pov):
    """{criterion id: {"id", "title", "why"}}: the differentiator each criterion helps prove (customer-safe)."""
    out = {}
    for d in for_pov(pov):
        for c in d["criteria"]:
            out.setdefault(c["id"], {"id": d["id"], "title": d["title"], "why": d["why"]})
    return out


def pack_ids(pov):
    return [c["id"] for d in for_pov(pov) for c in d["criteria"]]


def add_pack(pov):
    """Adds the bake-off pack to the POV's criteria (keeping the ones it has). -> the ids added"""
    from . import evidence, settings
    have = [c["id"] for c in evidence.selected_criteria(pov) if not c.get("usecase")]
    new = [c for c in dict.fromkeys(pack_ids(pov)) if c not in have]
    if new:
        settings.set_value(pov, "criteria", have + new)
        pov.log("criteria", f"bake-off pack added: {', '.join(new)}")
    return new


def se_view(pov):
    """For the SE only: the differentiators with competitor notes (draft, unverified) and lab checks."""
    d = load()
    notes = {x["id"]: x["se"] for x in d["differentiators"]}
    return {"status": d["se_status"], "vendors": d["vendors"],
            "differentiators": [dict(x, se=notes[x["id"]]) for x in for_pov(pov)]}


def sheet_html(pov):
    """The vendor-neutral evaluation sheet: what to ask every vendor to show, live, in the customer's tenant."""
    e = html.escape
    rows = "".join(
        f"<section><h2>{i}. {e(d['title'])}</h2><p class='why'>{e(d['why'])}</p>"
        f"<p><b>Ask every vendor to show:</b> {e(d['ask'])}</p><ul>"
        + "".join(f"<li><code>{e(c['id'])}</code> {e(c['title'])}</li>" for c in d["criteria"])
        + "</ul><p class='score'>Vendor A ☐ shown ☐ not shown &nbsp; Vendor B ☐ shown ☐ not shown &nbsp; Vendor C ☐ shown ☐ not shown</p></section>"
        for i, d in enumerate(for_pov(pov), 1))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Evaluation criteria: {e(pov.cfg['customer'])}</title><style>
body{{font:15px/1.5 -apple-system,Segoe UI,Arial,sans-serif;color:#14213d;background:#fbfbf8;max-width:860px;margin:32px auto;padding:0 16px}}
h1{{font-size:26px;margin:0 0 4px}}h2{{font-size:18px;margin:22px 0 4px}}.why{{color:#4a5568;margin:0 0 6px}}
section{{border-top:1px solid #d9dfe8;padding-top:6px}}.score{{color:#4a5568;font-size:14px}}code{{font-size:13px}}
@media print{{body{{margin:0}}}}</style></head><body>
<h1>Security platform evaluation: what to see working</h1>
<p class="why">For {e(pov.cfg['customer'])}'s evaluation. Each item is a live test in your own tenant, on your own pilot users and
devices, with an expected result. Ask every vendor to show each one the same way, and score what you saw.</p>
{rows}</body></html>"""


def report_section(pov, rows):
    """The report's neutral section: each differentiator and how its criteria came out (rows from evidence.evaluate)."""
    by = {r["criterion"]["id"]: r for r in rows}
    out = []
    for d in for_pov(pov):
        got = [by[c["id"]] for c in d["criteria"] if c["id"] in by]
        if not got:
            continue
        out.append({"title": d["title"], "why": d["why"], "passed": sum(1 for r in got if r["status"] == "pass"),
                    "total": len(got), "criteria": [(r["criterion"]["id"], r["criterion"]["title"], r["status"]) for r in got]})
    return out
