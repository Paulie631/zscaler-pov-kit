"""The POV checklist: what's done, what's next, and how to get there, worked out from the POV's own records.

Every POV shows it as a bar under the tabs ("4 of 11 · Next: Sign off the change list"). In a lab tenant (the POV's
lab setting) it becomes a **rehearsal**: the SE runs the whole path end to end before a customer, the checklist adds
the pieces that are easiest to get wrong in the field (self-test, backups, the Claude Desktop connectors, a pilot device,
the traffic generator, teardown), and the SE marks each step "worked" or "problem" with a note. The rehearsal report
(Markdown) collects that, so the kit's owner learns what breaks.
"""
from __future__ import annotations

import time

from . import evidence, lifecycle
from .core.changelist import ChangeList

REHEARSAL = "rehearsal.json"


def _manual(pov, stage):
    try:
        from . import manual
        st = manual.stage(pov, stage)
        return st.get("open", 0), len(st.get("steps") or [])
    except Exception:   # noqa: BLE001
        return 0, 0


def steps(pov):
    """[{id, title, done, detail, go, rehearsal}] in order. go: the console action that takes you there."""
    cfg, prods = pov.cfg, set(pov.products)
    led = lifecycle.ledger(pov)
    cl = ChangeList(pov.dir)
    plan = cl.plan() if cl.plan_file.exists() else None
    appr = cl.approval()
    applied = bool(led.active()) or cfg.get("state") in ("applied", "handed_over", "torn_down")
    lab = cfg.get("lab") == "yes"
    from .core import secrets
    slot = "main" if cfg.get("client_mode", "single") == "single" else "discovery"
    out = []

    def add(sid, title, done, detail="", go=None, rehearsal=False):
        out.append({"id": sid, "title": title, "done": bool(done), "detail": detail, "go": go, "rehearsal": rehearsal})

    add("connect", "Connect to the tenant", secrets.get(pov.id, f"{slot}-client-secret"),
        "The API client from the role spec, saved in the keychain.", "step:1")
    pilot = cfg.get("pilot_group") or cfg.get("pilot_emails") or (cfg.get("identity") or {}).get("pilot")
    add("pilot", "Choose who tests", pilot or prods <= {"aiguard"}, "A pilot group, named people or test accounts.",
        "step:2")
    if (cfg.get("approval") or "se") == "se":   # the SE applies directly: one step, signed off as it applies
        add("apply", "Apply to the tenant", applied, "Shows what the kit will make, then makes it (pilot users only); "
            "each object is recorded so teardown removes exactly them.", "step:4")
    else:
        add("plan", "Make the change list", plan, "Everything the kit will create, from a read-only look at the "
            "tenant.", "step:4")
        add("signoff", "Customer signs off the change list", appr and plan and appr.get("hash") == plan["hash"],
            "The customer approves this exact list; Apply refuses anything else.", "step:5")
        add("apply", "Apply", applied, "Creates the POV's objects, each recorded so teardown removes exactly them.",
            "step:6")
    o, t = _manual(pov, "finish")
    add("finish", "Finish setup (steps for people)", applied and o == 0,
        f"{t - o} of {t} done" if t else "Nothing for people to do after Apply.", "step:7")
    rows = evidence.evaluate(pov) if applied else []
    if prods & {"zia", "zcc", "zpa", "zdx", "eai"}:
        runs = evidence.probe_runs(pov)
        add("device", "Run the tests on a pilot device", runs,
            f"{len(runs)} probe run(s) imported" if runs else "Set up a pilot device, run pov-probe test, import the file.",
            "step:7")
    if "aiguard" in prods:
        from . import aiguard_calibrate as cal
        m = cal.summary(pov=pov)
        ran = any(v.get("source") == "test runner" for v in (pov.read_json("api_proofs.json", {}) or {}).values())
        add("aiguard", "Run the AI Guard tests", ran,
            (f"Tests checked in this tenant: {m['ok']} as written, {m['rewritten']} reworded, {m['swapped']} swapped"
             + (f", {m['missed']} won't trigger" if m["missed"] else "") if sum(m.values()) else
             "The runner checks each test triggers its detectors, then runs them."), "tab:aiguard")
    if rows:
        inc = [r["criterion"]["id"] for r in rows if r["status"] == "incomplete"]
        ok = sum(r["status"] == "pass" for r in rows)
        add("criteria", "Prove the success criteria", not inc,
            f"{ok} of {len(rows)} proved" + (f"; waiting on {', '.join(inc[:4])}" if inc else ""), "tab:criteria")
    else:
        add("criteria", "Prove the success criteria", False, "After Apply.", "tab:criteria")
    try:
        from . import execsum
        s, stale = execsum.current(pov)
    except Exception:   # noqa: BLE001
        s, stale = None, False
    add("summary", "Draft the executive summary", s and not stale,
        "Drafted, but the results changed since" if stale else "Customer and internal versions.", "tab:handover")

    if lab:   # the rehearsal adds what's easiest to get wrong in the field
        st = pov.read_json("selftest.json") or {}
        add("r-selftest", "Self-test passes", st.get("ok"), "Creates and deletes test objects in your lab tenant.",
            "tab:logs", True)
        add("r-backup", "Backups are on", (cfg.get("backup") or {}).get("at"), "So a lost laptop doesn't strand a POV.",
            "tab:status", True)
        m = cfg.get("mcp") or {}
        add("r-mcp", "Claude Desktop: Ask Claude connector works", m.get("installed"),
            "Install it, restart Claude Desktop, ask it something about the tenant.", "step:8", True)
        add("r-actions", "Claude Desktop: Claude can propose a change", m.get("actions_installed"),
            "Install it (Advanced view), ask Claude for a change, see it land in the change list.", "step:8", True)
        mark = marks(pov)
        if prods & {"zia", "zcc"}:
            add("r-traffic", "Traffic generator fills the dashboards", mark.get("r-traffic", {}).get("ok"),
                "On a pilot device or CloudShare: pov-probe traffic run, then check Insights.", "step:8", True)
    add("handover", "Hand over or tear down", cfg.get("state") in ("handed_over", "torn_down"),
        "Before the end date: export to Terraform, or remove the POV.", "tab:handover")
    for x in out:   # in a rehearsal, what the SE said about each step
        if lab and x["id"] in (mk := marks(pov)):
            x["mark"] = mk[x["id"]]
    return out


def summary(pov):
    s = steps(pov)
    nxt = next((x for x in s if not x["done"]), None)
    return {"steps": s, "done": sum(x["done"] for x in s), "total": len(s), "next": nxt,
            "rehearsal": pov.cfg.get("lab") == "yes"}


# ---------------------------------------------------------------- rehearsal notes
def marks(pov):
    return (pov.read_json(REHEARSAL, {}) or {}).get("marks") or {}


def mark(pov, sid, ok, note=""):
    r = pov.read_json(REHEARSAL, {}) or {}
    r.setdefault("marks", {})[sid] = {"ok": bool(ok), "note": str(note or "")[:1000],
                                      "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    pov.write_json(REHEARSAL, r)
    pov.log("rehearsal", f"{sid}: {'worked' if ok else 'problem'}" + (f" ({note[:80]})" if note else ""))
    return r["marks"][sid]


def report_md(pov):
    from . import VERSION
    s = summary(pov)
    lines = [f"# POV kit rehearsal: {pov.id}", "",
             f"Kit {VERSION} · products: {', '.join(pov.products)} · {time.strftime('%Y-%m-%d')}", "",
             f"{s['done']} of {s['total']} steps done.", "", "| Step | Done | SE's verdict | Note |", "|---|---|---|---|"]
    for x in s["steps"]:
        m = x.get("mark") or {}
        verdict = "" if not m else ("worked" if m["ok"] else "**problem**")
        lines.append(f"| {x['title']} | {'yes' if x['done'] else 'no'} | {verdict} | "
                     f"{(m.get('note') or '').replace('|', '/')} |")
    lines += ["", "No customer data: step names, states and the SE's own notes only."]
    return "\n".join(lines) + "\n"
