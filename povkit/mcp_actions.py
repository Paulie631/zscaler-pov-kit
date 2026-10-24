"""Claude Desktop making changes to the POV, through the kit (never straight to the tenant).

The read-only connector (mcp.py) lets Claude Desktop read the customer's tenant through Zscaler's MCP server. This
second connector, `pov-kit --pov <id> mcp actions`, lets Claude Desktop *act* on the POV, with the same rules as the
console:

  propose_change       a use case Claude writes in the kit's format: the kit validates every value against the
                       tenant's snapshot, names it, scopes it to the pilot group and adds it to the change list.
                       Nothing is built until the customer approves the new change list and the SE clicks Apply in
                       the console. Claude can't apply.
  set_aiguard_policy   switch the POV's own AI Guard policy (an approved POV object)
  run_aiguard_tests    the test runner on the POV's AI Guard criteria; results count as evidence
  run_api_proofs       the automated API proofs (read-only)
  check_status         drift and safety checks (read-only); fix_drift repairs only the POV's own objects
  steps_for_people     what a person still has to do in the console, and check_step for one of them
  pov_overview, tenant_snapshot, list_changes    reads

It needs two recorded agreements from the customer: the read-only one (Claude Desktop sends what it reads to
Anthropic, not through AI Guard, with names as they are), and a second one for making changes this way. It speaks
MCP over stdio (JSON-RPC 2.0, one message per line) with no extra package. Every action is logged as done by Claude
Desktop.
"""
from __future__ import annotations

import json
import sys
import time
import traceback

from . import VERSION
from .core import KitError

PROTOCOL = "2025-06-18"


def actions_consent(pov):
    return (pov.cfg.get("mcp") or {}).get("actions_consent")


def record_actions_consent(pov, by):
    by = (by or "").strip()
    if not by:
        raise KitError("Say who at the customer agreed (name and title).")
    pov.cfg.setdefault("mcp", {})["actions_consent"] = {"by": by, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    pov.save()
    pov.log("mcp", f"customer agreed that Claude Desktop may propose changes and run POV actions ({by})")


def ready(pov):
    from . import mcp
    if not mcp.consent(pov):
        raise KitError("The customer hasn't agreed to Claude Desktop reading the tenant yet (Next steps > Ask Claude "
                       "about this tenant).")
    if not actions_consent(pov):
        raise KitError("The customer hasn't agreed to Claude Desktop making changes through the change list yet "
                       "(Next steps > Ask Claude about this tenant > Let Claude make changes).")


def _tf():
    from .cli import tenant_for
    return tenant_for


# ---------------------------------------------------------------- the tools
def t_overview(pov, a):
    from . import evidence, manual
    from .core.changelist import ChangeList
    cl = ChangeList(pov.dir)
    plan = cl.plan() if cl.plan_file.exists() else None
    appr = cl.approval()
    rows = evidence.evaluate(pov)
    count = {}
    for r in rows:
        count[r["status"]] = count.get(r["status"], 0) + 1
    steps = [{"key": s["key"], "title": s["title"], "status": s["status"]} for s in manual.guide(pov)
             if s["status"] != "done" and s["phase"] != "end"]
    return {"customer": pov.cfg.get("customer"), "pov": pov.id, "products": pov.products,
            "state": pov.cfg.get("state"), "prefix": pov.prefix, "pilot_group": pov.cfg.get("pilot_group"),
            "change_list": {"items": len(plan["items"]), "approved": bool(appr and appr.get("hash") == plan["hash"])}
            if plan else None,
            "criteria": count, "not_passing": [{"id": r["criterion"]["id"], "title": r["criterion"]["title"],
                                                "status": r["status"]} for r in rows if r["status"] != "pass"][:40],
            "steps_for_people_open": steps}


def t_snapshot(pov, a):
    from . import lifecycle
    if a.get("refresh"):
        snaps, _ = lifecycle.discover(pov, _tf())
    else:
        snaps = (pov.read_json("discovery.json", {}) or {}).get("products") or {}
        if not snaps:
            snaps, _ = lifecycle.discover(pov, _tf())
    prod = a.get("product")
    if prod:
        if prod not in snaps:
            raise KitError(f"No snapshot for {prod}. Products in it: {', '.join(k for k in snaps if not k.startswith('_'))}.")
        snaps = {prod: snaps[prod]}
    text = json.dumps(snaps, default=str, ensure_ascii=False)
    return text[:150_000] + (" ...(cut)" if len(text) > 150_000 else "")


def t_propose(pov, a):
    from . import lifecycle, usecases
    proposal = a.get("proposal") or {}
    request = str(a.get("use_case") or proposal.get("summary") or "").strip()
    if not request:
        raise KitError("Give the use case in words (use_case).")
    snaps, _ = lifecycle.discover(pov, _tf())
    spec = usecases.validate(pov, snaps, proposal)
    ucs = usecases.load(pov)
    uc = {"id": usecases.next_id(ucs), "prompt": request[:2000], "by": "Claude Desktop",
          "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "status": "proposed", "spec": spec,
          "shared": "full", "masked": 0, "raw": json.dumps(proposal)[:20000], "history": [], "via": "claude-desktop"}
    ucs.append(uc)
    usecases.save(pov, ucs)
    usecases.set_status(pov, uc["id"], "accepted" if spec["changes"] else "directions")
    pov.log("usecase", f"{uc['id']} proposed by Claude Desktop: {len(spec['changes'])} changes, "
                       f"{len(spec['directions'])} directions")
    return {"id": uc["id"], "added_to_change_list": [{"kind": c["kind"], "name": c["name"]} for c in spec["changes"]],
            "directions_for_a_person": spec["directions"], "test": spec["test"],
            "next": ("The change list now has these changes. The customer approves the new change list in the POV "
                     "console (Setup > Change list, then Approval), and the SE clicks Apply there. Nothing is in the "
                     "tenant yet." if spec["changes"] else
                     "Nothing for the kit to build: the directions are steps for a person, and the test proves it.")}


def t_list(pov, a):
    from . import usecases
    return [{"id": u["id"], "status": u["status"], "by": u.get("by"), "use_case": u["prompt"][:200],
             "changes": [c["name"] for c in u["spec"]["changes"]]} for u in usecases.load(pov)]


def t_withdraw(pov, a):
    from . import lifecycle, usecases
    uid = a.get("id")
    led = lifecycle.ledger(pov)
    try:
        n = int(str(uid).split("-")[-1])
    except ValueError as e:
        raise KitError(f"No use case {uid}.") from e
    if any(f".uc{n:02d}." in e.get("key", "") for e in led.active()):
        raise KitError(f"{uid} is built in the tenant already: remove it in the console (Handover), not from here.")
    usecases.set_status(pov, uid, "discarded")
    pov.log("usecase", f"{uid} withdrawn by Claude Desktop")
    return f"{uid} withdrawn; the change list no longer has it."


def t_policy(pov, a):
    from . import lifecycle, products
    from .core.guard import LedgerTenant
    prof = a.get("profile")
    led = lifecycle.ledger(pov)
    out = []
    products.get("aiguard").set_profile(LedgerTenant(_tf()(pov, "apply"), led, []), pov, led, prof,
                                        lambda lv, m: out.append(m))
    pov.cfg.setdefault("aiguard", {})["profile"] = prof
    pov.save()
    pov.log("aiguard", f"POV policy set to {prof} by Claude Desktop")
    return " ".join(out) or f"POV AI Guard policy: {prof} (takes about 30 seconds)."


def t_tests(pov, a):
    from . import aiguard_runner as ar
    groups = ar.pov_criteria(pov)
    want = a.get("criteria") or [g["criterion"] for g in groups]
    tests = [t for g in groups if g["criterion"] in want for t in g["tests"]]
    if not tests:
        raise KitError("No AI Guard tests for those criteria. This POV's: " + ", ".join(g["criterion"] for g in groups))
    mode = "proxy" if a.get("mode") == "proxy" else "detect"
    res = ar.run(pov, tests, mode, tags=bool(a.get("tags", True)), rounds=1)
    ev = ar.record_evidence(pov, res)
    ok = [r for r in res if r.get("status") == "ok"]
    return {"scans": len(res), "blocked": sum(r.get("action") == "BLOCK" for r in ok),
            "not_as_expected": [{"criterion": r.get("criterion"), "test": r["name"], "missed": r.get("missed")}
                                for r in ok if r.get("pass") is False][:20],
            "errors": [r.get("error") for r in res if r.get("status") == "error"][:5],
            "evidence": {k: v["status"] + ": " + v["detail"] for k, v in ev.items()}}


def t_proofs(pov, a):
    from . import lifecycle
    ran = lifecycle.api_proofs(pov, _tf(), a.get("criteria") or None)
    return {k: f"{v['status']}: {v.get('detail', '')}" for k, v in ran.items()}


def t_status(pov, a, fix=False):
    from . import lifecycle
    checks = lifecycle.status(pov, _tf(), fix=fix)
    if fix:
        pov.log("status", "Fix drift run by Claude Desktop")
    return [{"check": c["label"], "status": c["status"], "detail": c.get("detail", ""), "fix": c.get("fix", "")}
            for c in checks if c["status"] != "ok" or fix]


def t_steps(pov, a):
    from . import manual
    return [{"key": s["key"], "title": s["title"], "who": s.get("who"), "status": s["status"], "stage": s["stage"],
             "steps": s.get("steps"), "values": s.get("values"), "holds_up": s.get("criteria")}
            for s in manual.guide(pov) if s["status"] != "done"]


def t_check_step(pov, a):
    from . import manual
    return manual.check(pov, a.get("key"), _tf())


def _propose_schema():
    from . import usecases
    s = json.loads(json.dumps(usecases.TOOL["input_schema"]))
    return {"type": "object", "required": ["use_case", "proposal"], "properties": {
        "use_case": {"type": "string", "description": "What the customer wants to see, in plain words."},
        "proposal": s}}


def tools():
    from . import usecases
    P = lambda **k: {"type": "object", "properties": k}   # noqa: E731
    return [
        ("pov_overview", "The POV at a glance: products, the change list and its approval, success criteria results, "
         "and the steps people still have to do. Read-only.", P(), t_overview),
        ("tenant_snapshot", "The read-only discovery snapshot of the customer's tenant, for one product (zia, zpa, "
         "aiguard, zdx, casb, zcc, identity) or all. Use its values in propose_change. refresh=true reads the tenant "
         "again.", P(product={"type": "string"}, refresh={"type": "boolean"}), t_snapshot),
        ("propose_change", "Make a change to the POV: describe a use case and propose how to prove it, in the kit's "
         "format. The kit checks every value against the tenant, names and scopes each object to the pilot group, "
         "and adds it to the change list. Nothing reaches the tenant until the customer approves the new change "
         "list and the SE clicks Apply in the POV console. Rules for the proposal:\n" + usecases.SYSTEM,
         _propose_schema(), t_propose),
        ("list_changes", "The use cases proposed so far (by the SE or Claude) and their status.", P(), t_list),
        ("withdraw_change", "Take a proposed use case (UC-..) out of the change list, if it isn't built yet.",
         P(id={"type": "string"}), t_withdraw),
        ("set_aiguard_policy", "Switch the POV's own AI Guard policy: monitor (log only), attacks (block attacks), "
         "data (block attacks and data leakage) or everything. Only the POV's policy changes; ~30 s to apply.",
         P(profile={"type": "string", "enum": ["monitor", "attacks", "data", "everything"]}), t_policy),
        ("run_aiguard_tests", "Run the POV's AI Guard criterion tests (all, or the criteria given) through the "
         "Detection API (mode detect) or the model through AI Guard (mode proxy, needs proxy set up). Results count "
         "as evidence for those criteria.", P(criteria={"type": "array", "items": {"type": "string"}},
                                              mode={"type": "string", "enum": ["detect", "proxy"]}), t_tests),
        ("run_api_proofs", "Run the automated API proofs (read-only) for all criteria or the ones given.",
         P(criteria={"type": "array", "items": {"type": "string"}}), t_proofs),
        ("check_status", "Drift and safety checks of the POV's objects (read-only): what isn't OK.", P(),
         lambda p, a: t_status(p, a)),
        ("fix_drift", "Repair the POV's own objects that drifted (missing, disabled, rescoped). Never touches the "
         "customer's objects.", P(), lambda p, a: t_status(p, a, fix=True)),
        ("steps_for_people", "What a person still has to do in the Zscaler console, with instructions and values.",
         P(), t_steps),
        ("check_step", "Check one step for people (by key) through the API, read-only.", P(key={"type": "string"}),
         t_check_step),
    ]


# ---------------------------------------------------------------- MCP over stdio
def handle(pov, msg, table):
    mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if mid is None:
        return None   # a notification
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": params.get("protocolVersion") or PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": f"zscaler-pov-{pov.id}-actions", "version": VERSION},
            "instructions": (f"Zscaler POV {pov.id} for {pov.cfg.get('customer')}. Changes go through the change list: "
                             "propose_change adds them, the customer approves and the SE applies in the POV console. "
                             "Start with pov_overview.")}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": [
            {"name": n, "description": d, "inputSchema": s} for n, (d, s, _) in table.items()]}}
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        if name not in table:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"No tool {name}"}}
        try:
            ready(pov)
            out = table[name][2](pov, args)
            text = out if isinstance(out, str) else json.dumps(out, default=str, ensure_ascii=False, indent=1)
            pov.log("mcp", f"Claude Desktop: {name}")
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": text}],
                                                            "isError": False}}
        except KitError as e:
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": str(e)}],
                                                            "isError": True}}
        except Exception as e:   # noqa: BLE001 - report, keep serving
            print(traceback.format_exc(), file=sys.stderr)
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text",
                                                                        "text": f"{type(e).__name__}: {e}"}],
                                                            "isError": True}}
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Unknown method {method}"}}


def serve(pov, stdin=None, stdout=None):
    ready(pov)
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    table = {n: (d, s, f) for n, d, s, f in tools()}
    print(f"pov-kit: POV actions for {pov.id} (changes go through the change list)", file=sys.stderr)
    pov.log("mcp", "Claude Desktop actions connector started")
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        reply = handle(pov, msg, table)
        if reply is not None:
            stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            stdout.flush()
    return 0
