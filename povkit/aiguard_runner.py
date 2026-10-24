"""The AI Guard tab: the demo kit's test runner, live prompt, customer prompt packs and one-page report, on the POV's
own AI Guard app, keys and policy (never the customer's).

  library(pov)            the demo kit's tests, presets, packs, guided stories, plus the customer's imported packs
  run(pov, tests, ...)    each test through the Detection API (or, in proxy mode, as a real prompt to the model through
                          AI Guard), as each of the chosen users, for N rounds; results to aiguard_runs.jsonl
  import_pack(pov, name, rows)
                          the customer's own prompts (CSV rows) as a pack, and as a success criterion (AI-AIG-Cn)
  report(pov)             a one-page summary of the runs: totals, detections by type, examples
Prompts in the library are synthetic; the customer's packs stay in the POV folder on this laptop.
"""
from __future__ import annotations

import html
import json
import re
import time
from collections import Counter
from pathlib import Path

from .core import KitError, secrets
from .products import aiguard as ag

LIB = json.loads((Path(ag.__file__).with_name("aiguard_library.json")).read_text(encoding="utf-8"))
RUNS = "aiguard_runs.jsonl"
PACKS = "aiguard_packs.json"
DRAFTS = "aiguard_drafts.json"   # tests Claude drafted for a criterion: {criterion: [test (status draft|accepted)]}
PANELS = {"pii": "Sensitive data (PII)", "pii_deepscan": "Sensitive data (PII)", "personal_data": "Sensitive data (PII)",
          "secrets": "Secrets", "prompt_injection": "Prompt injection", "toxicity": "Toxicity", "code": "Code",
          "language": "Languages", "prompt_tags": "Prompt classifications", "response_tags": "Response classifications",
          "competition": "Competition", "brand_and_reputation_risk": "Brand risk", "finance_advice": "Finance advice",
          "legal_advice": "Legal advice", "gibberish": "Gibberish", "invisible_text": "Invisible text",
          "malicious_url": "Malicious URL", "url_reachability": "URL reachability", "refusal": "Refusal"}


# ---------------------------------------------------------------- the library
def customer_packs(pov):
    return pov.read_json(PACKS, {}) or {}


def library(pov):
    packs = {k: {"name": v["name"], "description": v.get("description", ""), "tests": v["tests"], "customer": False}
             for k, v in LIB["packs"].items()}
    for k, v in customer_packs(pov).items():
        packs[k] = dict(v, customer=True)
    return {"groups": LIB["groups"], "presets": LIB["presets"], "users": LIB["users"], "tests": LIB["tests"],
            "packs": packs, "stories": LIB["stories"], "panels": PANELS}


# ---------------------------------------------------------------- the POV's own criteria, as runner groups
def drafts(pov):
    return pov.read_json(DRAFTS, {}) or {}


def accepted_drafts(pov, cid):
    return [t for t in drafts(pov).get(cid) or [] if t.get("status") == "accepted"]


def _expect(x):
    e = x.get("expect") or []
    return [e] if isinstance(e, str) else list(e)


def criterion_tests(pov, c, led=None):
    """A criterion's AI Guard tests, labelled with it: the catalog's proof tests, a use case's prompts, the customer's
    own prompts, plus tests Claude drafted that someone accepted. Each carries the key to scan with (a use case with
    its own AI Guard app uses that app's key)."""
    key_secret = None
    if c.get("customer_pack"):
        base = (customer_packs(pov).get(c.get("pack")) or {}).get("tests") or []
    elif c.get("usecase"):
        base = c.get("aiguard") or []
        from . import lifecycle
        from .usecases import aiguard_secret
        n = int(c["id"].split("-")[1]) if c["id"].split("-")[-1].isdigit() else 0
        own = next((e for e in (led or lifecycle.ledger(pov)).active("aiguard") if e["kind"] == "key"
                    and e["key"].startswith(f"aiguard.uc{n:02d}.")), None)
        key_secret = aiguard_secret(own["key"]) if own else None
    else:
        base = ag.PROOF_TESTS.get(c["id"]) or []
    base = list(base) + accepted_drafts(pov, c["id"])
    out = []
    for i, t in enumerate(base):
        x = {"id": f"pov:{c['id']}:{t.get('id') or i}", "name": t.get("name") or f"{c['id']} test {i + 1}",
             "group": c["id"], "category": c["title"], "criterion": c["id"], "direction": t.get("direction", "IN"),
             "text": t["text"], "expect": _expect(t), "drafted": bool(t.get("status"))}
        if key_secret:
            x["key_secret"] = key_secret
        out.append(x)
    return out


def pov_criteria(pov):
    """[{criterion, title, statement, tests}] for every AI Guard criterion this POV proves."""
    from . import evidence, lifecycle
    led = lifecycle.ledger(pov)
    out = []
    for c in evidence.selected_criteria(pov):
        if c.get("product") != "aiguard" and not c.get("aiguard"):
            continue
        out.append({"criterion": c["id"], "title": c["title"], "statement": c.get("statement", ""),
                    "tests": criterion_tests(pov, c, led), "drafts": [t for t in drafts(pov).get(c["id"]) or []
                                                                      if t.get("status") == "draft"]})
    return out


def find_tests(pov, ids=None, preset=None, pack=None):
    lib = library(pov)
    if pack:
        p = lib["packs"].get(pack)
        if not p:
            raise KitError(f"No pack {pack}.")
        return p["tests"]
    if ids:
        every = {t["id"]: t for t in lib["tests"]}
        for p in lib["packs"].values():
            every.update({t["id"]: t for t in p["tests"]})
        if any(str(i).startswith("pov:") for i in ids):
            every.update({t["id"]: t for g in pov_criteria(pov) for t in g["tests"]})
        return [every[i] for i in ids if i in every]
    if preset:
        pr = next((x for x in lib["presets"] if x["id"] == preset), None)
        if not pr:
            raise KitError(f"No preset {preset}.")
        return [t for t in lib["tests"] if t["group"] in pr["groups"]]
    return lib["tests"]


# ---------------------------------------------------------------- running tests on the POV's app
def proxy_keys(pov):
    """-> {provider: its POV proxy key} for each provider whose proxy key exists (made by Apply)."""
    from .usecases import aiguard_secret
    out = {}
    for pt, (kkey, _, _, _) in ag.PKEYS.items():
        k = secrets.get(pov.id, aiguard_secret(kkey))
        if k:
            out[pt] = k
    return out


def keys(pov):
    pk = proxy_keys(pov)
    return secrets.get(pov.id, ag.KEY_SECRET), next(iter(pk.values()), None)


def run_one(pov, test, user, mode="detect", tags=False, scan=None, chat=None, provider=None):
    """One test as `user`. Never raises: errors are in the result."""
    scan, chat = scan or ag.das_scan, chat or ag.proxy_chat
    competitor = (pov.cfg.get("aiguard") or {}).get("competitor") or "Competitor Inc"
    text = test["text"].replace("{_}", "").replace("{COMPETITOR}", competitor)
    expect = test.get("expect") or []
    expect = [expect] if isinstance(expect, str) else list(expect)
    res = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "id": test.get("id", "custom"),
           "name": test.get("name", "Custom prompt"), "group": test.get("group", "Custom"),
           "category": test.get("category", "Custom"), "direction": test.get("direction", "IN"), "user": user,
           "mode": mode, "expect": expect, "text": text[:2000]}
    if test.get("criterion"):
        res["criterion"] = test["criterion"]
    dkey, pkey = keys(pov)
    pkeys = proxy_keys(pov)
    if provider:
        pkey = pkeys.get(provider)
    if test.get("key_secret"):   # a use case's own AI Guard app
        dkey = secrets.get(pov.id, test["key_secret"]) or dkey
    try:
        if mode == "proxy":
            if not pkey:
                raise KitError("The POV has no proxy key yet: choose proxy mode in the AI Guard tab, then approve and "
                               "apply the change list.")
            if res["direction"] == "OUT":
                raise KitError("Model-reply tests run through the Detection API only.")
            setup = ag.proxy_setup(pov)
            ptype = provider or next((pt for pt in pkeys if pkeys[pt] == pkey), None) or ag.proxy_cfg(pov)[1]
            model = setup[ptype]["model"]
            res["provider"] = ptype
            reply, ms, blocked = chat(ptype, pkey, model, text, user=user)
            res.update(action="BLOCK" if blocked else "ALLOW", reply=reply[:800], latency_ms=ms, detectors=[])
            if tags and dkey:
                d = scan(dkey, text, "IN", user=user)
                res["detectors"] = ag.hits(d)
                res["tagged"] = True
                if not blocked and reply:
                    res["reply_detectors"] = ag.hits(scan(dkey, reply, "OUT", user=user))
        else:
            if not dkey:
                raise KitError("The POV has no AI Guard detection key yet: apply the change list first.")
            t0 = time.time()
            d = scan(dkey, text, res["direction"], user=user)
            res.update(action=d.get("action", ""), severity=d.get("severity", ""), detectors=ag.hits(d),
                       policy=d.get("policyName"), latency_ms=int((time.time() - t0) * 1000))
        res["missed"] = [e for e in expect if e not in res["detectors"]]
        res["status"] = "ok"
        res["pass"] = passed(res)
    except Exception as e:   # noqa: BLE001 - one failing test shouldn't stop a run
        res.update(status="error", error=str(e)[:300], detectors=[], missed=expect, action="")
    return res


def passed(res):
    """As expected: every expected detector triggered; with nothing expected, nothing harmful did. None when the
    detectors aren't known (proxy mode without detector tags)."""
    if res.get("status") != "ok" or (res.get("mode") == "proxy" and not res.get("tagged")):
        return None
    got = set(res.get("detectors") or [])
    return set(res["expect"]) <= got if res["expect"] else not (got & ag.HARMFUL)


def pov_users(pov):
    """Who the tests run as, so the POV's scans can be found in AI Guard Insights: the POV's pilot or test users,
    else names that carry the POV's ID."""
    try:
        from .device_setup import users
        named = users(pov)[:3]
    except Exception:   # noqa: BLE001
        named = []
    return named or [f"zpov-{pov.id}-tester{n}@pov.test" for n in (1, 2, 3)]


def run(pov, tests, mode="detect", tags=False, users=None, rounds=1, log=lambda *a: None, scan=None, chat=None,
        pause=0.2, on_result=None, stop=None, providers=None):
    """Runs the tests; each result goes to on_result as it lands. stop() is checked before each test, so Stop ends the
    run after the test in flight. -> results (a stopped run returns what ran)."""
    users = [u for u in (users or pov_users(pov)) if u] or ["pov-kit"]
    rounds = max(1, min(10, int(rounds or 1)))
    if mode == "proxy":
        tests = [t for t in tests if t.get("direction", "IN") == "IN"]
    if not tests:
        raise KitError("No tests to run.")
    if len(tests) * rounds > 500:
        raise KitError("That's more than 500 scans: pick fewer tests or rounds.")
    out = []
    f = pov.path(RUNS)
    n = 0
    for _ in range(rounds):
        for t in tests:
            if stop and stop():
                break
            prov = providers[n % len(providers)] if providers else None   # rotated, like the demo kit's apps
            res = run_one(pov, t, users[n % len(users)], mode, tags, scan, chat, provider=prov)
            n += 1
            out.append(res)
            if on_result:
                on_result(res)
            with open(f, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(res, ensure_ascii=False) + "\n")
            level = "fail" if res["status"] == "error" else "warn" if res["missed"] else "ok"
            log(level, f"{res['name']}: {res.get('action') or res.get('error', '')}"
                       + (f" · {', '.join(res['detectors'])}" if res["detectors"] else "")
                       + (f" · expected {', '.join(res['missed'])}" if res["missed"] else ""))
            if pause and (scan is None):
                time.sleep(pause)
        if stop and stop():
            break
    pov.log("aiguard", f"AI Guard test run: {len(out)} {mode} scans" + (" (stopped)" if stop and stop() else ""))
    return out


def record_evidence(pov, results, stopped=False):
    """Criterion-labelled results become that criterion's API proof (what Success criteria shows), like
    `pov-kit test --api`. Only results with known detectors count. A criterion whose tests didn't all run (a stopped
    or partial run) is incomplete unless one already failed. -> {criterion: proof}"""
    groups = {g["criterion"]: g for g in pov_criteria(pov)}
    by = {}
    for r in results:
        if r.get("criterion") in groups and r.get("pass") is not None:
            by.setdefault(r["criterion"], []).append(r)
    if not by:
        return {}
    saved = pov.read_json("api_proofs.json", {}) or {}
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out = {}
    for cid, rs in by.items():
        last = {}
        for r in rs:   # the latest result per test (rounds repeat them)
            last[r["id"]] = r
        rows = [{"test": r["name"], "expect": r["expect"], "detected": r["detectors"], "action": r.get("action"),
                 "pass": r["pass"], "user": r.get("user")} for r in last.values()]
        want = len(groups[cid]["tests"])
        bad = [x["test"] for x in rows if not x["pass"]]
        status = "fail" if bad else "pass" if len(rows) >= want else "incomplete"
        detail = (f"test runner{' (stopped)' if stopped else ''}: {len(rows) - len(bad)} of {len(rows)} as expected"
                  + (f"; {len(rows)} of {want} tests run" if len(rows) < want else "")
                  + (f"; not as expected: {', '.join(bad[:5])}" if bad else ""))
        saved[cid] = out[cid] = {"status": status, "detail": detail, "results": rows, "source": "test runner",
                                 "at": now, "partial": len(rows) < want}
    pov.write_json("api_proofs.json", saved)
    summary = ", ".join(f"{k} {v['status']}" for k, v in out.items())
    pov.log("test", f"AI Guard test runner evidence: {summary}")
    return out


# ---------------------------------------------------------------- Claude drafts more tests for a criterion
DRAFT_TOOL = {"name": "draft_tests", "description": "Draft AI Guard test prompts for one success criterion.",
              "input_schema": {"type": "object", "required": ["tests"], "properties": {"tests": {"type": "array",
                  "items": {"type": "object", "required": ["name", "text", "direction", "expect"], "properties": {
                      "name": {"type": "string"}, "text": {"type": "string"},
                      "direction": {"type": "string", "enum": ["IN", "OUT"]},
                      "expect": {"type": "array", "items": {"type": "string"}}}}}}}}
DRAFT_SYSTEM = """You write test prompts for Zscaler AI Guard, for one success criterion of a proof of value.
Each test is a prompt a user sends to an AI app (direction IN) or a reply the model gives (direction OUT), and the
AI Guard detectors that should trigger on it ("expect"; an empty list means nothing harmful should trigger, for a
test that shows normal use passes). Use only detector names from the list given. Use made-up data only: fake names,
card numbers from published test ranges, obviously fake keys. Write realistic, varied tests for the criterion (6 at
most), in the customer's industry if it's given. Call the tool."""


def draft(pov, cid, n=5, ask=None):
    """Claude drafts tests for a criterion; they wait for someone to accept them. -> the new drafts"""
    from . import ai, evidence
    c = next((x for x in evidence.selected_criteria(pov) if x["id"] == cid), None)
    if not c:
        raise KitError(f"{cid} isn't one of this POV's criteria.")
    dets = sorted({d for side in ag.template_detectors().values() for d in side} | set(PANELS))
    have = [t["text"][:200] for t in criterion_tests(pov, c)][:12]
    msg = (f"Criterion {cid}: {c['title']}\n{c.get('statement', '')}\n\nDetectors: {', '.join(dets)}\n"
           f"Customer industry: {pov.cfg.get('industry') or 'not given'}\nTests it has already (don't repeat):\n"
           + "\n".join(f"- {x}" for x in have) + f"\n\nWrite {max(1, min(int(n), 6))} new tests.")
    customer_words = bool(c.get("usecase") or c.get("customer_pack"))
    used, text = (ask or ai.ask)(pov, DRAFT_SYSTEM, msg, max_tokens=3000, tool=DRAFT_TOOL,
                                 needs_consent=customer_words)
    got = (used or {}).get("tests") or []
    allowed = set(dets)
    new = []
    for i, t in enumerate(got[:6]):
        body = str(t.get("text") or "").strip()
        if not body:
            continue
        exp = [e for e in (t.get("expect") or []) if e in allowed]
        new.append({"id": f"d{int(time.time())}{i}", "name": str(t.get("name") or "Drafted test")[:80],
                    "direction": "OUT" if t.get("direction") == "OUT" else "IN", "text": body[:4000],
                    "expect": exp, "status": "draft", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    if not new:
        raise KitError("Claude didn't draft any usable tests. Try again.")
    d = drafts(pov)
    d.setdefault(cid, []).extend(new)
    pov.write_json(DRAFTS, d)
    pov.log("aiguard", f"Claude drafted {len(new)} tests for {cid}")
    return new


def review_draft(pov, cid, tid, accept, by=""):
    d = drafts(pov)
    items = d.get(cid) or []
    t = next((x for x in items if x["id"] == tid), None)
    if not t:
        raise KitError("No such drafted test.")
    if accept:
        t.update(status="accepted", by=(by or "SE")[:80])
    else:
        items.remove(t)
    pov.write_json(DRAFTS, d)
    return t


def runs(pov, limit=500):
    f = pov.path(RUNS)
    if not f.exists():
        return []
    lines = f.read_text(encoding="utf-8").splitlines()[-limit:]
    return [json.loads(x) for x in lines if x.strip()]


# ---------------------------------------------------------------- the customer's own prompts
def import_pack(pov, name, rows):
    """rows: [{prompt, direction?, name?, expect?}] (from their CSV). -> (pack id, criterion id, count)"""
    name = (name or "").strip()[:60]
    if not name:
        raise KitError("Give the pack a name, e.g. 'Acme support chatbot prompts'.")
    if not rows or len(rows) > 500:
        raise KitError("A pack needs between 1 and 500 prompts.")
    packs = customer_packs(pov)
    n = len([k for k in packs]) + 1
    pid = f"customer-{n}"
    tests = []
    for i, r in enumerate(rows, 1):
        text = str(r.get("prompt") or r.get("text") or "").strip()
        if not text:
            continue
        if len(text) > 8000:
            raise KitError(f"Row {i}: the prompt is longer than 8,000 characters.")
        d = str(r.get("direction") or "IN").strip().upper()
        expect = r.get("expect") or []
        if isinstance(expect, str):
            expect = [e.strip() for e in re.split(r"[ ,;|]+", expect) if e.strip()]
        tests.append({"id": f"{pid}-{i}", "name": str(r.get("name") or f"Prompt {i}")[:60],
                      "direction": "OUT" if d in ("OUT", "RESPONSE", "REPLY") else "IN", "text": text,
                      "expect": [e for e in expect if e in PANELS]})
    if not tests:
        raise KitError("No rows had a prompt.")
    packs[pid] = {"name": name, "description": "The customer's own prompts (imported from CSV)", "tests": tests,
                  "criterion": f"AI-AIG-C{n}", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    pov.write_json(PACKS, packs)
    pov.log("aiguard", f"customer prompt pack '{name}': {len(tests)} prompts, criterion AI-AIG-C{n}")
    return pid, f"AI-AIG-C{n}", len(tests)


def parse_csv(text):
    import csv
    import io
    rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
    if rows and not any(k and k.strip().lower() in ("prompt", "text") for k in rows[0]):
        raise KitError("The CSV needs a 'prompt' column (and optionally direction, name, expect).")
    return [{(k or "").strip().lower(): v for k, v in r.items()} for r in rows]


def criteria(pov):
    """A success criterion per customer pack: their own prompts behave as they expect."""
    out = []
    for pid, p in customer_packs(pov).items():
        out.append({"id": p["criterion"], "product": "aiguard", "phase": "pov", "proofs": ["api"],
                    "title": f"The customer's own prompts: {p['name']}",
                    "statement": f"{len(p['tests'])} of the customer's own prompts are scanned by AI Guard, and each "
                                 "is detected as expected (or passes, where nothing is expected).",
                    "pack": pid, "usecase": True, "customer_pack": True})
    return out


# ---------------------------------------------------------------- the one-page report
def report(pov, customer=None):
    rs = [r for r in runs(pov) if r.get("status") == "ok"]
    e = html.escape
    by_det = Counter(d for r in rs for d in r.get("detectors") or [])
    blocked = sum(1 for r in rs if r.get("action") == "BLOCK")
    flagged = sum(1 for r in rs if r.get("detectors"))
    groups = Counter(r.get("group") or "Custom" for r in rs)
    examples = [r for r in rs if r.get("detectors")][:8]
    who = customer or pov.cfg.get("customer") or ""
    rows = "".join(f"<tr><td>{e(PANELS.get(d, d))}</td><td>{n}</td></tr>" for d, n in by_det.most_common())
    ex = "".join(f"<tr><td>{e(r['name'])}</td><td>{e(r['text'][:140])}</td><td>{e(r.get('action') or '')}</td>"
                 f"<td>{e(', '.join(r.get('detectors') or []))}</td></tr>" for r in examples)
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>AI Guard POV results: {e(who)}</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;margin:32px;color:#111}}h1{{margin:0 0 4px}}.m{{color:#555}}
.k{{display:flex;gap:24px;margin:18px 0}}.k div{{border:1px solid #ddd;border-radius:8px;padding:10px 16px}}
.k b{{display:block;font-size:24px}}table{{border-collapse:collapse;width:100%;margin:8px 0 18px}}
td,th{{border-bottom:1px solid #eee;padding:6px 8px;text-align:left;vertical-align:top}}</style></head><body>
<h1>AI Guard POV results</h1><div class="m">{e(who)} · {len(rs)} scans · {time.strftime('%Y-%m-%d')} ·
policy profile: {e(str((pov.cfg.get('aiguard') or {}).get('profile') or 'monitor'))}</div>
<div class="k"><div><b>{len(rs)}</b>prompts and replies scanned</div><div><b>{flagged}</b>flagged</div>
<div><b>{blocked}</b>blocked</div><div><b>{len(by_det)}</b>kinds of detection</div></div>
<h2>Detections by type</h2><table><tr><th>Type</th><th>Count</th></tr>{rows or '<tr><td colspan=2>None yet</td></tr>'}</table>
<h2>Scenarios</h2><p>{', '.join(f'{e(g)} ({n})' for g, n in groups.most_common())}</p>
<h2>Examples</h2><table><tr><th>Test</th><th>Prompt or reply</th><th>Action</th><th>Detected</th></tr>{ex}</table>
<p class="m">Synthetic test data, except the customer's own prompt packs. Scanned on the POV's own AI Guard app and
policy; the customer's apps and policies were not used.</p></body></html>"""
