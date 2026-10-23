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
        return [every[i] for i in ids if i in every]
    if preset:
        pr = next((x for x in lib["presets"] if x["id"] == preset), None)
        if not pr:
            raise KitError(f"No preset {preset}.")
        return [t for t in lib["tests"] if t["group"] in pr["groups"]]
    return lib["tests"]


# ---------------------------------------------------------------- running tests on the POV's app
def keys(pov):
    from .usecases import aiguard_secret
    return secrets.get(pov.id, ag.KEY_SECRET), secrets.get(pov.id, aiguard_secret("aiguard.proxy_key"))


def run_one(pov, test, user, mode="detect", tags=False, scan=None, chat=None):
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
    dkey, pkey = keys(pov)
    try:
        if mode == "proxy":
            if not pkey:
                raise KitError("The POV has no proxy key yet: choose proxy mode in the AI Guard tab, then approve and "
                               "apply the change list.")
            if res["direction"] == "OUT":
                raise KitError("Model-reply tests run through the Detection API only.")
            _, ptype, model = ag.proxy_cfg(pov)
            reply, ms, blocked = chat(ptype, pkey, model, text, user=user)
            res.update(action="BLOCK" if blocked else "ALLOW", reply=reply[:800], latency_ms=ms, detectors=[])
            if tags and dkey:
                d = scan(dkey, text, "IN", user=user)
                res["detectors"] = ag.hits(d)
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
    except Exception as e:   # noqa: BLE001 - one failing test shouldn't stop a run
        res.update(status="error", error=str(e)[:300], detectors=[], missed=expect, action="")
    return res


def run(pov, tests, mode="detect", tags=False, users=None, rounds=1, log=lambda *a: None, scan=None, chat=None,
        pause=0.2):
    users = [u for u in (users or LIB["users"][:1]) if u] or ["pov-kit"]
    rounds = max(1, min(10, int(rounds or 1)))
    if mode == "proxy":
        tests = [t for t in tests if t.get("direction", "IN") == "IN"]
    if not tests:
        raise KitError("No tests to run.")
    if len(tests) * rounds > 500:
        raise KitError("That's more than 500 scans: pick fewer tests or rounds.")
    out = []
    f = pov.path(RUNS)
    for r in range(rounds):
        for i, t in enumerate(tests):
            res = run_one(pov, t, users[(i + r) % len(users)], mode, tags, scan, chat)
            out.append(res)
            with open(f, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(res, ensure_ascii=False) + "\n")
            level = "fail" if res["status"] == "error" else "warn" if res["missed"] else "ok"
            log(level, f"{res['name']}: {res.get('action') or res.get('error', '')}"
                       + (f" · {', '.join(res['detectors'])}" if res["detectors"] else "")
                       + (f" · expected {', '.join(res['missed'])}" if res["missed"] else ""))
            if pause and (scan is None):
                time.sleep(pause)
    pov.log("aiguard", f"AI Guard test run: {len(out)} {mode} scans")
    return out


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
