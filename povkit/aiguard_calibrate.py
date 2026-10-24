"""Calibrating the AI Guard tests: every test should trigger the detectors it's meant to show, in this tenant.

Before a run, each test is scanned once through the POV's own Detection API key (a scan only: nothing goes to a
model). A test that triggers what it expects is kept as it is. One that doesn't:

  1. Claude rewrites it as a clearer example of the same thing (up to 3 tries, each scanned again);
  2. if it still misses, another test that expects the same detectors and does trigger them takes its place;
  3. if nothing works, it stays as it is and is marked as one that won't trigger here (the SE sees why).

The customer's own prompts (their prompt packs) are never rewritten or swapped: they're the customer's evidence.

What changed is kept in the POV (aiguard_calibration.json) and shown to the SE in the console and in the internal
readout. Runs use the calibrated tests. Calibration is redone when the POV's AI Guard policy changes.
"""
from __future__ import annotations

import hashlib
import json
import time

from . import aiguard_runner as runner
from .core import KitError
from .products import aiguard as ag

CAL = "aiguard_calibration.json"
TRIES = 3

REWRITE_SYSTEM = """You rewrite one test for Zscaler AI Guard so that it clearly and unambiguously shows what the test
is meant to show. A test is a prompt a user sends to an AI app (IN) or a reply from the model (OUT). AI Guard's
detectors scanned it and did not see what was expected. Write a new version, of the same kind and direction, that is
an unmistakable, textbook example of the expected detectors, while still reading like something a real user or model
would write. If the expected list is empty, the test must look like everyday work and trigger nothing harmful.
Use made-up data only: fake people, test card numbers from published test ranges, keys in the real format but with
random characters. Keep it under 120 words. Don't explain; call the tool."""
REWRITE_TOOL = {"name": "rewrite_test", "description": "The rewritten test text.",
                "input_schema": {"type": "object", "required": ["text"], "properties": {"text": {"type": "string"}}}}


# ---------------------------------------------------------------- state
def signature(pov):
    """Calibration holds while the POV's detectors and policy profile stay the same."""
    try:
        dets = ag.template_detectors()
    except Exception:   # noqa: BLE001
        dets = {}
    prof = (pov.cfg.get("aiguard") or {}).get("profile") or "monitor"
    return hashlib.sha256(json.dumps([dets, prof], sort_keys=True).encode()).hexdigest()[:16]


def load(pov):
    c = pov.read_json(CAL, {}) or {}
    if c.get("signature") != signature(pov):
        return {"signature": signature(pov), "tests": {}, "stale": bool(c.get("tests"))}
    return c


def save(pov, c):
    c["at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    c.pop("stale", None)
    pov.write_json(CAL, c)


def is_customer(t):
    """The customer's own prompts: never rewritten or swapped."""
    return bool(t.get("customer"))


def apply(pov, tests):
    """The tests as a run should send them: calibrated text (or the swapped-in test) where calibration changed them.
    Each changed test keeps its own ID and criterion, so evidence still lands on the right criterion."""
    recs = load(pov)["tests"]
    out = []
    for t in tests:
        r = recs.get(t.get("id"))
        if r and r["status"] in ("rewritten", "swapped") and not is_customer(t):
            t = dict(t, text=r["text"], expect=r.get("expect", t.get("expect")), calibrated=r["status"],
                     original_text=t.get("text"))
            if r["status"] == "swapped":
                t["swapped_from"] = r.get("swap_name")
        elif r:
            t = dict(t, calibrated=r["status"])
        out.append(t)
    return out


def needs(pov, tests):
    recs = load(pov)["tests"]
    return [t for t in tests if t.get("id") not in recs and not is_customer(t)]


# ---------------------------------------------------------------- calibrating
def _scan(pov, t, user, scan):
    r = runner.run_one(pov, t, user, "detect", False, scan)
    if r.get("status") != "ok":
        raise KitError(r.get("error") or "the scan failed")
    return r


def _candidates(pov, t, used):
    """Other tests that expect the same detectors in the same direction (library and catalog proofs)."""
    want, d = set(runner._expect(t)), t.get("direction", "IN")
    pool = list(runner.LIB["tests"]) + [x for v in ag.PROOF_TESTS.values() for x in (v or [])]
    seen, out = set(used), []
    for x in pool:
        if x.get("direction", "IN") != d or x["text"] in seen:
            continue
        if set(runner._expect(x)) == want:
            seen.add(x["text"])
            out.append(x)
    return out[:6]


def _rewrite(pov, t, got, tried, ask):
    from . import ai
    msg = (f"Direction: {t.get('direction', 'IN')}\nWhat it's meant to show: {t.get('category') or t.get('name')}\n"
           f"Expected detectors: {', '.join(runner._expect(t)) or 'none (everyday work)'}\n"
           f"AI Guard found instead: {', '.join(got) or 'nothing'}\n\nThe test:\n{t['text'].replace('{_}', '')}\n"
           + ("\nEarlier rewrites that also missed:\n" + "\n---\n".join(tried) if tried else ""))
    used, text = (ask or ai.ask)(pov, REWRITE_SYSTEM, msg, max_tokens=800, tool=REWRITE_TOOL,
                                 needs_consent=bool(t.get("usecase_words")))
    body = str((used or {}).get("text") or text or "").strip()
    if not body:
        raise KitError("Claude didn't return a rewrite.")
    return body[:2000]


def calibrate(pov, tests, log=lambda *a: None, stop=None, scan=None, ask=None, on_result=None, force=False):
    """Calibrates the tests that need it (all of them with force). -> {id: record}"""
    c = load(pov) if not force else {"signature": signature(pov), "tests": {}}
    if not runner.keys(pov)[0]:
        raise KitError("The POV has no AI Guard detection key yet: apply the change list first.")
    user = f"zpov-{pov.id}-calibration@pov.test"
    todo = [t for t in tests if not is_customer(t) and (force or t.get("id") not in c["tests"])]
    out = {}
    for t in todo:
        if stop and stop():
            break
        rec = {"name": t.get("name"), "criterion": t.get("criterion"), "expect": runner._expect(t)}
        try:
            r = _scan(pov, t, user, scan)
            rec["detected"] = r["detectors"]
            if r["pass"]:
                rec["status"] = "ok"
            else:
                tried, got = [], r["detectors"]
                for _ in range(TRIES):
                    if stop and stop():
                        break
                    try:
                        new = _rewrite(pov, t, got, tried, ask)
                    except Exception as e:   # noqa: BLE001 - no Claude: go on to swapping
                        rec["note"] = f"Claude couldn't rewrite it: {str(e)[:160]}"
                        break
                    r2 = _scan(pov, dict(t, text=new), user, scan)
                    if r2["pass"]:
                        rec.update(status="rewritten", text=new, detected=r2["detectors"], tries=len(tried) + 1)
                        break
                    tried.append(new)
                    got = r2["detectors"]
                if "status" not in rec:
                    for x in _candidates(pov, t, [t["text"]] + tried):
                        r3 = _scan(pov, dict(t, text=x["text"]), user, scan)
                        if r3["pass"]:
                            rec.update(status="swapped", text=x["text"], swap_name=x.get("name"),
                                       detected=r3["detectors"])
                            break
                if "status" not in rec:
                    rec.update(status="missed", detected=got,
                               why="No version triggered the expected detectors in this tenant.")
        except Exception as e:   # noqa: BLE001 - one test shouldn't stop the rest
            rec.update(status="error", why=str(e)[:200])
        if rec["status"] != "error":
            c["tests"][t["id"]] = rec
            save(pov, c)
        out[t["id"]] = rec
        lvl = {"ok": "ok", "rewritten": "ok", "swapped": "warn", "missed": "fail", "error": "fail"}[rec["status"]]
        log(lvl, f"{t.get('name')}: " + {"ok": "triggers as expected", "rewritten": "reworded so it triggers",
                                          "swapped": f"replaced by '{rec.get('swap_name')}'",
                                          "missed": "won't trigger here", "error": rec.get("why", "")}[rec["status"]])
        if on_result:
            on_result(dict(rec, id=t["id"]))
    pov.log("aiguard", f"calibrated {len(out)} AI Guard tests: "
            + ", ".join(f"{k} {v}" for k, v in summary(out).items() if v))
    return out


def summary(recs=None, pov=None):
    recs = recs if recs is not None else load(pov)["tests"]
    s = {"ok": 0, "rewritten": 0, "swapped": 0, "missed": 0, "error": 0}
    for r in recs.values():
        s[r["status"]] = s.get(r["status"], 0) + 1
    return s
