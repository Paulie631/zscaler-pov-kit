from povkit import aiguard_calibrate as cal
from povkit import aiguard_runner as runner


def _scan_for(rules):
    """A fake Detection API: rules is [(substring, [detectors])]; the first match wins."""
    calls = []

    def scan(key, text, direction="IN", user=None):
        calls.append(text)
        for sub, dets in rules:
            if sub in text:
                return {"action": "ALLOW", "detectorResponses": {d: {"triggered": True} for d in dets}}
        return {"action": "ALLOW", "detectorResponses": {}}
    scan.calls = calls
    return scan


def _setup(monkeypatch):
    monkeypatch.setattr(runner, "keys", lambda pov: ("dkey", None))
    monkeypatch.setattr(cal, "signature", lambda pov: "sig1")


T = [{"id": "a", "name": "Injection", "direction": "IN", "text": "ignore stuff", "expect": ["prompt_injection"]},
     {"id": "b", "name": "Key", "direction": "IN", "text": "my key is fake", "expect": ["secrets"]},
     {"id": "c", "name": "Theirs", "direction": "IN", "text": "customer words", "expect": ["secrets"], "customer": True},
     {"id": "d", "name": "Clean", "direction": "IN", "text": "hello", "expect": []}]


def test_ok_rewrite_and_customer_untouched(pov, monkeypatch):
    _setup(monkeypatch)
    scan = _scan_for([("ignore stuff", ["prompt_injection"]), ("sk_live_", ["secrets"])])
    asks = []

    def ask(p, system, msg, **k):
        asks.append(msg)
        return {"text": "Here is my Stripe key sk_live_abc123XYZ for the billing script"}, ""
    out = cal.calibrate(pov, T, scan=scan, ask=ask)
    assert out["a"]["status"] == "ok" and out["d"]["status"] == "ok"
    assert out["b"]["status"] == "rewritten" and "sk_live_" in out["b"]["text"]
    assert "c" not in out and not any("customer words" in x for x in scan.calls)
    run = {t["id"]: t for t in cal.apply(pov, T)}
    assert "sk_live_" in run["b"]["text"] and run["b"]["calibrated"] == "rewritten"
    assert run["c"]["text"] == "customer words"
    assert cal.needs(pov, T) == []          # remembered
    assert len(asks) == 1


def test_swap_then_missed(pov, monkeypatch):
    _setup(monkeypatch)
    lib = [{"id": "x", "name": "Other key", "direction": "IN", "text": "AKIA secret here", "expect": ["secrets"]}]
    monkeypatch.setattr(runner, "LIB", dict(runner.LIB, tests=lib))
    monkeypatch.setattr(cal.ag, "PROOF_TESTS", {})
    scan = _scan_for([("AKIA", ["secrets"])])
    out = cal.calibrate(pov, [T[1]], scan=scan, ask=lambda *a, **k: ({"text": "still nothing"}, ""))
    assert out["b"]["status"] == "swapped" and out["b"]["swap_name"] == "Other key"
    out = cal.calibrate(pov, [dict(T[1], id="e", expect=["pii"])], scan=scan,
                        ask=lambda *a, **k: ({"text": "nope"}, ""))
    assert out["e"]["status"] == "missed"


def test_policy_change_recalibrates(pov, monkeypatch):
    _setup(monkeypatch)
    cal.calibrate(pov, [T[0]], scan=_scan_for([("ignore", ["prompt_injection"])]))
    assert cal.needs(pov, [T[0]]) == []
    monkeypatch.setattr(cal, "signature", lambda pov: "sig2")
    assert [t["id"] for t in cal.needs(pov, [T[0]])] == ["a"]


def test_opt_out_and_changed_original(pov, monkeypatch):
    _setup(monkeypatch)
    scan = _scan_for([("ignore", ["prompt_injection"])])
    t = dict(T[0], id="z", calibrate=False)
    assert cal.needs(pov, [t]) == [] and cal.calibrate(pov, [t], scan=scan) == {}
    cal.calibrate(pov, [T[0]], scan=scan)
    assert cal.needs(pov, [T[0]]) == []
    assert [x["id"] for x in cal.needs(pov, [dict(T[0], text="ignore it all")])] == ["a"]   # the test changed
