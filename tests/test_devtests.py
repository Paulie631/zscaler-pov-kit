import pytest

from povkit import devtests, evidence, probe
from povkit.core import KitError


def fake(monkeypatch, outcome=lambda sp: sp.get("expect")):
    monkeypatch.setattr(probe, "run_spec", lambda sp, rid, s: {
        "spec": sp, "outcome": outcome(sp), "expect": sp.get("expect"), "pass": outcome(sp) == sp.get("expect"),
        "detail": ""})


def test_library_and_stories(pov):
    lib = devtests.library(pov)
    assert lib["criteria"] and all(t["id"] and t["text"] for c in lib["criteria"] for t in c["tests"])
    st = {s["id"]: s for s in lib["stories"]}
    assert "gambling" in st and st["gambling"]["tests"]
    web = next(t for c in lib["criteria"] for t in c["tests"] if t["type"] == "http")
    assert web["open"].startswith("https://")


def test_run_streams_and_counts_only_complete_criteria(pov, monkeypatch):
    fake(monkeypatch)
    lib = devtests.library(pov)
    two = next(c for c in lib["criteria"] if len(c["tests"]) >= 2 and c["criterion"] != "IS-TEN-01")
    seen = []
    out = devtests.run(pov, [two["tests"][0]["id"]], on_result=seen.append)    # half a criterion
    assert out["total"] == 1 and seen[0]["id"] == two["tests"][0]["id"] and out["evidence"] == []
    out = devtests.run(pov, [t["id"] for t in two["tests"]])                   # all of it
    assert out["evidence"] == [two["criterion"]]
    row = next(r for r in evidence.evaluate(pov) if r["criterion"]["id"] == two["criterion"])
    assert row["proofs"]["probe"]["status"] == "pass"


def test_gate_and_stop(pov, monkeypatch):
    fake(monkeypatch, outcome=lambda sp: "allow")                              # not the POV's tenant
    with pytest.raises(KitError, match="isn't in the POV's tenant"):
        devtests.run(pov)
    fake(monkeypatch)
    n = []
    out = devtests.run(pov, on_result=n.append, stop=lambda: len(n) >= 3)
    assert out["stopped"] and out["total"] == 3


def test_helpers_and_warm_up(pov_all, monkeypatch):
    h = devtests.helpers(pov_all)
    prods = {x["product"] for x in h["helpers"]}
    assert prods == {"zpa", "zdx", "casb"} & set(pov_all.products) and h["traffic"]
    zpa = next(x for x in h["helpers"] if x["product"] == "zpa")
    assert "{app}" not in zpa["steps"][0] and zpa["criteria"]
    from povkit import traffic
    fake(monkeypatch)
    monkeypatch.setattr(traffic, "run", lambda **k: {"total": 10, "errors": 0, "summary": "ok"})
    assert devtests.warm_up(pov_all, rounds=2) == {"total": 20, "errors": 0}


def test_show_and_open_here(pov, monkeypatch):
    import webbrowser
    lib = devtests.library(pov)
    tests = [t for c in lib["criteria"] for t in c["tests"]]
    assert all(t["show"]["look"] for t in tests)
    tcp = next((t for t in tests if t["type"] == "tcp"), None)
    if tcp:
        assert tcp["show"]["terminal"].startswith("nc -vz") and not tcp["show"]["open"]
    opened = []
    monkeypatch.setattr(webbrowser, "open", lambda u: opened.append(u) or True)
    web = next(t for t in tests if t["open"])
    assert devtests.open_here(pov, web["id"]) == web["open"] == opened[0]
    with pytest.raises(KitError):
        devtests.open_here(pov, "not-a-test")
    assert devtests.show({"type": "dlp_post", "expect": "block"})["copy"].count("Card number") == 6
