"""Proofs run on their own, and a failing proof says why and how to fix it."""
from povkit import evidence, gui, lifecycle, proof_explain
from povkit.core.changelist import ChangeList


def test_explain_splits_and_matches():
    ex = proof_explain.explain("'ZPOV: Block gambling' is disabled; ZIA puts www.bet365.com in SPORTS, not in the "
                               "rule's categories", "fail")
    assert [e["action"] for e in ex] == ["fixdrift", None]
    assert "classifies this test site differently" in ex[1]["why"] and len(ex[1]["fix"]) == 3
    ex = proof_explain.explain("access rule not scoped as approved; 1 of 2 POV connectors connected (2 needed for "
                               "failover)", "fail")
    assert [e["action"] for e in ex] == ["fixdrift", "finish"]
    assert proof_explain.explain("all fine", "pass") == []
    assert proof_explain.explain("something odd", "fail")[0]["fix"]          # never empty
    assert proof_explain.explain("test runner: 3 of 4 as expected; not as expected: Credit card", "fail")[0][
        "action"] == "runner"


def test_auto_proofs_after_apply_skip_ai_guard_and_explain(pov_all, tenant, tenant_for, monkeypatch):
    lifecycle.plan(pov_all, tenant_for)
    ChangeList(pov_all.dir).approve("Jane")
    assert not lifecycle.proofs_due(pov_all)                    # nothing applied yet
    monkeypatch.setattr(gui, "tf", tenant_for)
    jid = gui.api("POST", "/api/apply", {}, {})[1]["job"]
    import time
    for _ in range(200):
        j = gui.api("GET", "/api/job", {}, {"id": jid})[1]
        if j["done"]:
            break
        time.sleep(0.05)
    assert j["done"] and not j["error"], j["error"]
    proofs = pov_all.read_json("api_proofs.json", {})
    assert proofs and not any(k.startswith("AI-AIG") for k in proofs)   # the runner owns AI Guard
    assert pov_all.read_json("api_proofs_meta.json", {})["auto"] is True
    assert not lifecycle.proofs_due(pov_all)
    rows = evidence.evaluate(pov_all)
    failing = [r for r in rows if r["proofs"].get("api", {}).get("status") == "fail"]
    assert all(r["proofs"]["api"]["explain"] for r in failing)
    r = gui.api("GET", "/api/criteria", {}, {})[1]
    assert r["proofs_at"] and r["only_runner"] is False


def test_ai_guard_only_pov_needs_no_api_proofs(home, tenant_for):
    from povkit.core import pov as povs
    p = povs.new("Phish", ["aiguard"])
    assert not lifecycle.proofs_due(p)
