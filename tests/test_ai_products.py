"""The AI solutions: GenAI isolation (AI-GEN-03, opt-in), and the draft AI-SPM and AI Red Teaming products."""
from povkit import evidence, lifecycle, products, report
from povkit.core import pov as povs
from povkit.core.changelist import ChangeList

log = lambda *a: None  # noqa: E731


def applied(p, tenant_for):
    items = lifecycle.plan(p, tenant_for)[0]
    ChangeList(p.dir).approve("Jane Doe")
    lifecycle.apply(p, tenant_for, log)
    return items


def test_genai_isolation_only_when_chosen(pov, tenant, tenant_for):
    assert not tenant.by_name("cloud_app_control", "ZPOV: Isolate GenAI") and \
        not [i for i in applied(pov, tenant_for) if i["name"] == "ZPOV: Isolate GenAI"]


def test_genai_isolation_applies_and_switches(pov, tenant, tenant_for):
    pov.cfg["criteria"] = ["IS-TEN-01", "AI-GEN-01", "AI-GEN-03"]
    pov.save()
    applied(pov, tenant_for)
    r = tenant.by_name("cloud_app_control", "ZPOV: Isolate GenAI")
    assert r["actions"] == ["ISOLATE_AI_ML_WEB_USE"] and r["cbi_profile"]["id"] == "cbi-1"
    zia = products.get("zia")
    sw = {x["key"]: x for x in zia.switches(pov)}["zia.cloud_app_control.isolate-genai"]
    assert sw["planned"] == "ISOLATE" and [c["id"] for c in sw["choices"]] == ["BLOCK", "CAUTION", "ISOLATE", "ALLOW"]
    from povkit.core.guard import LedgerTenant
    plan = ChangeList(pov.dir).plan()["items"]
    lt = LedgerTenant(tenant, lifecycle.ledger(pov), plan)
    zia.switch(lt, pov, lifecycle.ledger(pov), "zia.cloud_app_control.isolate-genai", "BLOCK")
    r = tenant.by_name("cloud_app_control", "ZPOV: Isolate GenAI")
    assert r["actions"] == ["BLOCK_AI_ML_WEB_USE"]
    zia.switch(lt, pov, lifecycle.ledger(pov), "zia.cloud_app_control.isolate-genai", "planned")
    assert tenant.by_name("cloud_app_control", "ZPOV: Isolate GenAI")["cbi_profile"]
    spec = next(c for c in evidence.probe_pack(pov)["criteria"] if c["id"] == "AI-GEN-03")["probe"][0]
    assert spec == {"type": "http", "url": "https://www.perplexity.ai/", "expect": "isolate"}
    assert "genai" in evidence.probe_pack(pov)["traffic"]["types"]


def test_genai_isolation_left_out_without_isolation(pov, tenant, tenant_for):
    pov.cfg["criteria"] = ["IS-TEN-01", "AI-GEN-03"]
    pov.save()
    tenant.cbi = []
    items, notes, *_ = lifecycle.plan(pov, tenant_for)
    assert not [i for i in items if i["name"] == "ZPOV: Isolate GenAI"]
    assert any("Isolate GenAI" in n and "Isolation" in n for n in notes)


def test_draft_ai_products_are_attested(home, tenant, tenant_for):
    p = povs.new("Acme Corp", ["zia", "aispm", "airt"])
    p.cfg.update(pilot_group="POV Pilot", vanity_domain="acme")
    p.save()
    assert {"aispm", "airt"} <= set(products.CHOOSABLE)
    crit = {c["id"]: c for c in evidence.selected_criteria(p)}
    for cid in ("AS-INV-01", "AS-GOV-01", "RT-SCN-01", "RT-GRD-01"):
        assert crit[cid]["proofs"] == ["attested"] and crit[cid]["attest"]
    applied(p, tenant_for)   # nothing to make for them, and nothing breaks
    lifecycle.teardown(p, tenant_for, log)
    html = report.render_report(p, evidence.evaluate(p), None)
    assert "Shadow AI is inventoried" in html and "AI Guard stops what the red team found" in html
    assert "genai" in evidence.probe_pack(p)["traffic"]["types"]   # AI-SPM's inventory gets GenAI traffic
