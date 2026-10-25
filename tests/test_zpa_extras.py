"""ZPA Privileged Remote Access (PA-PRA-01) and App Protection (PA-APP-03): opt-in, scoped, and reversible."""
from povkit import evidence, lifecycle
from povkit.core.changelist import ChangeList

log = lambda *a: None  # noqa: E731
ALL = ["IS-TEN-01", "PA-APP-01", "PA-APP-02", "PA-CON-01"]


def run(pov, tenant_for):
    items, notes, h, checks = lifecycle.plan(pov, tenant_for)
    ChangeList(pov.dir).approve("Jane Doe")
    lifecycle.apply(pov, tenant_for, log)
    return items, notes, checks


def test_not_chosen_means_nothing_extra(pov_all, tenant, tenant_for):
    items, *_ = run(pov_all, tenant_for)
    assert not {i["kind"] for i in items} & {"pra_segment", "pra_portal", "insp_profile", "protect_rule"}
    assert not [c for c in evidence.selected_criteria(pov_all) if c["id"] in ("PA-PRA-01", "PA-APP-03")]


def test_pra_needs_its_settings_then_builds_and_tears_down(pov_all, tenant, tenant_for):
    pov_all.cfg["criteria"] = ALL + ["PA-PRA-01"]
    pov_all.save()
    items, notes, _h, checks = lifecycle.plan(pov_all, tenant_for)
    assert not [i for i in items if i["kind"].startswith("pra")]
    assert any("Privileged Remote Access" in n for n in notes)
    pov_all.cfg["zpa"].update(pra_server="jump1.acme.internal", pra_portal="pra.acme.com")
    pov_all.save()
    items, notes, checks = run(pov_all, tenant_for)
    st = tenant.store
    seg = next(s for s in st["zpa.application_segment"] if s["name"] == "ZPOV: PRA jump1.acme.internal")
    assert seg["common_apps_dto"]["apps_config"][0]["application_protocol"] == "RDP" and \
        seg["tcp_port_range"] == [{"from": "3389", "to": "3389"}]
    portal = st["zpa.pra_portal"][0]
    assert portal["domain"] == "pra.acme.com" and portal["certificate_id"] == "c1"   # the wildcard cert covers it
    con = st["zpa.pra_console"][0]
    assert con["pra_application_id"] == seg["praApps"][0]["id"] and con["pra_portal_ids"] == [portal["id"]]
    rule = next(r for r in st["zpa.policies"] if r["name"] == "ZPOV: pilot PRA access")
    assert {o["rhs"] for c in rule["conditions"] for o in c["operands"] if o["objectType"] == "APP"} == {seg["id"]}
    assert lifecycle.api_proofs(pov_all, tenant_for, ids=["PA-PRA-01"]) is not None
    row = next(r for r in evidence.evaluate(pov_all) if r["criterion"]["id"] == "PA-PRA-01")
    assert row["proofs"]["api"]["status"] == "pass"
    pack = evidence.probe_pack(pov_all)
    spec = next(c for c in pack["criteria"] if c["id"] == "PA-PRA-01")["probe"][0]
    assert spec["url"] == "https://pra.acme.com/"
    lifecycle.teardown(pov_all, tenant_for, log)
    assert not st["zpa.pra_portal"] and not st["zpa.pra_console"]
    assert {s["name"] for s in st["zpa.application_segment"]} == {"Corp intranet"}


def test_app_protection_inspects_the_pov_app(pov_all, tenant, tenant_for):
    pov_all.cfg["criteria"] = ALL + ["PA-APP-03"]
    pov_all.cfg["zpa"]["certificate"] = "acme-wildcard"   # the HR portal is HTTPS (443): inspection needs a cert
    pov_all.save()
    run(pov_all, tenant_for)
    st = tenant.store
    seg = next(s for s in st["zpa.application_segment"] if s["name"] == "ZPOV: HR portal")
    cfg = seg["common_apps_dto"]["apps_config"][0]
    assert cfg["application_protocol"] == "HTTPS" and cfg["certificate_id"] == "c1" and cfg["app_types"] == ["INSPECT"]
    prof = st["zpa.app_protection"][0]
    rule = next(r for r in st["zpa.policies"] if r["name"] == "ZPOV: inspect POV app")
    assert rule["zpn_inspection_profile_id"] == prof["id"] and rule["action"] == "INSPECT"
    lifecycle.api_proofs(pov_all, tenant_for, ids=["PA-APP-03"])
    row = next(r for r in evidence.evaluate(pov_all) if r["criterion"]["id"] == "PA-APP-03")
    assert row["proofs"]["api"]["status"] == "pass"
    spec = next(c for c in evidence.probe_pack(pov_all)["criteria"] if c["id"] == "PA-APP-03")["probe"][0]
    assert spec["url"].startswith("https://pov-app.acme.internal/?q=") and spec["block_status"] == [403]
    lifecycle.teardown(pov_all, tenant_for, log)
    assert not st["zpa.app_protection"] and {r["name"] for r in st["zpa.policies"]} == {"Corp: engineering"}


def test_app_protection_on_https_without_a_cert_is_left_out(pov_all, tenant, tenant_for):
    pov_all.cfg["criteria"] = ALL + ["PA-APP-03"]
    pov_all.save()
    tenant.store["zpa.certificates"] = []
    items, notes, *_ = lifecycle.plan(pov_all, tenant_for)
    assert not [i for i in items if i["kind"] in ("insp_profile", "protect_rule")]
    assert any("certificate" in n for n in notes)


def test_a_zpa_403_counts_as_a_block(monkeypatch):
    from povkit import probe

    class R:
        status_code, headers, text, history, url = 403, {"Content-Type": "text/html"}, "<p>Forbidden</p>", [], "x"
    s = type("S", (), {"get": lambda self, *a, **k: R()})()
    r = probe.run_spec({"type": "http", "url": "https://app/?q=x", "expect": "block", "block_status": [403]}, "r1", s)
    assert r["outcome"] == "block" and r["pass"]
    r = probe.run_spec({"type": "http", "url": "https://app/?q=x", "expect": "block"}, "r1", s)
    assert r["outcome"] == "allow"
