
from povkit import competitive, devtests, evidence, lifecycle, probe, report
from povkit.core.changelist import ChangeList

VENDORS = ["Palo Alto", "Prisma", "Netskope", "Cisco", "Cloudflare", "Entra", "Fortinet", "FortiSASE", "Check Point", "Cato"]


def test_differentiators_name_real_criteria_and_stay_neutral(pov_all):
    from povkit.products import base
    ids = {c["id"] for c in base.load_catalog()}
    data = competitive.load()
    for d in data["differentiators"]:
        assert set(d["criteria"]) <= ids and set(d["se"]) == set(data["vendors"])
        for v in d["se"].values():   # every SE note says where they stand, and its sources exist
            assert v["stance"] in ("gap", "parity", "strong", "unknown") and set(v["sources"]) <= set(data["sources"])
            assert v["stance"] != "gap" or v["sources"]   # a gap is never claimed without a source
        assert not any(v in d["why"] + d["ask"] + d["title"] for v in VENDORS)   # customer-facing text is neutral
    sheet = competitive.sheet_html(pov_all)
    assert "Ask every vendor to show" in sheet and not any(v in sheet for v in VENDORS)
    assert "docs.paloaltonetworks" not in sheet


def test_bakeoff_pack_adds_land_mines_and_keeps_the_rest(pov_all, tenant_for):
    before = {c["id"] for c in evidence.selected_criteria(pov_all)}
    added = competitive.add_pack(pov_all)
    after = {c["id"] for c in evidence.selected_criteria(pov_all)}
    assert before <= after and {"IS-SSL-03", "IS-DNS-02", "IS-ZCC-03", "PA-APP-04", "IS-DLP-03"} <= set(added)
    assert competitive.add_pack(pov_all) == []
    items = lifecycle.plan(pov_all, tenant_for)[0]
    assert any(i["name"] == "ZPOV: Block DNS over HTTPS" for i in items)
    lib = {g["criterion"]: g for g in devtests.library(pov_all)["criteria"]}
    assert lib["PA-APP-04"]["differentiator"]["id"] == "invisible-apps"
    assert any(i["kind"] == "dns" and i["body"].get("protocols") == ["DOHTTPS"] for i in items)
    spec = next(c for c in evidence.probe_pack(pov_all)["criteria"] if c["id"] == "IS-SSL-03")["probe"][0]
    assert spec["port"] == 1012


def test_report_section_is_neutral_and_se_notes_stay_out(pov_all, tenant_for):
    competitive.add_pack(pov_all)
    lifecycle.plan(pov_all, tenant_for)
    html = report.render_report(pov_all, evidence.evaluate(pov_all), None)
    assert "Where Zscaler stood apart" in html and "Private apps stay invisible" in html
    assert not any(v in html for v in VENDORS) and "docs.netskope" not in html
    se = competitive.se_view(pov_all)
    gaps = [v for d in se["differentiators"] for v in d["se"].values() if v["stance"] == "gap"]
    assert gaps and all(v["sources"][0]["url"].startswith("https://") for v in gaps) and "re-check" in se["status"]


def test_closed_port_counts_as_no_access(monkeypatch):
    monkeypatch.setattr(probe, "tcp_probe", lambda h, p: "timeout")
    r = probe.run_spec({"type": "tcp", "host": "app", "port": 22, "expect": "closed"}, "r1", None)
    assert r["outcome"] == "closed" and r["pass"]
    monkeypatch.setattr(probe, "tcp_probe", lambda h, p: "open")
    assert not probe.run_spec({"type": "tcp", "host": "app", "port": 22, "expect": "closed"}, "r1", None)["pass"]


def test_least_privilege_proof(pov_all, tenant, tenant_for):
    pov_all.cfg["criteria"] = ["IS-TEN-01", "PA-APP-01", "PA-APP-04"]
    pov_all.save()
    lifecycle.plan(pov_all, tenant_for)
    ChangeList(pov_all.dir).approve("Jane")
    lifecycle.apply(pov_all, tenant_for, lambda *a: None)
    lifecycle.api_proofs(pov_all, tenant_for, ids=["PA-APP-04"])
    row = next(r for r in evidence.evaluate(pov_all) if r["criterion"]["id"] == "PA-APP-04")
    assert row["proofs"]["api"]["status"] == "pass"


def test_quick_apply_reads_only_the_product_it_changes(pov_all, tenant, tenant_for):
    lifecycle.plan(pov_all, tenant_for)            # a reading of every product, as Setup leaves it
    seen, lines = [], []
    orig = tenant.call
    tenant.call = lambda r, m, *a, **k: (seen.append(r), orig(r, m, *a, **k))[1]
    lifecycle.quick_apply(pov_all, tenant_for, ["aiguard"], "AI Guard proxy setup", "Jane",
                          lambda lvl, msg: lines.append(msg))
    assert not [r for r in seen if r in ("url_filtering", "zpa.application_segment", "zcc.forwarding_profile")]
    text = "\n".join(lines)
    assert "using the last reading" in text and "AI Guard" in text and "Signed off as Jane" in text
