"""Drift, Client Connector adopt, handover, diagnostics, evidence, catalog and updater."""
import hashlib
import io
import json
import zipfile

import pytest

from povkit import evidence, handover, lifecycle, probe, products, updater
from povkit.core import KitError
from povkit.core.changelist import ChangeList
from povkit.core.redact import Redactor
from povkit import diagnostics

log = lambda *a: None  # noqa: E731


def applied(pov, tenant_for):
    lifecycle.plan(pov, tenant_for)
    ChangeList(pov.dir).approve("Jane Doe")
    return lifecycle.apply(pov, tenant_for, log)


# ---- drift and Fix drift
def test_drift_finds_and_fixes_disabled_and_rescoped_rules(pov, tenant, tenant_for):
    applied(pov, tenant_for)
    r = tenant.by_name("url_filtering", "ZPOV: Block gambling")
    r["state"], r["groups"] = "DISABLED", [{"id": 78}]
    checks = {c["id"]: c for c in lifecycle.status(pov, tenant_for)}
    assert checks["zia-disabled"]["status"] == "warn" and checks["zia-scope"]["status"] == "fail"
    lifecycle.status(pov, tenant_for, fix=True)
    r = tenant.by_name("url_filtering", "ZPOV: Block gambling")
    assert r["state"] == "ENABLED" and r["groups"] == [77]
    assert tenant.by_name("url_filtering", "Corp: Block adult")["groups"] == [{"id": 78}]


def test_fix_drift_recreates_a_rule_deleted_in_the_console(pov, tenant, tenant_for):
    applied(pov, tenant_for)
    tenant.rules["dlp"] = []
    assert {c["id"]: c for c in lifecycle.status(pov, tenant_for)}["zia-present"]["status"] == "warn"
    lifecycle.status(pov, tenant_for, fix=True)
    assert tenant.by_name("dlp", "ZPOV: Block card numbers")


# ---- Client Connector: create, or build by hand and adopt
def test_zcc_bare_400_then_adopt_by_name(pov, tenant, tenant_for):
    tenant.zcc_fwd_400 = True
    led = applied(pov, tenant_for)
    assert not led.find("zcc.fwd")                      # nothing recorded for a refused create
    tenant.zcc_fwd_400 = False
    tenant.fwds.append({"id": 40, "name": "ZPOV - Z-Tunnel 2.0"})          # built by hand to the spec
    tenant.apps.append({"id": 41, "name": "ZPOV - pilot devices"})
    lifecycle.status(pov, tenant_for, fix=True)
    led = lifecycle.ledger(pov)
    assert led.find("zcc.fwd")["state"] == "adopted" and led.find("zcc.app")["state"] == "adopted"
    lifecycle.teardown(pov, tenant_for, log)            # adopted objects are kept unless asked
    assert any(f["id"] == 40 for f in tenant.fwds)
    lifecycle.teardown(pov, tenant_for, log, include_adopted=True)
    assert not any(f["id"] == 40 for f in tenant.fwds)
    assert any(f["name"] == "Default" for f in tenant.fwds)


def test_zcc_copies_default_and_switches_to_z_tunnel_2(pov, tenant, tenant_for):
    applied(pov, tenant_for)
    fwd = next(f for f in tenant.fwds if f["name"] == "ZPOV - Z-Tunnel 2.0")
    assert all(a["actionType"] == 1 and a["enablePacketTunnel"] == 1 for a in fwd["forwardingProfileActions"])
    assert next(f for f in tenant.fwds if f["name"] == "Default")["forwardingProfileActions"][0]["actionType"] == 2


# ---- handover
def test_terraform_export_imports_in_place_and_retires_the_objects(pov, tenant, tenant_for):
    led = applied(pov, tenant_for)
    n = len([e for e in led.active() if e["product"] == "zia"])
    out, exported, _ = handover.terraform(pov, led)
    text = (out / "imports.tf").read_text()
    assert text.count("import {") == n
    assert "zia_url_filtering_rules.zpov_block_gambling" in text
    assert 'required_version = ">= 1.5"' in (out / "versions.tf").read_text()
    writes = len(tenant.writes)
    lifecycle.teardown(pov, tenant_for, log, include_adopted=True)     # handed-over objects are never deleted
    assert all(not w[1].startswith("delete") or w[0].startswith("zcc") for w in tenant.writes[writes:])
    assert tenant.by_name("url_filtering", "ZPOV: Block gambling")


def test_finish_clears_secrets_and_customer_data(pov, home, tenant_for):
    from povkit.core import secrets
    secrets.put(pov.id, "discovery-client-secret", "s3cret")
    lifecycle.plan(pov, tenant_for)
    gone, purged = handover.finish(pov)
    assert gone == ["discovery-client-secret"] and "discovery.json" in purged
    assert not pov.path("discovery.json").exists()


# ---- diagnostics: no secrets, no customer object names
def test_diagnostics_has_no_secrets_or_customer_names(pov, tenant, tenant_for):
    applied(pov, tenant_for)
    pov.log("api", "failed on Corp: Block adult for jane@acme.com", "error", client_secret="abc123secret",
            detail="Bearer eyJhbGciOiJIUzI1NiJ9.payload")
    z = zipfile.ZipFile(io.BytesIO(diagnostics.build(pov)))
    blob = "".join(z.read(n).decode() for n in z.namelist())
    for leak in ("abc123secret", "Corp: Block adult", "jane@acme.com", "eyJhbGci", "POV Pilot"):
        assert leak not in blob
    assert "ZPOV: Block gambling" in blob                # the kit's own objects stay readable


def test_redactor_masks_secret_fields():
    r = Redactor(["Sales EMEA"])
    out = r({"password": "x", "nested": [{"apiKey": "y", "msg": "group Sales EMEA"}]})
    assert out == {"password": "…", "nested": [{"apiKey": "…", "msg": "group <customer-object>"}]}


# ---- evidence
class Resp:
    def __init__(self, status=200, text="", ctype="text/html", url="https://x/"):
        self.status_code, self.text, self.url, self.history = status, text, url, []
        self.headers = {"Content-Type": ctype}


def test_classify_reads_zscaler_pages():
    assert probe.classify(Resp(403, "Zscaler: this site is blocked by policy")) == "block"
    assert probe.classify(Resp(200, "Zscaler caution: continue to the site?")) == "caution"
    assert probe.classify(Resp(200, "<h1>Welcome</h1>")) == "allow"
    assert probe.classify(error=ConnectionResetError("connection reset")) == "block"


def test_fake_cards_pass_luhn_and_eicar_is_assembled():
    assert all(probe.luhn_ok(probe.fake_card()) for _ in range(50))
    assert probe.eicar().startswith("X5O!") and probe.eicar().endswith("H+H*")


def test_evaluate_needs_every_proof(pov, tmp_path):
    run = {"run_id": "ab12", "device": "pilot-1", "at": "2026-10-22T10:00:00Z", "results": [
        {"criterion": "IS-SSL-01", "spec": {"type": "tls_issuer", "host": "h"}, "outcome": "Zscaler",
         "expect": "Zscaler", "pass": True, "detail": ""},
        {"criterion": "IS-URL-01", "spec": {"type": "http", "url": "u"}, "outcome": "block", "expect": "block",
         "pass": True, "detail": ""},
        {"criterion": "IS-THR-01", "spec": {"type": "eicar", "url": "u"}, "outcome": "allow", "expect": "block",
         "pass": False, "detail": ""}]}
    f = tmp_path / "run.json"
    f.write_text(json.dumps(run))
    evidence.import_probe(pov, f)
    evidence.attest(pov, "IS-URL-01", "Blocks seen in Web Insights for the pilot user", "SE")
    rows = {r["criterion"]["id"]: r["status"] for r in evidence.evaluate(pov)}
    assert rows["IS-SSL-01"] == "pass"           # probe only
    assert rows["IS-URL-01"] == "pass"           # probe + (attested) API
    assert rows["IS-THR-01"] == "fail"
    assert rows["IS-DLP-01"] == "incomplete"


def test_report_renders(pov):
    from povkit.report import render_report
    html = render_report(pov, evidence.evaluate(pov), None)
    assert "Proof of value: Acme Corp" in html and "IS-URL-01" in html


# ---- catalog
def test_catalog_ids_unique_and_every_product_covered():
    cat = products.base.load_catalog()
    ids = [c["id"] for c in cat]
    assert len(ids) == len(set(ids))
    assert {c["product"] for c in cat} == set(products.ORDER)
    tpl = json.loads((products.base.CATALOG.parent / "products" / "zia_pov_template.json").read_text())
    used = {c for sect in tpl.values() if isinstance(sect, list) for r in sect for c in r.get("criteria", [])}
    assert used <= set(ids)
    for c in cat:
        assert c["proofs"] and c["phase"] in ("v1", "v2", "v3")
        assert "probe" not in c["proofs"] or c.get("probe"), c["id"]


def test_every_product_has_the_full_lifecycle():
    for name in products.ORDER:
        p = products.get(name)
        assert p.ready, name
        for m in ("role_scopes", "discover", "plan", "apply", "live_object", "drift", "teardown"):
            assert getattr(type(p), m) is not getattr(products.base.Product, m), f"{name}.{m}"
        assert p.criteria(), name                     # from its catalog file


# ---- updater
def test_update_refuses_a_zip_that_doesnt_match_its_hash(tmp_path):
    class R:
        content = b"not the zip"
    info = {"version": "9.9.9", "zip_url": "https://github.com/x/y.zip", "sha256": hashlib.sha256(b"other").hexdigest()}
    with pytest.raises(KitError, match="SHA-256"):
        updater.install(info, get=lambda *a, **k: R(), app=tmp_path / "app", previous=tmp_path / "prev")
    assert not (tmp_path / "app").exists()
