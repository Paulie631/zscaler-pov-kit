"""The console's API, driven the way the setup wizard drives it, against the fake tenant."""
import pytest

from povkit import gui
from povkit.core import KitError, secrets


@pytest.fixture
def console(home, tenant, monkeypatch):
    monkeypatch.setattr(gui, "TENANT_FOR", lambda pov, which: tenant)

    def call(path, body=None, **q):
        code, out = gui.api("GET" if body is None else "POST", path, body or {}, {k: str(v) for k, v in q.items()})
        assert code == 200, out
        return out
    return call


def wait(console, job):
    import time
    for _ in range(200):
        j = console("/api/job", id=job)
        if j["done"]:
            return j
        time.sleep(0.02)
    raise AssertionError("job never finished")


def test_the_wizard_end_to_end(console, tenant):
    assert console("/api/state")["current"] is None
    console("/api/pov/new", {"customer": "Acme Corp", "products": ["zia", "zcc", "zpa"], "prefix": "ZPOV",
                             "client_mode": "single"})
    cur = console("/api/state")["current"]
    assert cur["clients"] == {"main": {"client_id": None, "saved": False}}
    assert "## ZPOV " in console("/api/rolespec")["text"]
    console("/api/connect", {"vanity_domain": "acme", "client_id": "cid-1", "secret": "s3cret"})
    assert console("/api/state")["current"]["clients"]["main"]["saved"]
    console("/api/settings", {"values": {"pilot_group": "POV Pilot", "pilot_emails": "jane@acme.com",
                                         "zpa.domains": "hr.acme.internal", "placement": "top", "zpa.scope": "scim"}})
    pre = console("/api/preflight", {})
    assert not [c for c in pre["checks"] if c["status"] == "fail"], pre["checks"]
    plan = console("/api/plan", {})
    assert plan["hash"] and any(i["product"] == "zpa" for i in plan["items"])
    with pytest.raises(KitError, match="Tick the box"):
        gui.api("POST", "/api/approve", {"by": "Jane"}, {})
    console("/api/approve", {"by": "Jane Doe, CISO", "reviewed": True})
    j = wait(console, console("/api/apply", {})["job"])
    assert j["error"] is None and j["result"] > 10
    st = wait(console, console("/api/status", {})["job"])
    assert {c["id"]: c for c in st["result"]}["plan-approved"]["status"] == "ok"
    assert console("/api/state")["current"]["zpa_key"]
    assert console("/api/reveal", {"what": "zpa-key"})["value"] == "3|fake-provisioning-secret"
    assert len(console("/api/zpa-template", {})["template"]["Resources"]) >= 5
    assert console("/api/probe-pack", {})["criteria"]
    rows = console("/api/criteria")["rows"]
    assert {r["criterion"]["id"] for r in rows} >= {"IS-URL-01", "PA-APP-01"}
    console("/api/attest", {"criterion": "IS-URL-01", "note": "Blocks seen in Web Insights", "by": "SE"})
    console("/api/report", {})
    with pytest.raises(KitError, match="Type DELETE"):
        gui.api("POST", "/api/handover", {"how": "teardown", "confirm": "nope"}, {})
    j = wait(console, console("/api/handover", {"how": "teardown", "confirm": "DELETE"})["job"])
    assert j["result"]["finished"] is True
    assert not secrets.get(console("/api/state")["current"]["id"], "main-client-secret")


def test_secrets_never_come_back_in_state(console):
    console("/api/pov/new", {"customer": "Acme", "products": ["zia"]})
    console("/api/connect", {"vanity_domain": "acme", "client_id": "cid-1", "secret": "very-secret-value"})
    assert "very-secret-value" not in str(console("/api/state"))


def test_settings_are_validated(console):
    console("/api/pov/new", {"customer": "Acme", "products": ["zia"]})
    with pytest.raises(KitError, match="email"):
        gui.api("POST", "/api/settings", {"values": {"pilot_emails": "not-an-email"}}, {})
    with pytest.raises(KitError, match="placement"):
        gui.api("POST", "/api/settings", {"values": {"placement": "middle"}}, {})


def test_pages_with_customer_data_need_the_token(console):
    console("/api/pov/new", {"customer": "Acme", "products": ["zia"]})
    assert gui.page_file("/plan", {"t": "wrong"}, "right") is None
    assert gui.diagnostics_zip({}, "right") is None
