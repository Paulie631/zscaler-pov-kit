"""Quick start: three answers, then the kit fills in the rest, runs preflight and makes the change list."""
import time

from povkit import gui
from povkit.core import pov as povs


def wait(jid):
    for _ in range(200):
        j = gui.JOBS[jid]
        if j["done"]:
            return j
        time.sleep(0.02)
    raise AssertionError("job didn't finish")


def test_quickstart_makes_a_change_list_with_a_test_user(home, tenant, tenant_for, monkeypatch):
    tenant.zidentity = True   # a SAML tenant signs its users in through ZIdentity
    monkeypatch.setattr(gui, "tf", tenant_for)
    monkeypatch.setattr(gui.mcp, "desktop_client", lambda: None)
    _, r = gui.api("POST", "/api/quickstart", {"customer": "Acme Corp", "products": ["zia", "zcc"],
                                               "vanity_domain": "acme", "client_id": "c1", "secret": "s1"}, {})
    j = wait(r["job"])
    assert j["error"] is None, j
    p = povs.Pov(r["id"])
    assert p.cfg["identity"]["pilot"] == "test" and p.cfg["identity"]["test_users"] == 1
    assert p.cfg["identity"]["users_in"] == "zidentity"   # learned on the first pass, used on the second
    assert j["result"]["creates"] > 5 and j["result"]["fails"] == 0, "\n".join(x["msg"] for x in j["lines"])
    assert gui.api("GET", "/api/plan", {}, {})[1]["plan"]["items"]


def test_quickstart_says_when_the_client_doesnt_sign_in(home, tenant_for, monkeypatch):
    monkeypatch.setattr(gui, "tf", tenant_for)
    monkeypatch.setattr(gui.mcp, "desktop_client", lambda: None)
    import pytest
    from povkit.core import KitError
    with pytest.raises(KitError, match="didn't sign in"):
        gui.api("POST", "/api/quickstart", {"customer": "Acme Corp", "products": ["zia"], "vanity_domain": "acme",
                                           "client_id": "", "secret": ""}, {})


def test_a_lab_pov_can_be_started_from_the_console(home, tenant_for, monkeypatch):
    monkeypatch.setattr(gui, "tf", tenant_for)
    _, r = gui.api("POST", "/api/pov/new", {"customer": "Lab", "products": ["zia"], "lab": True}, {})
    assert povs.Pov(r["id"]).cfg["lab"] == "yes"
    _, r = gui.api("POST", "/api/pov/new", {"customer": "Acme", "products": ["zia"]}, {})
    assert povs.Pov(r["id"]).cfg.get("lab") != "yes"


def test_quickstart_carries_on_a_pov_started_for_the_role_spec(home, tenant, tenant_for, monkeypatch):
    tenant.zidentity = True
    monkeypatch.setattr(gui, "tf", tenant_for)
    monkeypatch.setattr(gui.mcp, "desktop_client", lambda: None)
    _, r = gui.api("POST", "/api/pov/new", {"customer": "Acme", "products": ["zia", "zcc"]}, {})
    assert "role" in gui.api("GET", "/api/rolespec", {}, {})[1]["text"].lower()     # what the SE sends beforehand
    _, q = gui.api("POST", "/api/quickstart", {"existing": True, "vanity_domain": "acme", "client_id": "c1",
                                               "secret": "s1"}, {})
    j = wait(q["job"])
    assert j["error"] is None and q["id"] == r["id"] and len(povs.all_povs()) == 1
