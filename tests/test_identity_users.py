"""Test accounts: a name the SE can change (another POV or SE may use the default), the list the console shows,
and passwords set before apply."""
import pytest

from povkit import gui, lifecycle, settings
from povkit.core import KitError, secrets
from povkit.core.changelist import ChangeList
from povkit.products import zia as Z


def test_name_setting_is_checked(pov):
    settings.set_value(pov, "identity.test_login", "Acme-POV")
    assert pov.cfg["identity"]["test_login"] == "acme-pov"
    for bad in ("a", "-x", "has space", "x" * 41, "a@b"):
        with pytest.raises(KitError):
            settings.set_value(pov, "identity.test_login", bad)


def hosted(pov, tenant, n=2, **extra):
    tenant.groups = [g for g in tenant.groups if g["name"] != "POV Pilot"]
    tenant.saml = False                                                       # form sign-in, Hosted DB
    pov.cfg["identity"] = dict({"test_users": n}, **extra)
    pov.save()


def test_plan_uses_the_name_and_flags_names_in_use(pov, tenant, tenant_for):
    hosted(pov, tenant)
    tenant.users.append({"id": 92, "name": "Other SE", "email": "zpov-pilot-1@acme.com", "groups": []})
    _, _, _, checks = lifecycle.plan(pov, tenant_for)
    st = {c["id"]: c for c in checks}
    assert st["zia-testtaken"]["status"] == "fail" and "zpov-pilot-1@acme.com" in st["zia-testtaken"]["detail"]
    settings.set_value(pov, "identity.test_login", "paul-pov")
    items, _, _, checks = lifecycle.plan(pov, tenant_for)
    assert "zia-testtaken" not in {c["id"] for c in checks}
    assert [i["body"]["email"] for i in items if i["kind"] == "user"] == ["paul-pov-1@acme.com", "paul-pov-2@acme.com"]


def test_accounts_list_and_passwords_before_apply(pov, tenant):
    hosted(pov, tenant, test_domain="acme.com", test_login="paul-pov", pilot="test")
    r = gui.api("POST", "/api/test-accounts", {}, {})[1]
    assert [a["email"] for a in r["accounts"]] == ["paul-pov-1@acme.com", "paul-pov-2@acme.com"]
    assert r["where"] == "zia" and not any(a["password"] or a["made"] for a in r["accounts"])
    with pytest.raises(KitError, match="8 characters"):
        gui.api("POST", "/api/test-accounts", {"n": 1, "password": "short"}, {})
    r = gui.api("POST", "/api/test-accounts", {"n": 1, "password": "Pilot!2026x"}, {})[1]
    assert r["accounts"][0]["password"] is True and secrets.get(pov.id, Z.TEST_PW.format(n=1)) == "Pilot!2026x"
    r = gui.api("POST", "/api/test-accounts", {"n": 2}, {})[1]                              # generated
    pw = secrets.get(pov.id, Z.TEST_PW.format(n=2))
    assert r["accounts"][1]["password"] is True and len(pw) >= 12 and pw not in str(r)       # never sent back


def test_apply_uses_the_password_set_before(pov, tenant, tenant_for):
    hosted(pov, tenant, n=1)
    secrets.put(pov.id, Z.TEST_PW.format(n=1), "Typed!Pass1")
    lifecycle.plan(pov, tenant_for)
    ChangeList(pov.dir).approve("Jane")
    lifecycle.apply(pov, tenant_for, lambda *a: None)
    u = next(x for x in tenant.users if x.get("email") == "zpov-pilot-1@acme.com")
    assert u["password"] == "Typed!Pass1"
    r = gui.api("POST", "/api/test-accounts", {}, {})[1]
    assert r["accounts"][0]["made"] and r["accounts"][0]["email"] == "zpov-pilot-1@acme.com"   # domain from preflight
