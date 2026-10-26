"""Pilot users › Test accounts: the domain comes from the tenant, most used first."""
from povkit import gui
from povkit.products import zia as Z


def test_org_domains_ranked_by_users(tenant):
    tenant.org_domains = ["acme.io", "acme.com", "acme.zscalerbeta.net"]
    tenant.users.append({"id": 93, "name": "Lee", "email": "lee@other.org"})
    assert Z.tenant_domains(tenant) == ["acme.com", "acme.io", "other.org"]   # acme.com has 2 users; Zscaler's left out
    assert Z.test_domain(tenant) == "acme.com"


def test_falls_back_to_user_emails(tenant):
    tenant.org_domains = None   # no access to orgInformation
    assert Z.tenant_domains(tenant) == ["acme.com"]


def test_org_domain_when_no_users(tenant):
    tenant.org_domains = ["lab.example"]
    tenant.users = []
    assert Z.test_domain(tenant) == "lab.example"


def test_check_returns_the_domains(pov, tenant, tenant_for, monkeypatch):
    tenant.saml = False
    pov.cfg["identity"] = {"test_users": 1, "pilot": "test"}
    pov.save()
    monkeypatch.setattr(gui, "TENANT_FOR", tenant_for)
    tenant.org_domains = ["acme.com", "acme.io"]
    r = gui.api("POST", "/api/test-accounts", {"check": True}, {})[1]
    assert r["domains"][:2] == ["acme.com", "acme.io"] and r["domain"] == "acme.com"


def test_role_spec_reads_org_information(pov):
    from povkit import rolespec
    assert "organization information" in rolespec.render(pov)
