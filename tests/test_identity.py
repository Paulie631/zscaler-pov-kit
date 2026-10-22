"""The identity step and single-client mode."""
import pytest

from povkit import lifecycle, rolespec
from povkit.core import KitError, secrets
from povkit.core.changelist import ChangeList
from povkit.tenant import client_slot

log = lambda *a: None  # noqa: E731


def checks_of(pov, tenant_for):
    return {c["id"]: c for c in lifecycle.discover(pov, tenant_for)[1]}


def test_entitlements_are_checked_for_every_product_in_scope(pov_all, tenant, tenant_for):
    tenant.zidentity = True
    pov_all.cfg["pilot_emails"] = ["jane@acme.com", "raj@acme.com"]
    pov_all.save()
    c = checks_of(pov_all, tenant_for)["id-entitlements"]
    assert c["status"] == "fail" and "raj@acme.com (Private Access)" in c["detail"]
    lifecycle.plan(pov_all, tenant_for)
    ChangeList(pov_all.dir).approve("Jane Doe")
    with pytest.raises(KitError, match="Discovery found problems"):
        lifecycle.apply(pov_all, tenant_for, log)
    tenant.entitlements["z2"].append("Private Access")
    assert checks_of(pov_all, tenant_for)["id-entitlements"]["status"] == "ok"


def test_pilot_users_outside_the_group_are_flagged(pov, tenant, tenant_for):
    pov.cfg["pilot_emails"] = ["jane@acme.com", "raj@acme.com", "nobody@acme.com"]
    pov.save()
    c = checks_of(pov, tenant_for)
    assert "raj@acme.com" in c["id-zia-group"]["detail"]
    assert "nobody@acme.com" in c["id-zia-users"]["detail"]


def test_sign_in_sites_are_never_decrypted(pov_all, tenant, tenant_for):
    lifecycle.plan(pov_all, tenant_for)
    ChangeList(pov_all.dir).approve("Jane Doe")
    lifecycle.apply(pov_all, tenant_for, log)
    cat = tenant.by_name("url_category", "ZPOV - sign-in sites")
    assert ".okta.com" in cat["urls"]                       # the ZPA IdP is Okta
    ssl = [r["name"] for r in sorted(tenant.rules["ssl"], key=lambda r: r["order"])]
    assert ssl.index("ZPOV: Bypass sign-in") < ssl.index("ZPOV: Inspect pilot group")
    assert tenant.by_name("ssl", "ZPOV: Bypass sign-in")["url_categories"] == [cat["id"]]


def test_hosted_db_test_users(pov, tenant, tenant_for):
    tenant.groups = [g for g in tenant.groups if g["name"] != "POV Pilot"]   # no pilot group yet
    pov.cfg["identity"] = {"test_users": 2}
    tenant.saml = False                                                       # form sign-in, Hosted DB
    pov.save()
    items, _, _, checks = lifecycle.plan(pov, tenant_for)
    assert {c["id"]: c["status"] for c in checks}["zia-testusers"] == "ok"
    users = [i for i in items if i["kind"] == "user"]
    assert [u["body"]["email"] for u in users] == ["zpov-pilot-1@acme.com", "zpov-pilot-2@acme.com"]
    assert all("password" not in u["body"] for u in users)  # never in the change list
    ChangeList(pov.dir).approve("Jane Doe")
    lifecycle.apply(pov, tenant_for, log)
    grp = next(g for g in tenant.groups if g["name"] == "ZPOV - pilot users")
    made = [u for u in tenant.users if u["email"].startswith("zpov-pilot-")]
    assert len(made) == 2 and all(u["groups"] == [{"id": grp["id"]}] for u in made)
    assert secrets.get(pov.id, "zia-test-user-1") and made[0]["password"] == secrets.get(pov.id, "zia-test-user-1")
    assert tenant.by_name("url_filtering", "ZPOV: Block gambling")["groups"] == [grp["id"]]
    assert {c["id"]: c for c in lifecycle.status(pov, tenant_for)}["plan-approved"]["status"] == "ok"
    lifecycle.teardown(pov, tenant_for, log)
    assert not [u for u in tenant.users if u["email"].startswith("zpov-pilot-")]
    assert not any(g["name"] == "ZPOV - pilot users" for g in tenant.groups)
    assert not secrets.get(pov.id, "zia-test-user-1")
    assert {u["name"] for u in tenant.users} == {"Jane Roe", "Raj Patel"}


def test_test_users_refused_where_zidentity_owns_users(pov, tenant, tenant_for):
    tenant.zidentity = True
    pov.cfg["identity"] = {"test_users": 1}
    pov.save()
    assert checks_of(pov, tenant_for)["zia-testusers"]["status"] == "fail"


def test_zpa_scoped_by_saml_attribute(pov_all, tenant, tenant_for):
    pov_all.cfg["zpa"].update(scope="saml", saml_attribute="memberOf", saml_value="pov-pilots")
    pov_all.save()
    lifecycle.plan(pov_all, tenant_for)
    ChangeList(pov_all.dir).approve("Jane Doe")
    lifecycle.apply(pov_all, tenant_for, log)
    rule = next(r for r in tenant.store["zpa.policies"] if r["name"] == "ZPOV: pilot access")
    ops = {o["objectType"]: o["rhs"] for c in rule["conditions"] for o in c["operands"]}
    assert ops["SAML"] == "pov-pilots" and "SCIM_GROUP" not in ops
    assert lifecycle.api_proofs(pov_all, tenant_for, {"PA-APP-02"})["PA-APP-02"]["status"] == "pass"


def test_single_client_is_the_default(pov):
    assert pov.cfg["client_mode"] == "single"
    assert client_slot(pov, "discovery") == client_slot(pov, "apply") == "main"
    text = rolespec.render(pov)
    assert text.count("## ZPOV") == 1 and "view only" in text and "full" in text
    pov.cfg["client_mode"] = "separate"
    assert client_slot(pov, "apply") == "apply" and rolespec.render(pov).count("## ZPOV") == 2


def test_role_spec_asks_for_user_management_only_with_test_users(pov):
    assert "user management (for" not in rolespec.render(pov)
    pov.cfg["identity"] = {"test_users": 2}
    assert "user management (for the POV's Hosted DB test users only)" in rolespec.render(pov)


def test_blank_bypass_field_still_uses_the_idps_sites(pov_all, tenant, tenant_for):
    pov_all.cfg["identity"] = {"bypass_domains": []}       # what the console saves for an empty field
    pov_all.save()
    c = checks_of(pov_all, tenant_for)["id-bypass"]
    assert c["status"] == "info" and ".okta.com" in c["detail"]
