"""Reading the tenant less: action lookups kept a day, one reading for Make it, Ask Claude reads what it needs."""
import collections

from povkit import lifecycle, usecases
from povkit.products import zia as Z
from test_usecases import claude, ready  # noqa: F401, F811  (fixtures)


def _count(tenant):
    c = collections.Counter()
    orig = tenant.call

    def call(r, m, *a, **k):
        c[(r, m)] += 1
        return orig(r, m, *a, **k)
    tenant.call = call
    return c


def test_action_lookups_are_kept(pov, tenant, tenant_for):
    c = _count(tenant)
    lifecycle.discover(pov, tenant_for)
    first = c[("cloudappcontrol", "list_available_actions")]
    c.clear()
    lifecycle.discover(pov, tenant_for)
    assert first > 0 and c[("cloudappcontrol", "list_available_actions")] == 0
    pov.cfg["vanity_domain"] = "other"   # another tenant: asked again
    pov.save()
    assert Z.ActionCache(pov).data == {}


def test_make_now_reads_once(pov, tenant, tenant_for, ready):  # noqa: F811
    lifecycle.plan(pov, tenant_for)
    from povkit.core.changelist import ChangeList
    ChangeList(pov.dir).approve("Jane Doe")
    lifecycle.apply(pov, tenant_for, lambda *a: None)
    usecases.propose(pov, ready, "Let pilot users open Dropbox but not upload to it")
    usecases.set_status(pov, "UC-01", "accepted")
    pv = lifecycle.make_preview(pov, tenant_for, "UC-01")
    c = _count(tenant)
    lifecycle.make_now(pov, tenant_for, "UC-01", pv["hash"], "Paul", lambda *a: None)
    # apply still lists each rule type to place its rules; a reading would also list users, groups and categories
    assert c[("url_filtering", "add_rule")] == 1
    assert c[("user_management", "list_groups")] == 0 and c[("url_categories", "list_categories")] == 0


def test_products_for():
    ps = ["zia", "zcc", "zpa", "aiguard"]
    assert usecases.products_for("Marketing can use ChatGPT but can't upload files to it", ps) == {"zia"}
    assert usecases.products_for("Pilot users reach the wiki at wiki.acme.internal through ZPA", ps) == {"zpa"}
    assert usecases.products_for("Our support chatbot blocks prompt injection", ps) == {"aiguard"}
    assert usecases.products_for("Something vague", ps) is None
    assert usecases.products_for("Report card numbers in OneDrive", ["zia"]) is None or "casb" not in \
        usecases.products_for("Report card numbers in OneDrive", ["zia"])
