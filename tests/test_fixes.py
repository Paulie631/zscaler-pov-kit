"""Every error or blocker comes with step-by-step instructions to resolve it (fixes.json)."""
import glob
import re

from povkit import console, fixes, gui, lifecycle, manual
from povkit.core.changelist import ChangeList
from povkit.core.checks import FAIL, OK, WARN, check, render


def planned(p, tenant_for):
    lifecycle.plan(p, tenant_for)
    ChangeList(p.dir).approve("Jane Doe")


def source_check_ids():
    ids = set()
    for f in glob.glob("povkit/**/*.py", recursive=True):
        ids |= set(re.findall(r'check\("([a-z0-9-]+)"', open(f, encoding="utf-8").read()))
    return ids


def test_catalog_is_complete_and_points_at_real_things():
    c = fixes.catalog()
    ids = source_check_ids()
    steps = set(manual.GUIDE["steps"]) | set(manual.CHECKS)
    for fid, e in c["fixes"].items():
        assert e["title"] and e["who"] and e["steps"] and e["done"], fid
        assert not e.get("console") or e["console"] in console.paths(), fid
        assert e["match"], fid
        for m in e["match"]:
            if m.get("detail"):
                re.compile(m["detail"])
            p = m.get("check")
            if p:   # a typo here would silently never match
                hit = [i for i in ids | steps if (i.endswith(p[1:]) if p.startswith("*") else
                                                   i.startswith(p[:-1]) if p.endswith("*") else i == p)]
                assert hit, f"{fid}: no check or step matches {p}"
    for r in c["roles"].values():
        re.compile(r["pattern"])


def test_every_failing_check_kind_has_a_fix():
    """Each check the kit can raise as a warning or failure gets instructions, with or without a message."""
    no_fix_needed = {"aiguard-tenant", "teardown", "id-signin", "id-testusers", "zdx-traces", "zia-cbi",
                     "zia-lookalike", "customer-actions", "zid-new", "zpa-app", "zcc-adopted"}
    detail_led = {"zia-activation": "status PENDING", "zia-testusers": "users sign in with SAML",
                  "zid-members": "not found: a@b.com"}
    missing = [i for i in sorted(source_check_ids() - no_fix_needed)
               if not fixes.find([i], detail_led.get(i, "x.y failed: boom"))]
    assert not missing, missing


def test_warnings_and_failures_carry_the_steps():
    c = check("zpa-customer-id", "ZPA customer ID", WARN, "not set", "one-liner")
    assert c["howto"]["id"] == "zpa-customer-id" and len(c["howto"]["steps"]) >= 4
    assert "Private Access API" in c["howto"]["where"]
    assert "howto" not in check("zpa-customer-id", "ZPA customer ID", OK, "set")
    txt = render([c], pov_id="acme-1234")
    assert "how to fix: Set the ZPA customer ID" in txt and "  1. " in txt and "done when" in txt


def test_a_403_becomes_that_products_role():
    for cid, msg, prod in [("zpa-read", "zpa.segment.list failed: 403 Forbidden", "zpa"),
                           ("connect", "url_filtering.list_rules failed: 403", "zia"),
                           ("zcc-read", "forbidden", "zcc"), ("zid-read", "403", "zid"),
                           ("zdx-read", "the API client has no ZDX role", "zdx")]:
        f = fixes.find([cid], msg, "acme-1234")
        assert f["id"] == f"role-{prod}", (cid, f["id"])
        assert any("ZPOV acme-1234" in s for s in f["steps"]) and not any("{" in s for s in f["steps"])


def test_errors_map_to_their_fix():
    assert fixes.for_error("Zscaler rejected the API client's sign-in (401). Check...")["id"] == "signin-401"
    assert fixes.for_error("zpa.x failed: Max retries exceeded with url")["id"] == "network"
    assert fixes.for_error("ssl.SSLError: CERTIFICATE_VERIFY_FAILED")["id"] == "tls"
    assert fixes.for_error("zia.x failed: 429 Too Many Requests")["id"] == "rate-limit"
    assert fixes.for_error("Enter the customer's name.") is None   # a plain form error needs no walkthrough


def test_the_screenshot_cases(pov_all, tenant, tenant_for):
    """ZDX 403 and the missing ZPA customer ID: each step shows how to resolve it."""
    planned(pov_all, tenant_for)
    tenant.zdx_forbidden = True
    r = manual.check(pov_all, "setup.zdx_role", tenant_for)
    assert r["ok"] is False and "no ZDX role yet" in r["detail"]
    assert r["howto"]["id"] == "role-zdx"
    r = manual.check(pov_all, "setup.zpa_customer_id", tenant_for)
    assert r["ok"] is False and r["howto"]["id"] == "zpa-customer-id"
    steps = {s["key"]: s for s in manual.guide(pov_all)}
    assert steps["setup.zdx_role"]["howto"]["title"].startswith("Give the API client a Digital Experience")
    assert steps["setup.zpa_customer_id"]["howto"]["steps"]
    assert steps["zia.ca.malware"]["howto"] is None   # never checked: nothing to fix yet
    md = manual.sheet_md(pov_all)
    assert "**To fix it: Set the ZPA customer ID**" in md and "<pov-id>" not in md


def test_a_failed_job_carries_the_fix(pov_all):
    import time
    from povkit.core import KitError

    def work(log):
        raise KitError("Zscaler rejected the API client's sign-in (401). Check the client ID.")
    jid = gui.start_job("apply", work)
    for _ in range(100):
        if gui.JOBS[jid]["done"]:
            break
        time.sleep(0.02)
    code, out = gui.api("GET", "/api/job", {}, {"id": jid})
    assert out["error"] and out["howto"]["id"] == "signin-401"


def test_fail_status_kept_for_exit_codes():
    from povkit.core.checks import exit_code
    assert exit_code([check("zia-names", "POV names are free", FAIL, "ZPOV x")]) == 1
