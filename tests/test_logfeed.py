import json
import urllib.error
import urllib.request

import pytest

from povkit import devlink, evidence, lifecycle, logfeed
from povkit.core import KitError
from povkit.core.changelist import ChangeList


def plan_approve(pov, tenant_for):
    items, *_ = lifecycle.plan(pov, tenant_for)
    ChangeList(pov.dir).approve("Jane")
    return items


def test_log_feed_end_to_end(pov_all, tenant, tenant_for):
    pov = pov_all
    logfeed.set_mode(pov, "console")
    items = plan_approve(pov, tenant_for)
    feed = next(i for i in items if i["kind"] == "nss_feed")
    assert feed["body"]["users"] and "filled in at apply" in feed["body"]["connection_url"]
    devlink.LISTEN.pop("url", None)
    with pytest.raises(KitError, match="tunnel"):
        lifecycle.apply(pov, tenant_for, lambda *a: None)
    assert not tenant.nss_feeds and not [w for w in tenant.writes if w[1].startswith("add")]
    st = devlink.start(pov, lambda: pov, port=18899)
    try:
        devlink.LISTEN["url"] = f"http://127.0.0.1:{st['port']}"   # stands in for the tunnel
        lifecycle.apply(pov, tenant_for, lambda *a: None)
        live = next(iter(tenant.nss_feeds.values()))
        url = live["connection_url"]
        assert url.endswith("/services/collector") and "/nss/" in url
        assert live["connection_headers"][0].startswith("Authorization:Splunk ")
        # ZIA posts web log lines for a device run
        lines = [{"sourcetype": "zscalernss-web", "event": {"user": "jane@acme.com", "action": "Blocked",
                  "reason": "Not allowed to browse this category", "urlcategory": "Gambling",
                  "hostname": "www.bet365.com", "url": "www.bet365.com/?zpov_run=abcd1234"}},
                 {"sourcetype": "zscalernss-web", "event": {"user": "jane@acme.com", "action": "Blocked",
                  "reason": "Not allowed to browse this category", "urlcategory": "Gambling",
                  "hostname": "www.pokerstars.com", "url": "www.pokerstars.com/?zpov_run=abcd1234"}}]
        body = "\n".join(json.dumps(x) for x in lines).encode()
        r = urllib.request.urlopen(urllib.request.Request(url, data=body, method="POST"))
        assert json.loads(r.read())["code"] == 0
        bad = url.replace("/nss/", "/nss/x")
        with pytest.raises(urllib.error.HTTPError, match="403"):
            urllib.request.urlopen(urllib.request.Request(bad, data=body, method="POST"))
        v = logfeed.view(pov)
        assert v["count"] == 2 and all(e["test"] and e["test"]["pass"] for e in v["events"])
        assert v["runs"][0]["run"] == "abcd1234" and v["runs"][0]["ok"] == 2
        out = logfeed.record(pov, "abcd1234")
        assert out["criteria"] == ["IS-URL-01"]
        row = next(r for r in evidence.evaluate(pov, ["IS-URL-01"]))
        assert row["proofs"]["probe"]["status"] == "pass"
        # the tunnel's address changes: the POV's own feed follows
        devlink.LISTEN["url"] = f"http://localhost:{st['port']}"
        logfeed.update_address(pov, tenant)
        assert next(iter(tenant.nss_feeds.values()))["connection_url"].startswith("http://localhost:")
        lifecycle.teardown(pov, tenant_for, lambda *a: None)
        assert not tenant.nss_feeds
    finally:
        devlink.stop(pov)


def test_log_feed_left_out_without_pilot_users_or_nss(pov, tenant, tenant_for):
    logfeed.set_mode(pov, "console")
    items, notes, *_ = lifecycle.plan(pov, tenant_for)
    assert not any(i["kind"] == "nss_feed" for i in items) and any("Log feed left out" in n for n in notes)
    tenant.nss = False
    items, notes, *_ = lifecycle.plan(pov, tenant_for)
    assert any("Cloud NSS" in n for n in notes)


def test_parse_and_outcome():
    raw = b'{"event":{"action":"Allowed","reason":"Caution"}}{"event":{"action":"Blocked"}} [{"action":"Allowed"}]'
    evs = logfeed.parse(raw)
    assert [logfeed.outcome(e) for e in evs] == ["caution", "block", "allow"]
