"""The ZIA traffic generator (ported from the demo kit): its catalog matches the POV policy, it sends nothing unless
traffic goes through Zscaler, the schedule on each OS, and the AWS generator template."""
import json
import re

import pytest

from povkit import gui, lifecycle, traffic, traffic_aws
from povkit.core import KitError
from povkit.core.changelist import ChangeList

TEMPLATE = json.loads((traffic.HERE / "products" / "zia_pov_template.json").read_text(encoding="utf-8"))


def test_catalog_matches_the_pov_policy():
    cat = traffic.catalog()
    tenant = [w for w in cat["web"] if w["category"] == "POV tenant check"]
    assert len(tenant) == 1 and cat["web"][0] is tenant[0]   # the first "block": always sent
    host = tenant[0]["url"].split("/")[2]
    assert host in TEMPLATE["url_category"]["urls"]
    pov_ports = next(n for n in [TEMPLATE["network_service"]] if n["key"] == "pov-ports")["dest_tcp"]
    assert cat["ports"]["blocked_by_pov"] == pov_ports
    blocked = {c for r in TEMPLATE["url_filtering"] if r["action"] == "BLOCK" for c in r["url_categories"]}
    for w in cat["web"]:
        if w["expect"] == "block" and w["category"] != "POV tenant check":
            assert w["category"] in blocked, w   # never claim the POV blocks what it doesn't
    assert not re.search(r"SE-Demo|demo tenant|aiguard-kit", (traffic.HERE / "traffic.py").read_text())


def test_fake_data_is_test_data():
    card = traffic.fake_card()
    assert traffic.luhn_ok(card) and card[:6] in traffic.TEST_BINS
    assert traffic.eicar().startswith("X5O!P%@AP")


def test_run_sends_nothing_unless_through_zscaler(monkeypatch):
    sent = []
    monkeypatch.setattr(traffic, "via_zscaler", lambda s: (False, []))
    monkeypatch.setattr(traffic, "fetch", lambda *a, **k: sent.append(a) or {"outcome": "allow"})
    r = traffic.run(count=1, quiet=True, sess=object())
    assert r["skipped"] and r["total"] == 0 and not sent


def test_run_one_type(monkeypatch, tmp_path):
    monkeypatch.setattr(traffic, "via_zscaler", lambda s: (True, ["zscalertwo"]))
    monkeypatch.setattr(traffic, "fetch", lambda s, m, url, **k: {"outcome": "block" if "example.com" in url else "allow",
                                                                  "url": url})
    monkeypatch.setattr(traffic.time, "sleep", lambda *_: None)
    r = traffic.run(types=["web"], count=1, quiet=True, sess=object(), log_dir=tmp_path, seed=1)
    assert r["by_type"]["web"]["block"] >= 1 and (tmp_path / "zia-traffic-last.json").exists()


@pytest.mark.parametrize("system", ["Windows", "Darwin", "Linux"])
def test_schedule_on_each_os(system, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(traffic.Path, "home", classmethod(lambda cls: tmp_path))
    calls = []

    class R:
        stdout = "0 9 * * * other job\n"

    def run(args, **k):
        calls.append((args, k))
        return R()
    msg = traffic.schedule_install(every=5, count=2, types=["web", "dns"], system=system, run=run)
    assert "15" in msg   # at least every 15 minutes
    flat = json.dumps(calls)
    if system == "Darwin":
        flat = (tmp_path / "Library" / "LaunchAgents" / f"{traffic.LAUNCH_ID}.plist").read_text()
    assert "traffic" in flat and "--count" in flat and "web,dns" in flat
    if system == "Darwin":
        plist = tmp_path / "Library" / "LaunchAgents" / f"{traffic.LAUNCH_ID}.plist"
        assert "<integer>900</integer>" in plist.read_text()
    if system == "Linux":
        assert "other job" in calls[-1][1]["input"]
    traffic.schedule_remove(system=system, run=run)


@pytest.fixture
def ready(pov_all, tenant_for):
    lifecycle.plan(pov_all, tenant_for)
    ChangeList(pov_all.dir).approve("Jane Doe")
    pov_all.cfg["zcc"] = {"cloud": "zscalertwo"}
    pov_all.cfg["pilot_emails"] = ["jane@acme.com"]
    pov_all.save()
    return pov_all


def test_aws_template_for_the_pov(ready):
    name, t = traffic_aws.for_pov(ready)
    assert name == f"zpov-traffic-{ready.id}.json"
    p = t["Parameters"]
    assert p["PilotUser"]["Default"] == "jane@acme.com" and p["ZccCloudName"]["Default"] == "zscalertwo"
    assert p["PovId"]["Default"] == ready.id
    ud = t["Resources"]["Generator"]["Properties"]["UserData"]["Fn::Base64"]["Fn::Sub"]
    assert set(re.findall(r"\$\{([A-Za-z:]+)\}", ud)) <= set(p)   # every ${...} is a parameter
    assert "zcc-setup.ps1" in ud and "traffic.cmd" in ud and "secret" not in json.dumps(t).lower()
    assert "SE-Demo" not in json.dumps(t)
    for k, r in t["Resources"].items():
        if "Condition" in r:
            assert r["Condition"] in t["Conditions"], k
    sg = t["Resources"]["NoInbound"]["Properties"]
    assert "SecurityGroupIngress" not in sg


def test_aws_template_checks(pov_all, ready):
    with pytest.raises(KitError, match="isn't an address"):
        traffic_aws.for_pov(ready, pilot_user="x y@acme.com")
    pov_all.cfg["zcc"] = {}
    with pytest.raises(KitError, match="cloud"):
        traffic_aws.for_pov(pov_all)


def test_console_endpoint(ready, monkeypatch, tenant_for):
    monkeypatch.setattr(gui, "tf", tenant_for)
    code, r = gui.api("POST", "/api/traffic/aws", {"email": "jane@acme.com"}, {})
    assert code == 200 and r["template"]["Parameters"]["PilotUser"]["Default"] == "jane@acme.com"


def test_cli_parses():
    from povkit.cli import parser
    a = parser().parse_args(["traffic", "schedule", "--every", "60", "--types", "web"])
    assert a.what == "schedule" and a.every == 60
    assert parser().parse_args(["traffic", "aws", "--user", "jane@acme.com"]).user == "jane@acme.com"
