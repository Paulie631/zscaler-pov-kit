"""The demo-style setup flow: steps for people grouped where the setup stops, How to verify panels, and
'Continue anyway' recorded."""
import pytest

from povkit import gui, lifecycle, manual, settings
from povkit.core import KitError
from povkit.core.changelist import ChangeList


def test_stages_before_a_plan(pov_all):
    pre = manual.stage(pov_all, "preflight")
    keys = [s["key"] for s in pre["steps"]]
    assert {"setup.zdx_role", "setup.zpa_customer_id", "zia.ca.malware", "casb.ca.tenant"} <= set(keys)
    assert not pre["passed"] and pre["open"] == len(keys)
    assert [s["key"] for s in manual.stage(pov_all, "connect")["steps"]] == ["setup.api_client"]
    assert all(s.get("help", {}).get("verify") for s in pre["steps"])


def test_finish_stage_follows_apply_order(pov_all, tenant_for):
    lifecycle.plan(pov_all, tenant_for)
    ChangeList(pov_all.dir).approve("Jane Doe")
    keys = [s["key"] for s in manual.stage(pov_all, "finish")["steps"]]
    assert keys.index("zpa.ca.connectors") < keys.index("zpa.ca.users") < keys.index("zcc.ca.devices")


def test_continue_anyway_is_recorded_and_stays_on_the_list(pov_all):
    with pytest.raises(KitError, match="who"):
        manual.skip(pov_all, ["setup.zdx_role"], "")
    open_ = [s["key"] for s in manual.stage(pov_all, "preflight")["steps"]]
    manual.skip(pov_all, open_, "Paul", "ZDX later")
    st = manual.stage(pov_all, "preflight")
    assert st["passed"] and st["skipped"] == len(open_)
    zdx = next(s for s in manual.guide(pov_all) if s["key"] == "setup.zdx_role")
    assert zdx["status"] == "skipped" and zdx["skipped_by"] == "Paul"
    assert "DX-SCR-01" in manual.waiting_on(pov_all)          # still holds its criteria up
    manual.mark(pov_all, "setup.zdx_role", "Jane")
    assert next(s for s in manual.guide(pov_all) if s["key"] == "setup.zdx_role")["status"] == "done"


def test_check_help_for_preflight_checks():
    assert manual.check_help("zia-read-url_filtering")["fix"]
    assert manual.check_help("aiguard-names") == manual.check_help("zia-names")
    assert manual.check_help("keychain")["verify"] and manual.check_help("no-such-check") is None


def test_console_api(pov_all, tenant_for, monkeypatch):
    monkeypatch.setattr(gui, "tf", tenant_for)
    m = gui.api("GET", "/api/manual", {}, {})[1]
    assert m["mode"] == "live" and m["stages"]["preflight"]["open"] >= 4
    sheet = gui.api("GET", "/api/manual/sheet", {}, {"stage": "preflight"})[1]["text"]
    assert "Before the change list" in sheet and "When the POV ends" not in sheet
    gui.api("POST", "/api/manual/skip", {"stage": "preflight", "by": "Paul"}, {})
    assert gui.api("GET", "/api/state", {}, {})[1]["current"]["manual_open"]["stages"]["preflight"]["passed"]
    settings.set_value(pov_all, "manual.mode", "async")
    assert gui.api("GET", "/api/manual", {}, {})[1]["mode"] == "async"
    with pytest.raises(KitError):
        settings.set_value(pov_all, "manual.mode", "sometimes")
    r = gui.api("POST", "/api/preflight", {}, {})[1]
    assert any(c.get("help") for c in r["checks"]) or all(c["status"] == "ok" for c in r["checks"])


def test_status_checks_get_details_and_actions():
    b = manual.check_help("backup")
    assert b["action"] == "backup" and len(b["fix"]) >= 3
    assert manual.check_help("zia-present")["action"] == "fixdrift"       # *-present matches the end
    assert manual.check_help("zpa-connectors-left")["fix"]
    assert manual.check_help("zia-auth") == manual.check_help("id-signin")
    out = manual.with_help([{"id": "mcp", "status": "info"}, {"id": "nothing-here", "status": "ok"}])
    assert out[0]["help"]["action"] == "mcp" and "help" not in out[1]


def test_ai_guard_only_pov_has_no_pilot_user_checks(home, tenant_for):
    from povkit.core import pov as povs
    p = povs.new("Phish", ["aiguard"])
    _, checks = lifecycle.discover(p, tenant_for)
    assert not [c for c in checks if c["id"].startswith("id-")]


def test_backup_now_from_the_console(pov, monkeypatch, tmp_path):
    from povkit import backup
    with pytest.raises(KitError, match="aren't set up"):
        gui.api("POST", "/api/backup", {"now": True}, {})
    backup.setup(str(tmp_path / "bk"), "correct horse battery")
    r = gui.api("POST", "/api/backup", {"now": True}, {})[1]
    assert r["file"].endswith(f"{pov.id}.zpovbak")
