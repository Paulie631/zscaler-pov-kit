"""Steps for people: shown before the POV, the values to paste, and the criteria each open step holds up."""
from povkit import gui, lifecycle, manual
from povkit.core.changelist import ChangeList


def planned(p, tenant_for):
    lifecycle.plan(p, tenant_for)
    ChangeList(p.dir).approve("Jane Doe")
    return p


def test_preview_before_a_pov_exists():
    keys = [s["key"] for s in manual.preview(["zia", "zcc"])]
    assert keys[0] == "setup.api_client" and "zia.ca.malware" in keys and "zcc.ca.devices" in keys
    assert "setup.zpa_customer_id" not in keys and keys[-1] == "end.api_clients"
    assert "zpa.ca.connectors" in [s["key"] for s in manual.preview(["zpa"])]


def test_values_and_what_each_step_holds_up(pov_all, tenant_for):
    planned(pov_all, tenant_for)
    steps = {s["key"]: s for s in manual.guide(pov_all)}
    assert {"label": "API client name", "value": f"ZPOV {pov_all.id}"} in steps["setup.api_client"]["values"]
    labels = {v["label"]: v["value"] for v in steps["zpa.ca.connectors"]["values"]}
    assert labels["Connector group"].startswith("ZPOV") and "Provisioning key name" in labels
    assert "IS-THR-01" in steps["zia.ca.malware"]["criteria"]
    dev = steps["zcc.ca.devices"]["criteria"]
    assert "IS-ZCC-01" in dev and "IS-TEN-01" in dev           # every device-proved criterion waits on devices
    assert steps["setup.zdx_role"]["criteria"] == ["DX-SCR-01"]
    wait = manual.waiting_on(pov_all)
    assert any(w["key"] == "zia.ca.malware" for w in wait["IS-THR-01"])
    sheet = manual.sheet_md(pov_all)
    assert "Values to use:" in sheet and "Holds up:" in sheet


def test_done_steps_hold_nothing_up(pov_all, tenant_for):
    planned(pov_all, tenant_for)
    manual.mark(pov_all, "zia.ca.malware", "Jane")
    assert all(w["key"] != "zia.ca.malware" for ws in manual.waiting_on(pov_all).values() for w in ws)


def test_console_shows_it(pov_all, tenant_for, monkeypatch):
    planned(pov_all, tenant_for)
    monkeypatch.setattr(gui, "tf", tenant_for)
    st = gui.api("GET", "/api/state", {}, {})[1]
    assert st["current"]["manual_open"]["open"] >= 3
    rows = gui.api("GET", "/api/criteria", {}, {})[1]["rows"]
    thr = next(r for r in rows if r["criterion"]["id"] == "IS-THR-01")
    assert any(w["key"] == "zia.ca.malware" for w in thr["waiting_on"])
    prev = gui.api("GET", "/api/manual/preview", {}, {"products": "zia,zpa"})[1]["steps"]
    assert any(s["key"] == "zpa.ca.users" for s in prev)
