"""The four-step Setup: Review & apply stands in for Preflight, and the console knows the POV's criteria."""
from povkit import gui
from povkit.core import secrets


def test_review_and_apply_checks_this_computer(pov, tenant_for, monkeypatch):
    monkeypatch.setattr(gui, "TENANT_FOR", tenant_for)
    monkeypatch.setattr(secrets, "keychain_works", lambda: (False, "locked"))
    r = gui.api("POST", "/api/plan", {}, {})[1]
    assert r["checks"][0]["id"] == "keychain" and r["checks"][0]["status"] == "fail"


def test_state_lists_the_criteria(pov):
    pov.cfg["criteria"] = ["PA-PRA-01"]
    pov.save()
    assert gui.pov_state(pov)["criteria"] == ["PA-PRA-01"]


def test_console_has_four_steps():
    html = (gui.Path(gui.__file__).parent / "console.html").read_text(encoding="utf-8")
    assert "function barSteps(){return !S||!S.current||seMode()?[1,2,4,7]:[1,2,4,5,6,7]}" in html
    assert 'id="wnew"' not in html and 'id="wopts"' in html
