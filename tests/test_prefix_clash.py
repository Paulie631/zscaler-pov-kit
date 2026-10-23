"""Two POVs in one tenant (a lab): the second gets its own prefix, and a clash says whose names they are."""
import pytest

from povkit import lifecycle, settings
from povkit.core import KitError, pov as povs
from povkit.core.checks import FAIL, check


def applied(p):
    p.cfg["state"] = "applied"
    p.save()


def test_new_povs_avoid_a_prefix_in_use(home):
    a = povs.new("Anyco", ["zia"])
    assert a.prefix == "ZPOV"
    b = povs.new("Test co", ["zia"])
    assert b.prefix == "ZPOV"          # nothing in a tenant yet: no clash
    applied(a)
    c = povs.new("Third", ["zia"])
    assert c.prefix == "ZPOV2"
    assert povs.new("Fourth", ["zia"], prefix="LAB").prefix == "LAB"


def test_prefix_changes_only_before_apply(home):
    a = povs.new("Anyco", ["zia"])
    applied(a)
    b = povs.new("Test co", ["zia"], prefix="LAB")
    with pytest.raises(KitError, match="Another POV"):
        settings.set_value(b, "prefix", "ZPOV")
    settings.set_value(b, "prefix", "ZPOV2")
    assert povs.Pov(b.id).prefix == "ZPOV2"
    with pytest.raises(KitError, match="letters"):
        settings.set_value(b, "prefix", "2bad!")


def test_clash_names_the_other_pov_and_the_fix(home):
    a = povs.new("Anyco", ["zia"])
    applied(a)
    b = povs.new("Test co", ["zia"], prefix="ZPOV")
    checks = [check("zia-names", "ZIA: POV names are free", FAIL, "'ZPOV: Block gambling' (URL filtering)")]
    lifecycle.name_clash(b, checks)
    c = checks[0]
    assert a.id in c["detail"] and "Use prefix ZPOV2 on the Apply step" in c["fix"] and c["prefix_alt"] == "ZPOV2"


def test_leftover_objects_suggest_a_new_prefix_too(home):
    b = povs.new("Test co", ["zia"])
    checks = [check("aiguard-names", "AI Guard: POV names are free", FAIL, "'ZPOV: POV app' (App)")]
    lifecycle.name_clash(b, checks)
    assert "Use prefix ZPOV2" in checks[0]["fix"] and "aren't this POV's" in checks[0]["detail"]
