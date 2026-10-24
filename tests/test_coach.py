from povkit import coach


def test_checklist_and_rehearsal(pov):
    s = coach.summary(pov)
    assert s["total"] >= 8 and s["next"]["id"] == "connect" and not s["rehearsal"]
    pov.cfg["lab"] = "yes"
    pov.save()
    s = coach.summary(pov)
    assert s["rehearsal"] and any(x["rehearsal"] for x in s["steps"])
    coach.mark(pov, "apply", False, "timed out | on ZIA")
    md = coach.report_md(pov)
    assert "**problem**" in md and "timed out / on ZIA" in md
    assert next(x for x in coach.steps(pov) if x["id"] == "apply")["mark"]["ok"] is False
