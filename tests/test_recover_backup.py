"""A lost laptop must not strand POV objects: recover finds them from the tenant, backups restore the ledger."""
import pytest

from povkit import backup, lifecycle, recover
from povkit.core import KitError
from povkit.core import pov as povs
from povkit.core.changelist import ChangeList
from povkit.core.ledger import Ledger

log = lambda *a: None  # noqa: E731


def applied(pov, tenant_for):
    lifecycle.plan(pov, tenant_for)
    ChangeList(pov.dir).approve("Jane Doe")
    lifecycle.apply(pov, tenant_for, log)
    return Ledger(pov.path("ledger.json"), pov.id, pov.prefix)


def test_recover_rebuilds_the_ledger_and_teardown_cleans_up(pov_all, tenant, tenant_for):
    before = {(e["product"], e["kind"], e["id"]) for e in applied(pov_all, tenant_for).active()}
    tenant.rules["url_filtering"].append({"id": 4242, "name": "ZPOV: Block gambling", "order": 9,
                                          "description": "zpov:someone-else-1a2b POV kit: another SE's POV"})
    pov_all.path("ledger.json").unlink()                                   # the laptop's ledger is gone
    finds, problems = recover.run(pov_all, tenant_for)
    assert not problems and not pov_all.path("ledger.json").exists()       # a report, nothing written
    found = {(f["product"], f["kind"], f["id"]) for f in finds if f["proof"] != "other POV"}
    sweepable = {x for x in before if x[0] != "zdx"}                       # deep traces end on their own
    assert found == sweepable
    other = next(f for f in finds if f["id"] == "4242")
    assert other["proof"] == "other POV" and other["status"].startswith("left alone")
    assert {f["proof"] for f in finds if f["product"] == "zia"} >= {"stamp"}

    finds, _ = recover.run(pov_all, tenant_for, write=True)
    led = Ledger(pov_all.path("ledger.json"), pov_all.id, pov_all.prefix)
    assert {(e["product"], e["kind"], e["id"]) for e in led.active()} == sweepable
    assert led.find("zia.label") and led.find("zpa.access_rule")           # keys matched to the saved change list
    assert led.find("zcc.fwd")["state"] == "adopted"                       # name only: kept unless the SE says yes

    lifecycle.teardown(pov_all, tenant_for, log, include_adopted=True)
    assert tenant.by_name("url_filtering", "ZPOV: Block gambling")["id"] == 4242   # the other POV's rule stays
    assert tenant.by_name("url_filtering", "Corp: Block adult")
    left = [o for v in tenant.store.values() for o in v if str(o.get("name", "")).startswith("ZPOV")
            and v is not tenant.store["zdx.troubleshooting"]]
    assert not left


def test_recover_on_a_new_laptop_starts_an_empty_pov_with_the_same_id(home, tenant, tenant_for):
    p = povs.create_with_id("acme-corp-9z9z", "Acme Corp", ["zia"])
    assert p.id == "acme-corp-9z9z" and p.cfg["recovered"]
    finds, _ = recover.run(p, tenant_for)
    assert finds == []                                                     # nothing of this POV in the tenant


def test_backup_is_encrypted_and_restores(pov_all, tenant, tenant_for, tmp_path):
    with pytest.raises(KitError, match="12 characters"):
        backup.setup(str(tmp_path / "bk"), "short")
    backup.setup(str(tmp_path / "bk"), "correct horse battery")
    led = applied(pov_all, tenant_for)
    f = tmp_path / "bk" / f"{pov_all.id}.zpovbak"
    blob = f.read_bytes()
    assert b"POV Pilot" not in blob and b"ZPOV" not in blob                 # encrypted
    import shutil
    shutil.rmtree(pov_all.dir)                                             # the laptop is gone
    with pytest.raises(KitError, match="Wrong passphrase"):
        backup.restore(pov_all.id, "wrong passphrase!!")
    p = backup.restore(pov_all.id, "correct horse battery")
    led2 = Ledger(p.path("ledger.json"), p.id, p.prefix)
    assert [e["id"] for e in led2.active()] == [e["id"] for e in led.active()]
    assert ChangeList(p.dir).approval()["by"] == "Jane Doe"
    lifecycle.teardown(p, tenant_for, log, include_adopted=True)
    assert not [o for o in tenant.store["zpa.policies"] if o["name"].startswith("ZPOV")]


def test_status_warns_when_nothing_is_backed_up(pov_all, tenant_for):
    applied(pov_all, tenant_for)
    c = {x["id"]: x for x in lifecycle.status(pov_all, tenant_for)}["backup"]
    assert c["status"] == "warn" and "backup setup" in c["fix"]


# ---- end dates and reminders
def test_end_date_warns_then_fails_with_objects_left(pov_all, tenant_for, monkeypatch):
    import datetime as dt

    from povkit import remind
    assert pov_all.cfg["ends"]                                             # 30 days by default
    applied(pov_all, tenant_for)
    end = dt.date.fromisoformat(pov_all.cfg["ends"])
    monkeypatch.setattr(remind, "today", lambda: end - dt.timedelta(days=3))
    assert remind.end_check(pov_all)["status"] == "warn"
    monkeypatch.setattr(remind, "today", lambda: end + dt.timedelta(days=2))
    c = remind.end_check(pov_all)
    assert c["status"] == "fail" and "still in the tenant" in c["detail"]
    sent = []
    urgent, _ = remind.run(weekly=False, send=lambda t, b: sent.append((t, b)))
    assert sent and "Acme Corp" in sent[0][1] and "action needed" in sent[0][0]
    lifecycle.teardown(pov_all, tenant_for, log, include_adopted=True)
    pov_all.cfg["state"] = "handed_over"
    pov_all.save()
    assert remind.end_check(pov_all)["status"] == "ok"
    sent.clear()
    remind.run(weekly=False, send=lambda t, b: sent.append((t, b)))
    assert not sent


def test_end_date_setting_is_validated(pov_all):
    from povkit import settings
    assert settings.set_value(pov_all, "ends", "2026-12-15") == "2026-12-15"
    with pytest.raises(KitError, match="date like"):
        settings.set_value(pov_all, "ends", "next friday")
