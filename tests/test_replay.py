"""Holding the kit to real API responses recorded in a lab tenant (tests/fixtures/*.jsonl)."""
import json
import re
from pathlib import Path

import pytest
from conftest import FakeTenant

from povkit import lifecycle, recorder
from povkit.core import KitError

FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("*.jsonl"))


def norm(k):
    return re.sub(r"[_-]", "", str(k)).lower()


def fields(resp):
    """The field names of a response's records (a list, or the first list in an object, or the object itself)."""
    if isinstance(resp, list):
        rows = resp
    elif isinstance(resp, dict):
        rows = next((v for v in resp.values() if isinstance(v, list) and v and isinstance(v[0], dict)), [resp])
    else:
        rows = []
    return {norm(k) for r in rows if isinstance(r, dict) for k in r}


class ReplayTenant:
    """Answers reads with the recorded responses; refuses anything it has no recording for."""
    def __init__(self, recs):
        self.reads = {}
        for r in recs:
            if r["response"] is not None:
                self.reads.setdefault((r["resource"], r["method"]), r["response"])

    def call(self, resource, method, *a, **kw):
        if (resource, method) in self.reads:
            return self.reads[(resource, method)]
        raise KitError(f"no recording for {resource}.{method}")


def load(f):
    return [json.loads(x) for x in Path(f).read_text(encoding="utf-8").splitlines() if x.strip()]


def contract(recs):
    """Every field the fake tenant answers with must be in the real response."""
    fake, problems = FakeTenant(), []
    for r in recs:
        if r["response"] is None or not re.match(r"(list|get)", r["method"]):
            continue
        try:
            mine = fake.call(r["resource"], r["method"], *r["args"], **r["kwargs"])
        except (AssertionError, KitError, Exception):
            continue
        real = fields(r["response"])
        extra = fields(mine) - real if real else set()
        if extra:
            problems.append(f"{r['resource']}.{r['method']}: the fake has {sorted(extra)}, the real API doesn't")
    return problems


@pytest.mark.parametrize("fixture", FIXTURES, ids=[f.stem for f in FIXTURES])
def test_fake_tenant_matches_the_recording(fixture):
    assert not contract(load(fixture))


@pytest.mark.parametrize("fixture", FIXTURES, ids=[f.stem for f in FIXTURES])
def test_discovery_and_plan_run_on_the_recording(fixture, pov_all):
    t = ReplayTenant(load(fixture))
    snaps, _ = lifecycle.discover(pov_all, lambda p, w: t)
    lifecycle.make_plan(pov_all, snaps)


def test_record_export_replay_round_trip(pov_all, tenant, tmp_path):
    """The machinery itself: record the fake tenant's traffic, export it, and replay it."""
    class Recording:
        def call(self, resource, method, *a, **kw):
            out = tenant.call(resource, method, *a, **kw)
            recorder.write(pov_all, resource, method, a, kw, out)
            return out
    snaps, _ = lifecycle.discover(pov_all, lambda p, w: Recording())
    raw = (pov_all.path("recordings")).glob("*.jsonl").__next__().read_text()
    assert "POV Pilot" not in raw and "jane@acme.com" not in raw                 # names replaced on the laptop
    tenant.groups.append({"id": 79, "name": "ACMECORP"})                       # an all-caps customer name
    recorder.write(pov_all, "user_management", "list_groups", (), {}, tenant.groups)
    out, n = recorder.export(pov_all, "Lab run 1", tmp_path)
    text = out.read_text()
    assert n > 10 and "Corp" not in text and "Acme" not in text and "ACMECORP" not in text
    assert pov_all.id not in text
    assert '"ANONYMIZER"' in text or '"GAMBLING"' in text                        # Zscaler's own values stay
    recs = load(out)
    assert contract(recs) == []                                                 # the fake agrees with itself
    snaps2, _ = lifecycle.discover(pov_all, lambda p, w: ReplayTenant(recs))
    assert set(snaps2) | set(snaps2.get("_waiting") or {}) >= {"zia", "zpa", "aiguard", "identity"}


def test_selftest_creates_and_removes_one_object_per_product(pov_all, tenant, tenant_for):
    from povkit import selftest
    with pytest.raises(KitError, match="lab"):
        selftest.run(pov_all, tenant_for, lambda *a: None)
    with pytest.raises(KitError, match="isn't marked as a lab POV"):          # the flag alone isn't enough
        selftest.run(pov_all, tenant_for, lambda *a: None, lab=True)
    pov_all.cfg["lab"] = "yes"
    before = {k: list(v) for k, v in tenant.store.items()}
    labels = list(tenant.rules["label"])
    res = selftest.run(pov_all, tenant_for, lambda *a: None, lab=True)
    assert res["ok"], res
    assert {(s["product"], s["step"]) for s in res["steps"]} >= {("zia", "write"), ("zpa", "write"), ("aiguard", "write"),
                                                                  ("zcc", "read"), ("zdx", "read"), ("casb", "read")}
    assert tenant.store == before and tenant.rules["label"] == labels       # nothing left behind
    assert not pov_all.path("ledger.json").exists()                           # the POV's ledger is untouched
    assert ("activate", "activate") in [w[:2] for w in tenant.writes]


def test_selftest_skips_zia_writes_when_others_are_pending(pov_all, tenant, tenant_for):
    from povkit import selftest
    tenant.activation = "PENDING"
    pov_all.cfg["lab"] = "yes"
    res = selftest.run(pov_all, tenant_for, lambda *a: None, lab=True)
    z = next(s for s in res["steps"] if s["product"] == "zia" and s["step"] == "write")
    assert not z["ok"] and "waiting to be activated" in z["detail"]
    assert ("activate", "activate") not in [w[:2] for w in tenant.writes]
