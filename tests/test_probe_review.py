import pytest

from povkit import evidence
from povkit.core import KitError


def _crit(pov):
    return next(c for c in evidence.selected_criteria(pov) if c.get("probe"))


def test_review_add_leave_out_and_restore(pov):
    c = _crit(pov)
    r = evidence.pack_review(pov)
    row = next(x for x in r["rows"] if x["criterion"] == c["id"])
    n0 = r["tests"]
    first = row["tests"][0]
    assert first["source"] == "catalog" and "→ expect" in first["text"]

    added = evidence.add_test(pov, c["id"], "http", by="Paul", url="www.example.org/x", expect="block")
    assert added["url"] == "https://www.example.org/x"
    p = evidence.probe_pack(pov)
    specs = next(x for x in p["criteria"] if x["id"] == c["id"])["probe"]
    assert {"type": "http", "url": "https://www.example.org/x", "expect": "block"} in specs
    assert evidence.pack_review(pov)["tests"] == n0 + 1
    with pytest.raises(KitError):
        evidence.add_test(pov, c["id"], "http", url="www.example.org/x", expect="block")

    evidence.remove_test(pov, c["id"], first["id"])          # a catalog test: left out, can come back
    assert evidence.pack_review(pov)["tests"] == n0
    assert next(t for x in evidence.pack_review(pov)["rows"] if x["criterion"] == c["id"]
                for t in x["tests"] if t["id"] == first["id"])["skipped"]
    evidence.restore_test(pov, first["id"])
    evidence.remove_test(pov, c["id"], added["id"])            # an added test: deleted
    assert evidence.pack_review(pov)["tests"] == n0


def test_extra_checks_and_validation(pov):
    evidence.add_test(pov, "SE-EXTRA", "tcp", host="ssh.example.com", port="22", expect="block")
    p = evidence.probe_pack(pov)
    assert any(x["id"] == "SE-EXTRA" for x in p["criteria"])
    for bad in (dict(kind="http", url="not a url", expect="block"), dict(kind="tcp", host="a.com", port=0, expect="block"),
                dict(kind="dns", name="x.com", expect="open"), dict(kind="ftp", expect="block")):
        k = bad.pop("kind")
        with pytest.raises(KitError):
            evidence.add_test(pov, "SE-EXTRA", k, **bad)
    with pytest.raises(KitError):
        evidence.add_test(pov, "NOPE-1", "dns", name="x.com", expect="block")
