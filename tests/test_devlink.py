import threading
import time

from povkit import device, devlink, devtests, probe


def test_linked_device_runs_tests_live_and_uploads(pov, monkeypatch):
    monkeypatch.setattr(device, "gate", lambda c: None)
    monkeypatch.setattr(probe, "run_spec", lambda sp, rid, s: {"spec": sp, "outcome": sp.get("expect"),
                                                               "expect": sp.get("expect"), "pass": True, "detail": ""})
    opened = []
    import webbrowser
    monkeypatch.setattr(webbrowser, "open", lambda u: opened.append(u) or True)
    monkeypatch.setattr(devlink, "POLL", 1)
    st = devlink.start(pov, lambda: pov, port=18799)
    try:
        assert st["on"] and st["commands"]["macos"].endswith("'" + st["commands"]["code"] + "'")
        info = device.link_from_code(st["commands"]["code"])
        info["u"] = [f"http://127.0.0.1:{st['port']}"]
        lk = device.Link(info, say=lambda *a: None)
        lk.hello()
        threading.Thread(target=lk.serve, daemon=True).start()
        time.sleep(0.3)
        devs = devlink.devices(pov)
        assert len(devs) == 1 and devs[0]["online"]
        lib = devtests.library(pov)
        crit = next(c for c in lib["criteria"] if c["criterion"] == "IS-URL-01")
        seen = []
        out = devtests.run(pov, [t["id"] for t in crit["tests"]], on_result=seen.append, on_device=devs[0]["id"])
        assert out["total"] == len(crit["tests"]) == len(seen) and out["evidence"] == ["IS-URL-01"]
        assert all(r["id"] for r in seen)
        devtests.open_here(pov, crit["tests"][0]["id"], devs[0]["id"])
        for _ in range(30):
            if opened:
                break
            time.sleep(0.1)
        assert opened == [crit["tests"][0]["open"]]
        # a run started on the device itself lands in the console too
        res = probe.run([{"id": "IS-URL-02", "probe": [{"type": "http", "url": "https://www.facebook.com/",
                                                         "expect": "caution"}]}])
        r = lk.post("/agent/upload", {"res": res})
        assert r["imported"] and devlink.devices(pov)[0]["last"]["ok"] == 1
        # a wrong token is refused
        bad = device.Link(dict(info, t="nope"), say=lambda *a: None)
        try:
            bad.hello()
            raise AssertionError("should refuse")
        except device.DeviceError:
            pass
    finally:
        devlink.stop(pov)
        devlink.DEVICES.clear()
