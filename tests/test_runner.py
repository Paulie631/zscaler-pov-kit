import json
import threading
import time
import urllib.request

from povkit import demo, device, evidence, probe, runner


def test_runner_runs_tests_and_saves_results(pov, monkeypatch, tmp_path):
    pack = evidence.probe_pack(pov)
    monkeypatch.setattr(device, "HOME", tmp_path / "probe")
    monkeypatch.setattr(device, "PACK", tmp_path / "probe" / "pack.json")
    monkeypatch.setattr(device, "LINK", tmp_path / "probe" / "link.json")
    monkeypatch.setattr(device, "desktop", lambda: tmp_path / "Desktop")
    device.install_pack(pack)
    monkeypatch.setattr(device, "gate", lambda c: None)
    monkeypatch.setattr(probe, "run_spec", lambda sp, rid, s: {"spec": sp, "outcome": sp.get("expect"),
                                                               "expect": sp.get("expect"), "pass": True, "detail": ""})
    st = runner.state()
    assert st["pack"]["pov"] == pov.id and st["library"]["stories"] and not st["link"]
    # the same test IDs as the console's
    c0 = pack["criteria"][0]
    assert st["library"]["criteria"][0]["tests"][0]["id"] == evidence.spec_id(c0["id"], c0["probe"][0]) \
        == demo.spec_id(c0["id"], c0["probe"][0])
    ids = [t["id"] for t in st["library"]["criteria"][1]["tests"]]
    runner.start(ids)
    for _ in range(50):
        if runner.JOB.get("done"):
            break
        time.sleep(0.05)
    r = runner.JOB["result"]
    assert r["ok"] == r["total"] == len(ids) and r["file"] and not r["sent"]
    saved = json.loads(open(r["file"]).read())
    assert saved["pov"] == pov.id and len(saved["results"]) == len(ids)
    runner.start(ids, record=False)   # a Show it step: nothing saved
    for _ in range(50):
        if runner.JOB.get("done"):
            break
        time.sleep(0.05)
    assert runner.JOB["result"]["file"] is None


def test_runner_page_needs_its_token():
    t = threading.Thread(target=lambda: runner.serve(port=18795, open_browser=False), daemon=True)
    t.start()
    time.sleep(0.4)
    html = urllib.request.urlopen("http://127.0.0.1:18795/").read().decode()
    assert "POV device tests" in html and "__TOKEN__" not in html
    try:
        urllib.request.urlopen("http://127.0.0.1:18795/api/state")
        raise AssertionError("no token should be refused")
    except urllib.error.HTTPError as e:
        assert e.code == 403
