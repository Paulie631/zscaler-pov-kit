"""The POV probe package (pilot devices only) and how probe packs follow the POV's success criteria."""
import json
import subprocess
import sys
import zipfile

import pytest

from povkit import device, evidence, probe, settings, traffic, traffic_aws, usecases
from povkit.core import KitError

ROOT = evidence.Path(evidence.__file__).resolve().parents[1]


def fake_run(monkeypatch, outcome="block"):
    def run(criteria, session=None, pack=None):
        out = {"run_id": "r1", "device": "pilot-1", "os": "test", "at": "2026-10-23T12:00:00Z", "results": [
            {"criterion": c["id"], "spec": sp, "outcome": outcome, "expect": sp.get("expect"),
             "pass": outcome == sp.get("expect"), "detail": ""} for c in criteria for sp in c["probe"]]}
        if pack:
            out.update(pov=pack.get("pov"), pack_id=pack.get("pack_id"),
                       tests={c["id"]: c.get("hash") for c in criteria if c.get("hash")})
        return out
    monkeypatch.setattr(probe, "run", run)
    monkeypatch.setattr(probe, "run_spec", lambda sp, rid, s: {"outcome": outcome, "expect": sp.get("expect")})


def accept_uc(pov, n, changes, probe_tests=()):
    ucs = usecases.load(pov)
    ucs.append({"id": f"UC-{n:02d}", "prompt": "x", "status": "accepted", "spec": {
        "summary": "s", "changes": changes, "directions": [],
        "test": {"title": f"use case {n}", "statement": "", "probe": list(probe_tests), "aiguard": [], "attest": ""}}})
    usecases.save(pov, ucs)


def test_pack_follows_the_chosen_criteria(pov):
    settings.set_value(pov, "criteria", ["IS-TEN-01", "IS-DLP-01"])
    pack = evidence.probe_pack(pov)
    assert {c["id"] for c in pack["criteria"]} <= {"IS-TEN-01", "IS-DLP-01"} and pack["criteria"]
    assert all(c["hash"] for c in pack["criteria"]) and len(pack["pack_id"]) == 10
    assert pack["traffic"]["types"] == ["web", "dlp"]
    settings.set_value(pov, "criteria", ["IS-TEN-01", "IS-FW-01"])
    again = evidence.probe_pack(pov)
    assert again["pack_id"] != pack["pack_id"] and "ports" in again["traffic"]["types"]


def test_use_cases_shape_the_traffic(pov):
    accept_uc(pov, 1, [{"kind": "url_filtering", "name": "Block wiki", "action": "BLOCK", "urls": ["wiki.example.org"]},
                       {"kind": "firewall", "name": "No RDP", "action": "BLOCK_RESET", "tcp_ports": ["3389"],
                        "udp_ports": [], "dest_addresses": []}],
              [{"type": "http", "url": "https://wiki.example.org/", "expect": "block"}])
    pack = evidence.probe_pack(pov)
    prof = pack["traffic"]
    assert {"url": "https://wiki.example.org/", "category": "UC-01 Block wiki", "expect": "block"} in prof["web"]
    assert prof["block_ports"] == [3389] and "ports" in prof["types"]
    assert any(c["id"] == "UC-01" for c in pack["criteria"])
    cat = traffic.catalog(prof)
    assert cat["must_web"][0]["url"] == "https://wiki.example.org/" and 3389 in cat["ports"]["blocked_by_pov"]


def test_no_zia_means_no_traffic(home):
    from povkit.core import pov as povs
    p = povs.new("ZPA Only", ["zpa"])
    assert evidence.traffic_profile(p, [])["types"] == []
    r = traffic.run(profile={"types": []}, quiet=True, sess=object())
    assert r["skipped"] and r["total"] == 0


def test_device_runs_the_installed_pack_and_results_carry_it(pov, monkeypatch, tmp_path):
    fake_run(monkeypatch)
    f = tmp_path / "pack.json"
    f.write_text(json.dumps(evidence.probe_pack(pov)))
    assert device.main(["pack", "install", str(f)]) == 0
    assert device.current_pack()["pov"] == pov.id
    res, path = device.test()
    data = json.loads(path.read_text())
    assert data["pov"] == pov.id and data["pack_id"] and data["tests"]
    evidence.import_probe(pov, path)
    st = evidence.pack_status(pov)
    assert st["runs"] == 1 and not st["stale"] and st["devices"] == ["pilot-1"]


def test_stale_results_and_other_povs(pov, monkeypatch, tmp_path, home):
    from povkit.core import pov as povs
    fake_run(monkeypatch)
    pack = evidence.probe_pack(pov)
    res = probe.run([c for c in pack["criteria"] if c["id"] == "IS-TEN-01"], pack=pack)
    f = tmp_path / "r.json"
    probe.save(res, f)
    evidence.import_probe(pov, f)
    row = next(r for r in evidence.evaluate(pov) if r["criterion"]["id"] == "IS-TEN-01")
    assert row["proofs"]["probe"]["status"] == evidence.PASS
    # the criterion's tests change (a different tenant-check URL): the old run no longer proves it
    monkeypatch.setattr(evidence, "test_hash", lambda p, c: "changed!!!" if c["id"] == "IS-TEN-01" else
                        evidence._h(evidence._pack_specs(p, c, evidence._values(p))))
    row = next(r for r in evidence.evaluate(pov) if r["criterion"]["id"] == "IS-TEN-01")
    assert row["proofs"]["probe"]["status"] == evidence.INCOMPLETE and row["proofs"]["probe"]["stale"]
    other = povs.new("Other Co", ["zia"])
    with pytest.raises(KitError, match="not " + other.id):
        evidence.import_probe(other, f)


def test_old_results_without_a_pack_still_count(pov, tmp_path):
    f = tmp_path / "old.json"
    f.write_text(json.dumps({"run_id": "o1", "at": "2026-10-01T00:00:00Z", "device": "d", "results": [
        {"criterion": "IS-TEN-01", "spec": {}, "outcome": "block", "expect": "block", "pass": True, "detail": ""}]}))
    evidence.import_probe(pov, f)
    row = next(r for r in evidence.evaluate(pov) if r["criterion"]["id"] == "IS-TEN-01")
    assert row["proofs"]["probe"]["status"] == evidence.PASS


def test_the_package_has_only_the_device_parts(tmp_path):
    sys.path.insert(0, str(ROOT / "tools"))
    import package
    if subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True).returncode:
        pytest.skip("no git checkout")
    # build from the working tree's files (HEAD may not have them yet), the same mapping as the release
    z = tmp_path / "probe.zip"
    with zipfile.ZipFile(z, "w") as out:
        for src, dst in package.PROBE_SHIP.items():
            out.write(ROOT / src, package.PROBE_TOP + dst)
    names = set(zipfile.ZipFile(z).namelist())
    assert "zscaler-pov-probe/povkit/device.py" in names and not any("gui" in n or "secrets" in n for n in names)
    zipfile.ZipFile(z).extractall(tmp_path)
    app = tmp_path / "zscaler-pov-probe"
    # it runs on its own: no console, SDK, keychain or tenant code to import
    r = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, '.'); from povkit import device; "
                        "import sys as s; bad=[m for m in s.modules if m.startswith('povkit.') and m not in "
                        "('povkit.device','povkit.probe','povkit.traffic')]; print(bad); print(device.parser().prog)"],
                       cwd=app, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split("\n")[0] == "[]" and "pov-probe" in r.stdout
    help_ = subprocess.run([sys.executable, "-I", "pov_probe.py", "--help"], cwd=app, capture_output=True, text=True)
    assert help_.returncode == 0 and "test" in help_.stdout and "traffic" in help_.stdout


def test_aws_generator_carries_the_pack(pov_all):
    pov_all.cfg["zcc"] = {"cloud": "zscalertwo"}
    pov_all.save()
    name, t = traffic_aws.for_pov(pov_all)
    ud = t["Resources"]["Generator"]["Properties"]["UserData"]["Fn::Base64"]["Fn::Sub"]
    assert "__PACK_B64__" not in ud and "ZPOV_PACK_FILE" in ud and "pov-probe.cmd" in ud
    assert len(ud) < 16000


def test_kit_commands_still_work(pov, monkeypatch, tmp_path, capsys):
    from povkit import cli
    fake_run(monkeypatch)
    f = tmp_path / "pack.json"
    f.write_text(json.dumps(evidence.probe_pack(pov)))
    out = tmp_path / "res.json"
    assert cli.main(["probe", "--pack", str(f), "--out", str(out)]) in (0, None)
    assert json.loads(out.read_text())["pov"] == pov.id


def test_cloudshare_traffic_script(pov):
    from povkit.core import KitError as KE
    with pytest.raises(KE, match="cloud"):
        traffic_aws.cloudshare_script(pov)
    pov.cfg["zcc"] = {"cloud": "zscalertwo"}
    pov.save()
    name, text = traffic_aws.cloudshare_script(pov, every=5)
    assert name == f"zpov-traffic-{pov.id}.ps1"
    assert "traffic schedule --every 15" in text and "traffic check --cloud zscalertwo" in text
    assert "install-probe.ps1" in text and "pack install" in text and "{" in text and "{{" not in text
    import base64
    b64 = text.split('FromBase64String("')[1].split('"')[0]
    assert json.loads(base64.b64decode(b64))["pov"] == pov.id


def test_root_ca_pinned_and_trust_commands(tmp_path, monkeypatch):
    from povkit import device
    pem, der = device.root_ca()
    assert pem.startswith("-----BEGIN CERTIFICATE-----") and len(der) > 500
    monkeypatch.setattr(device, "HOME", tmp_path)
    for osname, word in (("Darwin", "add-trusted-cert"), ("Windows", "certutil"), ("Linux", "update-ca-certificates")):
        seen = []
        device.trust_ca(run=lambda cmd, seen=seen: seen.append(cmd) or type("R", (), {"returncode": 0})(), system=osname)
        assert word in " ".join(seen[0])


def test_pack_travels_in_the_commands(pov, tmp_path, monkeypatch):
    from povkit import device, device_setup
    pack = {"pov": pov.id, "customer": "Acme", "criteria": [{"id": "X-1", "probe": [{"type": "web"}]}]}
    code = device_setup.pack_code(pack)
    assert device.from_code(code) == pack and len(code) < 400
    monkeypatch.setattr(device_setup, "cloud", lambda p: "zscalertwo")
    mac = device_setup.one_liner(pov, "macos", "jane@acme.com", pack)
    assert f"ZPOV_PACK_GZ='{code}'" in mac and "--user jane" in mac
    win = device_setup.one_liner(pov, "windows", "jane@acme.com", pack)
    assert "$env:ZPOV_PACK_GZ=" in win
    assert f"--code '{code}'" in device_setup.test_command(pov, "macos", pack)
    monkeypatch.setattr(device, "HOME", tmp_path)
    monkeypatch.setattr(device, "PACK", tmp_path / "pack.json")
    assert device.install_pack(device.from_code(code))["pov"] == pov.id


def test_gate_stops_a_device_outside_the_tenant():
    from povkit import device
    crit = [{"id": "IS-TEN-01", "probe": [{"type": "http", "url": "https://www.example.com/", "expect": "block"}]}]
    device.gate(crit, run_spec=lambda sp, rid, s: {"outcome": "block", "expect": "block"})   # in the tenant: fine
    with pytest.raises(device.DeviceError, match="isn't in the POV's tenant"):
        device.gate(crit, run_spec=lambda sp, rid, s: {"outcome": "allow", "expect": "block"})
    device.gate([{"id": "AI-AIG-01", "probe": []}], run_spec=None)   # no ZIA tenant check in the pack: no gate


class _Resp:
    def __init__(self, status, text, ctype="text/html"):
        self.status_code, self.text, self.headers, self.history, self.url = status, text, {"Content-Type": ctype}, [], "https://x/"


def test_classify_caution_block_and_page_note():
    caution = _Resp(403, "<title>Internet Security by Zscaler</title><p>Caution: this site is social networking. "
                         "<input type=submit value='Continue'></p>")
    block = _Resp(403, "<title>Internet Security by Zscaler</title><p>Website blocked. Sorry, you don't have "
                       "permission to visit this site. Continue to learn more.</p>")
    assert probe.classify(caution) == "caution" and probe.classify(block) == "block"
    assert probe.classify(_Resp(200, "<p>hello</p>")) == "allow"
    note = probe.page_note(block)
    assert "Internet Security by Zscaler" in note and "Website blocked" in note
    assert probe.page_note(_Resp(200, "<p>hello</p>")) == ""
