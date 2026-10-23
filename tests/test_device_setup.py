"""Set up a pilot device: one-liners and scripts for macOS and Windows, cloud detection, and the probe's wait."""
import base64
import json
import subprocess
import sys

import pytest

from povkit import device_setup as ds, gui, lifecycle, probe
from povkit.core import KitError
from povkit.core.changelist import ChangeList


@pytest.fixture
def ready(pov_all, tenant_for):
    lifecycle.plan(pov_all, tenant_for)
    ChangeList(pov_all.dir).approve("Jane Doe")
    pov_all.cfg["zcc"] = {"cloud": "zscalertwo"}
    pov_all.save()
    return pov_all


def test_one_liners_fill_in_cloud_domain_and_user(ready):
    mac = ds.one_liner(ready, "macos", "jane@acme.com")
    assert mac.endswith("zcc-setup.sh | bash -s -- --cloud zscalertwo --domain acme.com --user jane")
    win = ds.one_liner(ready, "windows", "jane@acme.com")
    assert "zcc-setup.ps1" in win and "-Cloud zscalertwo -Domain acme.com -User jane" in win
    with pytest.raises(KitError):
        ds.one_liner(ready, "macos", "jane; rm -rf /@acme.com")


def test_needs_a_cloud(pov_all):
    with pytest.raises(KitError, match="cloud"):
        ds.one_liner(pov_all, "macos", "jane@acme.com")


def test_scripts_carry_the_probe_pack_and_parse(ready, tmp_path):
    from povkit import evidence
    pack = evidence.probe_pack(ready)
    name, text = ds.script(ready, "macos", "jane@acme.com", pack)
    assert name.endswith("-jane.sh") and "set -- --cloud zscalertwo --domain acme.com --user jane" in text
    b64 = text.split("ZPOV_PACK_B64='", 1)[1].split("'", 1)[0]
    assert json.loads(base64.b64decode(b64)) == json.loads(json.dumps(pack))
    assert "\r" not in text
    if sys.platform != "win32":   # Windows' bash.exe is WSL, which can't read the temp path
        f = tmp_path / name
        f.write_text(text)
        assert subprocess.run(["bash", "-n", str(f)]).returncode == 0
    name, text = ds.script(ready, "windows", "jane@acme.com", pack)
    assert name.endswith(".ps1") and "-Cloud zscalertwo -Domain acme.com -User jane" in text and "@'\n" in text


def test_users_include_test_users_and_named_ones(ready):
    assert "jane@acme.com" in ds.users(ready)


def test_detect_cloud_reads_the_entitlement(tenant):
    from povkit.core.guard import ReadOnlyTenant

    class T:
        def call(self, res, method, *a, **kw):
            if res == "zid.users":
                return [{"id": "u1"}]
            return {"services": [{"serviceName": "ZPA", "cloudName": "private"},
                                 {"serviceName": "ZIA", "cloudName": "zscalertwo.net"}]}
    assert ds.detect_cloud(ReadOnlyTenant(T())) == "zscalertwo"

    class P:   # no cloud in ZIdentity: ZIA's default PAC file names the gateway
        def call(self, res, method, *a, **kw):
            if res == "zid.users":
                return [{"id": "u1"}]
            if res == "pac_files":
                return [{"pacContent": 'return "PROXY gateway.zscalerthree.net:80; DIRECT";'}]
            return {"services": [{"serviceName": "ZIA"}]}
    assert ds.detect_cloud(ReadOnlyTenant(P())) == "zscalerthree"


def test_gui_endpoints(ready, tenant_for, monkeypatch):
    monkeypatch.setattr(gui, "tf", tenant_for)
    assert gui.api("GET", "/api/device", {}, {})[1]["cloud"] == "zscalertwo"
    assert gui.api("POST", "/api/device/cloud", {"cloud": "zscaler"}, {})[1]["cloud"] == "zscaler"
    with pytest.raises(KitError):
        gui.api("POST", "/api/device/cloud", {"cloud": "zscaler two"}, {})
    r = gui.api("POST", "/api/device/setup", {"os": "windows", "email": "jane@acme.com"}, {})[1]
    assert "-Cloud zscaler " in r["line"]
    r = gui.api("POST", "/api/device/setup", {"os": "macos", "email": "jane@acme.com", "what": "script"}, {})[1]
    assert r["text"].startswith("#!/bin/bash")


def test_wait_for_zscaler(monkeypatch):
    seq = iter([False, False, True])
    monkeypatch.setattr(probe, "via_zscaler", lambda s: (next(seq), ""))
    assert probe.wait_for_zscaler(1, lambda *a: None, session=__import__('types').SimpleNamespace(headers={}), sleep=lambda s: None, every=0)
    monkeypatch.setattr(probe, "via_zscaler", lambda s: (False, ""))
    assert not probe.wait_for_zscaler(0, lambda *a: None, session=__import__('types').SimpleNamespace(headers={}), sleep=lambda s: None)


def test_pins_are_well_formed():
    w = ds.PINS["windows"]
    assert len(w["sha256"]) == 64 and w["file"].endswith(".msi")
