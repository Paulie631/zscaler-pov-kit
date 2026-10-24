"""Pilot-device commands: the POV's tests and the traffic generator. No API keys, nothing in any tenant changes.

This is the whole of the POV probe package (`pov-probe`), the small download a customer installs on pilot devices,
and the same code behind the full kit's `pov-kit probe` and `pov-kit traffic`. It imports only probe.py and
traffic.py, so the probe package carries no console, no tenant API code and no secrets handling.

  pov-probe pack install FILE   keep the POV's probe pack on this device (the setup script does this)
  pov-probe pack show           which POV and which criteria the pack on this device tests
  pov-probe test [--wait N]     run the pack's tests; writes a results file for the SE
  pov-probe traffic check|run|schedule   the ZIA traffic generator, shaped by the pack's traffic profile
  pov-probe cleanup             remove the Endpoint AI test items a test left
  pov-probe trust-ca            trust the Zscaler root CA on this device (if Client Connector didn't), for SSL inspection
"""
from __future__ import annotations

import argparse
import json
import hashlib
import platform
import re
import shutil
import ssl
import subprocess
import sys
from pathlib import Path

from . import VERSION, probe, traffic

HOME = traffic.DEVICE_HOME
PACK = HOME / "pack.json"


class DeviceError(Exception):
    pass


# ---------------------------------------------------------------- the probe pack on this device
def from_code(code) -> dict:
    """The probe pack as the console's commands carry it: gzip, then base64."""
    import base64
    import gzip
    try:
        return json.loads(gzip.decompress(base64.b64decode(str(code).strip())).decode("utf-8"))
    except Exception as e:   # noqa: BLE001
        raise DeviceError("That pack code is damaged: copy the command from the POV console again.") from e


def desktop() -> Path:
    d = Path.home() / "Desktop"
    return d if d.is_dir() else HOME / "results"


def read_pack(src) -> dict:
    try:
        data = json.loads(Path(src).read_text(encoding="utf-8")) if not isinstance(src, dict) else src
    except (OSError, ValueError) as e:
        raise DeviceError(f"Couldn't read the probe pack {src}: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("criteria"), list):
        raise DeviceError(f"{src} isn't a POV probe pack. In the POV console, Set up a pilot device gives a command "
                          "with the POV's tests in it.")
    return data


def install_pack(src) -> dict:
    data = read_pack(src)
    HOME.mkdir(parents=True, exist_ok=True)
    old = current_pack()
    if old and old.get("pov") and data.get("pov") and old["pov"] != data["pov"]:
        shutil.copyfile(PACK, HOME / f"pack-{old['pov']}.json")   # another POV's pack: keep a copy
    PACK.write_text(json.dumps(data, indent=1), encoding="utf-8")
    return data


def current_pack():
    try:
        return read_pack(PACK) if PACK.exists() else None
    except DeviceError:
        return None


def describe(p) -> str:
    if not p:
        return "No probe pack on this device yet. `pov-probe pack install FILE` (the SE sends the file)."
    n = sum(len(c.get("probe") or []) for c in p["criteria"])
    return (f"POV {p.get('pov')} ({p.get('customer')}), pack {p.get('pack_id') or '(no ID: an older kit made it)'}, "
            f"made {str(p.get('generated_at') or '?')[:16]}: {len(p['criteria'])} criteria, {n} tests"
            + (f"; traffic: {', '.join((p.get('traffic') or {}).get('types') or []) or 'none'}"
               if p.get("traffic") is not None else ""))


# ---------------------------------------------------------------- the tests
def base_criteria():
    """Without a pack: the full kit's catalog tests that need no POV values (the probe package has no catalog)."""
    try:
        from .products import base
    except ImportError as e:
        raise DeviceError("This device doesn't have the POV's tests yet. In the POV console: Setup > Finish setup > "
                          "Set up a pilot device > 2. Run the tests: copy that command and paste it here.") from e
    crit = [c for c in base.load_catalog() if c.get("probe")]
    crit = [dict(c, probe=[s for s in c["probe"] if not any("{" in str(v) and "{b64}" not in str(v) for v in s.values())])
            for c in crit]
    return [c for c in crit if c["probe"]]


def test(pack=None, wait=0, out=None, only=None, say=print, code=None):
    """-> (results, file written)"""
    if code:
        install_pack(from_code(code))
    p = read_pack(pack) if pack else current_pack()
    crit = p["criteria"] if p else base_criteria()
    if only:
        want = set(only)
        crit = [c for c in crit if c["id"] in want]
    if wait and not probe.wait_for_zscaler(wait, say):
        raise DeviceError(f"Traffic still doesn't go through Zscaler after {wait} minutes, so the tests would mean "
                          "nothing. Check Client Connector is signed in with Internet Security On, then run this again.")
    gate(crit)
    res = probe.run(crit, pack=p)
    path = Path(out or (desktop() / f"pov-probe-results-{(p or {}).get('pov', 'device')}-{res['run_id']}.json"))
    path.parent.mkdir(parents=True, exist_ok=True)
    probe.save(res, path)
    return res, path


def gate(crit, run_spec=None):
    """Before any test traffic: is this device in the POV's tenant, as a pilot user? Only the POV's own rule blocks
    the tenant-check page, and only for the pilot group, so a device on another tenant (a work laptop's corporate
    Client Connector, say) stops here and sends nothing else."""
    sp = next((x for c in crit if c["id"] == "IS-TEN-01" for x in c.get("probe") or []), None)
    if not sp:
        return
    import requests
    r = (run_spec or probe.run_spec)(sp, "gate", requests.Session())
    if r["outcome"] != r["expect"]:
        raise DeviceError("This device isn't in the POV's tenant as a pilot user (the POV's own test page isn't "
                          "blocked here), so no tests were run. Sign in to Client Connector as the pilot user the SE "
                          "named, with Internet Security on, then run the command again. A work laptop on its "
                          "company's Zscaler can't be a pilot device.")


# ---------------------------------------------------------------- command line (pov-probe)
def _say(level, msg):
    mark = {"ok": "✓", "warn": "!", "fail": "✗"}.get(level, "·")
    try:
        print(f"  {mark} {msg}")
    except UnicodeEncodeError:
        print(f"  {level}: {msg}")


def c_test(a):
    a.code = getattr(a, "code", None)   # the full kit's `pov-kit probe` has no --code
    if a.code or current_pack():
        print(describe(from_code(a.code) if a.code else current_pack()))
    if a.wait:
        print(f"Waiting for this device's traffic to go through Zscaler (up to {a.wait} minutes): sign in to Client "
              "Connector as the pilot user if you haven't.")
    res, path = test(a.pack, a.wait, a.out, [x for x in (a.criteria or "").split(",") if x] or None, code=a.code)
    ok = sum(r["pass"] for r in res["results"])
    for r in res["results"]:
        _say("ok" if r["pass"] else "warn", f"{r['criterion']}: {r['outcome']} (expected {r['expect']}) {r['detail']}")
    print(f"\n{ok} of {len(res['results'])} as expected. The results are in:\n  {path}\n"
          "Next: in the POV console, Set up a pilot device > 3. Import the results, and pick that file (on another "
          "computer than the SE's, send it to the SE first).")
    if any(r["spec"]["type"] == "ai_artifacts" for r in res["results"]):
        print("Endpoint AI test files stay for the console's inventory; remove them afterwards: `cleanup`.")
    return 0


def c_pack(a):
    if a.what == "install":
        if not a.file:
            raise DeviceError("Say which file: `pack install FILE`.")
        print(f"Installed. {describe(install_pack(a.file))}")
    else:
        print(describe(current_pack()))
    return 0


def c_traffic(a):
    p = current_pack()
    prof = (p or {}).get("traffic")
    if a.what == "check":
        bad = 0
        for c in traffic.check(cloud=a.cloud):
            _say({"ok": "ok", "fail": "fail"}.get(c["status"], "warn"), f"{c['label']}: {c['detail']}")
            if c["fix"]:
                print(f"        {c['fix']}")
            bad += c["status"] == "fail"
        return 1 if bad else 0
    if a.what == "schedule":
        if a.remove:
            traffic.schedule_remove()
            print("Scheduled traffic removed.")
            return 0
        types = [t for t in (a.types or "").split(",") if t] or None
        print(f"Scheduled: {traffic.schedule_install(a.every, a.count, types)}. Each round sends nothing unless "
              f"traffic goes through Zscaler, and follows the probe pack on this device. Results: {traffic.log_dir()}. "
              "Stop it: `traffic schedule --remove`.")
        return 0
    types = [t for t in (a.types or "").split(",") if t] or None
    bad = [t for t in types or [] if t not in traffic.TYPES]
    if bad:
        raise DeviceError(f"Unknown traffic type(s): {', '.join(bad)}. Use any of: {', '.join(traffic.TYPES)}.")
    if prof is not None and not types:
        print(f"Following the probe pack for POV {p.get('pov')}: {', '.join(prof.get('types') or []) or 'nothing'}.")
    res = traffic.run(types=types, count=a.count, log_dir=traffic.log_dir(), profile=prof)
    if res.get("skipped"):
        return 2
    print(f"\n{res['summary']}")
    return 0


# ---------------------------------------------------------------- the Zscaler root CA
CA_FILE = Path(__file__).with_name("zscaler_root_ca.crt")
CA_SHA256 = "b5ca18b668d1d85b51e964ee06407b0d88e48df6daabd59e93f5b74c29229997"   # Zscaler Root CA, Feb 2025 to 2052


def root_ca():
    """-> (PEM text, DER bytes) of the kit's copy of the Zscaler root CA, after checking its pinned fingerprint."""
    m = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", CA_FILE.read_text(encoding="ascii"), re.S)
    if not m:
        raise DeviceError("The kit's copy of the Zscaler root CA is missing or damaged.")
    der = ssl.PEM_cert_to_DER_cert(m.group(0))
    if hashlib.sha256(der).hexdigest() != CA_SHA256:
        raise DeviceError("The kit's copy of the Zscaler root CA doesn't match its pinned fingerprint, so it wasn't used.")
    return m.group(0) + "\n", der


def trust_ca(run=subprocess.run, system=None):
    """Adds the Zscaler root CA to this device's trusted roots (admin rights needed). -> what was done"""
    pem, _ = root_ca()
    tmp = HOME / "zscaler-root-ca.crt"
    HOME.mkdir(parents=True, exist_ok=True)
    tmp.write_text(pem, encoding="ascii")
    osname = system or platform.system()
    if osname == "Darwin":
        cmd = ["sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k",
               "/Library/Keychains/System.keychain", str(tmp)]
    elif osname == "Windows":
        cmd = ["certutil", "-addstore", "-f", "Root", str(tmp)]
    else:
        dest = "/usr/local/share/ca-certificates/zscaler-root-ca.crt"
        cmd = ["sudo", "sh", "-c", f"cp '{tmp}' {dest} && update-ca-certificates"]
    r = run(cmd)
    if getattr(r, "returncode", 0):
        raise DeviceError("Adding the certificate failed" + (": run PowerShell as administrator."
                                                              if osname == "Windows" else "."))
    return f"Zscaler Root CA (SHA-256 {CA_SHA256[:16]}...) is now a trusted root on this device."


def c_trust_ca(a):
    print(trust_ca())
    print("Check it: pov-probe traffic check (SSL inspection should say: certificate issued by Zscaler).")
    return 0


def c_cleanup(a):
    print(f"Removed {probe.cleanup_ai()} Endpoint AI test item(s).")
    return 0


def add_test_args(s):
    s.add_argument("--pack", help="a probe pack file (default: the one installed on this device)")
    s.add_argument("--wait", type=int, default=0, help="minutes to wait for traffic to go through Zscaler first")
    s.add_argument("--out", help="the results file to write")
    s.add_argument("--criteria", help="only these criterion IDs, comma-separated")
    s.add_argument("--code", help="the POV's tests as the console's command carries them (installs them first)")


def add_traffic_args(s):
    s.add_argument("what", choices=["check", "run", "schedule"])
    s.add_argument("--types", help="any of: web,saas,genai,threats,dlp,files,dns,ports (default: the pack's)")
    s.add_argument("--count", type=int, default=4, help="requests per type")
    s.add_argument("--every", type=int, default=30, help="with schedule: minutes between rounds (15 to 1440)")
    s.add_argument("--remove", action="store_true", help="with schedule: stop the scheduled rounds")
    s.add_argument("--cloud", help="with check: the Zscaler cloud traffic should reach (e.g. zscalertwo)")


def parser():
    ap = argparse.ArgumentParser(prog="pov-probe", description="Zscaler POV probe: the POV's tests on a pilot device. "
                                 "No API keys; nothing in any tenant changes.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("test", help="run the POV's tests (the probe pack's) and write a results file for the SE")
    add_test_args(s)
    s.set_defaults(fn=c_test)
    s = sub.add_parser("pack", help="pack install FILE | pack show")
    s.add_argument("what", choices=["install", "show"])
    s.add_argument("file", nargs="?")
    s.set_defaults(fn=c_pack)
    s = sub.add_parser("traffic", help="traffic check | run | schedule: ZIA traffic for the customer's dashboards")
    add_traffic_args(s)
    s.set_defaults(fn=c_traffic)
    s = sub.add_parser("cleanup", help="remove the Endpoint AI test items a test left")
    s.set_defaults(fn=c_cleanup)
    s = sub.add_parser("trust-ca", help="trust the Zscaler root CA here (Client Connector normally does this)")
    s.set_defaults(fn=c_trust_ca)
    s = sub.add_parser("version", help="print the version")
    s.set_defaults(fn=lambda a: print(VERSION) or 0)
    return ap


def main(argv=None):
    a = parser().parse_args(argv)
    try:
        return a.fn(a) or 0
    except DeviceError as e:
        print(f"\n  {e}\n", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
