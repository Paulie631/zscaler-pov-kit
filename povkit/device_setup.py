"""Set up a pilot device: Client Connector installed for this tenant, then the POV's own tests.

The console's Next steps > Set up a pilot device gives, per pilot user and OS:
  - a one-line command (the hosted zcc-setup.sh / zcc-setup.ps1, with this tenant's cloud, the user's domain and
    name filled in), and
  - a script file for the customer's IT to review or push: the same setup script inside, plus the POV's probe pack,
    so the device runs the tests once Client Connector is connected.
The installers are the kit's pinned copies (zcc_installers.json), checked on the device by SHA-256 and Zscaler's
signature. Nothing here touches the tenant except `detect_cloud`, a read of ZIdentity entitlements.
"""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path

from .core import KitError
from .tenant import g, items

ROOT = Path(__file__).resolve().parent
PINS = json.loads((ROOT / "zcc_installers.json").read_text(encoding="utf-8"))
SCRIPTS = {"macos": "zcc-setup.sh", "windows": "zcc-setup.ps1"}


def _script(name):
    f = ROOT / name
    if not f.exists():
        raise KitError(f"{name} is missing from this copy of the kit.")
    return f.read_text(encoding="utf-8").replace("\r\n", "\n")   # a Windows checkout mustn't break bash


def base_url():
    return f"https://github.com/{PINS['repo']}/releases/latest/download"


def cloud(pov):
    return (pov.cfg.get("zcc") or {}).get("cloud") or ""


def detect_cloud(t):
    """The Zscaler cloud name (zscalertwo...) from ZIdentity's Internet & SaaS entitlement, or None. Read-only."""
    from .identity import ZIA_SERVICE
    try:
        users = items(t.call("zid.users", "list_users", query_params={"limit": 5}))
    except KitError:
        return None
    for u in users[:5]:
        try:
            body = t.call("zid.user_entitlement", "get_service_entitlement", g(u, "id"))
        except Exception:   # noqa: BLE001 - one unreadable user shouldn't stop the others
            continue
        found = []

        def walk(x, svc=None, found=found):
            if isinstance(x, dict):
                name = next((x[k] for k in ("serviceName", "service_name") if isinstance(x.get(k), str)), svc)
                for k in ("cloudName", "cloud_name"):
                    if isinstance(x.get(k), str):
                        found.append((name or "", x[k]))
                for v in x.values():
                    walk(v, name, found)
            elif isinstance(x, list):
                for v in x:
                    walk(v, svc, found)
        walk(body)
        zia = [c for n, c in found if ZIA_SERVICE.search(n)] or [c for _, c in found]
        for c in zia:
            c = re.sub(r"\.net$", "", c.strip().lower())
            if re.fullmatch(r"[a-z0-9]+", c):
                return c
    return None


def users(pov):
    """The pilot users a device can be set up for: named pilot users and the POV's test users."""
    from .core.changelist import ChangeList
    out = [e.strip().lower() for e in pov.cfg.get("pilot_emails") or [] if "@" in e]
    cl = ChangeList(pov.dir)
    for i in (cl.plan()["items"] if cl.plan_file.exists() else []):
        b = i.get("body") or {}
        if i["kind"] == "user" and i["product"] in ("zia", "zid"):
            e = b.get("email") or b.get("login_name")
            if e and "@" in e:
                out.append(e.lower())
    return list(dict.fromkeys(out))


def split(email):
    name, _, domain = email.partition("@")
    if not (re.fullmatch(r"[A-Za-z0-9._+-]+", name) and re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", domain)):
        raise KitError(f"{email} isn't an address Client Connector can take.")
    return name, domain


def info(pov):
    return {"cloud": cloud(pov), "users": users(pov),
            "installers": {k: ({"version": v["version"], "file": v["file"]} if v else None)
                           for k, v in PINS.items() if k in ("windows", "macos")},
            "platform_releases": "Infrastructure > Common Resources > Deployment > Platform Releases"}


def _need_cloud(pov):
    c = cloud(pov)
    if not c:
        raise KitError("Set the Zscaler cloud first (Detect, or type it: zscalertwo, zscaler, zscloud...).")
    return c


def one_liner(pov, os_, email):
    c = _need_cloud(pov)
    name, domain = split(email)
    if os_ == "macos":
        return (f"curl -fsSL {base_url()}/zcc-setup.sh | bash -s -- --cloud {c} --domain {domain} --user {name}")
    if os_ == "windows":
        return (f"& ([scriptblock]::Create((irm {base_url()}/zcc-setup.ps1))) -Cloud {c} -Domain {domain} "
                f"-User {name}")
    raise KitError("The OS is macos or windows.")


def script(pov, os_, email, pack=None):
    """-> (file name, text): the setup script with this device's values and, optionally, the probe pack inside."""
    c = _need_cloud(pov)
    name, domain = split(email)
    b64 = base64.b64encode(json.dumps(pack, separators=(",", ":")).encode()).decode() if pack else ""
    body = _script(SCRIPTS[os_])
    if os_ == "macos":
        body = body.split("\n", 1)[1]   # drop its shebang: this file has its own
        text = ("#!/bin/bash\n"
                f"# Zscaler POV {pov.id}: pilot device setup for {email} (macOS). Review it, then run:\n"
                f"#   bash \"<this file>\"\n"
                f"export ZPOV_PACK_B64='{b64}' ZPOV_POV='{pov.id}'\n"
                f"set -- --cloud {c} --domain {domain} --user {name}\n" + body)
        return f"zpov-device-setup-{pov.id}-{name}.sh", text
    if os_ == "windows":
        if "'@" in body:
            raise KitError("zcc-setup.ps1 can't be embedded.")
        text = (f"# Zscaler POV {pov.id}: pilot device setup for {email} (Windows). Review it, then in PowerShell\n"
                f"# opened with 'Run as administrator':\n"
                f"#   powershell -ExecutionPolicy Bypass -File \"<this file>\"\n"
                f"$env:ZPOV_PACK_B64 = '{b64}'\n$env:ZPOV_POV = '{pov.id}'\n"
                f"& ([scriptblock]::Create(@'\n{body}\n'@)) -Cloud {c} -Domain {domain} -User {name}\n")
        return f"zpov-device-setup-{pov.id}-{name}.ps1", text
    raise KitError("The OS is macos or windows.")
