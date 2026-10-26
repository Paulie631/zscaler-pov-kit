"""Self-update from GitHub releases, as in the AI Guard SE Demo Kit.

Each release publishes latest.json (version, notes, zip URL, SHA-256). The kit checks it at most every 12 hours (the
console's Updates button can force a check), downloads the zip only from GitHub, verifies its SHA-256 before anything
is replaced, and installs it into ~/.zscaler-pov-kit/app, keeping the previous copy for one-step rollback. A git
checkout is never overwritten: it's told to `git pull` instead. POVs, secrets and tenants are never touched.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import time
import zipfile
from pathlib import Path

from . import VERSION, installer
from .core import KitError
from .core.pov import BASE

REPO = os.getenv("ZPOV_KIT_REPO", "Paulie631/zscaler-pov-kit")
UPDATE_URL = os.getenv("ZPOV_KIT_UPDATE_URL", f"https://github.com/{REPO}/releases/latest/download/latest.json")
RELEASES = f"https://github.com/{REPO}/releases/latest"
CACHE = BASE / "update.json"
CACHE_HOURS = 12
TOP = "zscaler-pov-kit/"
HOSTS = ("github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com")


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def _url_ok(u):
    return bool(re.match(r"https://([a-z0-9.-]+)/", u or "")) and u.split("/")[2] in HOSTS


def fetch_release(force=False, get=None):
    """Latest release info {version, notes, zip_url, sha256}, cached for 12 hours."""
    if not force and CACHE.exists():
        try:
            c = json.loads(CACHE.read_text(encoding="utf-8"))
            if time.time() - c["at"] < CACHE_HOURS * 3600:
                return c["info"]
        except (ValueError, KeyError):
            pass
    from .core import trust
    get = get or trust.get   # trusts this computer's roots too (Client Connector's TLS inspection re-signs GitHub)
    try:   # cache-busting query and headers, so a proxy or CDN can't answer with an old latest.json
        r = get(UPDATE_URL, params={"t": int(time.time())}, timeout=15,
                headers={"Accept": "application/json", "Cache-Control": "no-cache"})
    except Exception as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            raise KitError("Couldn't check for updates: GitHub's certificate isn't trusted on this computer. If "
                           "Zscaler Client Connector inspects this laptop's traffic, its root certificate should be in "
                           "the System keychain; IT can add it, or update from Terminal with the install command "
                           "(curl uses the keychain).") from e
        raise KitError(f"Couldn't reach GitHub to check for updates: {e}") from e
    if r.status_code != 200:
        raise KitError(f"The update check failed: HTTP {r.status_code}. If your laptop's web policy blocks GitHub "
                       f"downloads, ask IT to allow {', '.join(HOSTS)}.")
    info = r.json()
    if not (info.get("version") and _url_ok(info.get("zip_url")) and re.fullmatch(r"[0-9a-f]{64}", info.get("sha256", ""))):
        raise KitError("The release information was incomplete or not in the expected format.")
    BASE.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps({"at": time.time(), "info": info}), encoding="utf-8")
    return info


def check(force=True, get=None):
    info = fetch_release(force, get)
    return info, vtuple(info["version"]) > vtuple(VERSION)


def status(force=False, get=None):
    """What the console's Updates button shows."""
    prev = installer.APP.with_name("app.previous")
    st = {"current": VERSION, "latest": None, "available": False, "notes": "", "error": None,
          "installed": installer.installed(), "git": installer.is_git(), "releases": RELEASES,
          "can_rollback": (prev / "pov_kit.py").exists()}
    try:
        info = fetch_release(force, get)
        st.update(latest=info["version"], notes=info.get("notes", ""),
                  available=vtuple(info["version"]) > vtuple(VERSION))
    except KitError as e:
        st["error"] = str(e)
    return st


def install(info, get=None, log=lambda level, msg: None):
    """Download, verify, and install the release into the app folder. -> the installed version."""
    if installer.is_git():
        raise KitError("This copy is a git checkout: update it with `git pull` instead.")
    if not _url_ok(info.get("zip_url", "")):
        raise KitError("Refusing to download an update from anywhere but GitHub.")
    from .core import trust
    get = get or trust.get
    log("info", f"Downloading {info['version']}")
    r = get(info["zip_url"], timeout=120)
    data = r.content
    if hashlib.sha256(data).hexdigest() != info["sha256"]:
        raise KitError("The download didn't match its published SHA-256, so nothing was installed.")
    log("ok", "Download verified against the release's SHA-256")
    work = BASE / "update-staging"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
        if not names or not all(n.startswith(TOP) and ".." not in n and not n.startswith("/") for n in names):
            raise KitError("The release zip isn't laid out as expected, so nothing was installed.")
        z.extractall(work)
    src = work / TOP.rstrip("/")
    if not (src / "pov_kit.py").exists():
        raise KitError("The release zip has no kit in it, so nothing was installed.")
    installer.copy_kit(src, installer.APP)
    shutil.rmtree(work, ignore_errors=True)
    log("ok", f"Installed {info['version']} in {installer.APP} (the previous version is kept for rollback)")
    installer.shortcuts(log, installer.APP)
    return info["version"]


def installed_version(folder):
    m = re.search(r'VERSION = "([^"]+)"', (Path(folder) / "povkit" / "__init__.py").read_text(encoding="utf-8")) \
        if (Path(folder) / "povkit" / "__init__.py").exists() else None
    return m.group(1) if m else "?"


def rollback():
    app, prev = installer.APP, installer.APP.with_name("app.previous")
    if not (prev / "pov_kit.py").exists():
        raise KitError("There's no previous version to roll back to.")
    tmp = app.with_name("app.rollback")
    shutil.rmtree(tmp, ignore_errors=True)
    if app.exists():
        app.rename(tmp)
    prev.rename(app)
    if tmp.exists():
        tmp.rename(prev)
    return installed_version(app)
