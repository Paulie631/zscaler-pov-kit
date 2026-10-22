"""Self-update from GitHub releases, as in the demo kit: latest.json names the version, zip URL and SHA-256; the zip
is verified before anything is replaced, and the previous copy is kept for one-step rollback."""
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

from . import VERSION
from .core import KitError
from .core.pov import BASE

REPO = os.getenv("ZPOV_KIT_REPO", "Paulie631/zscaler-pov-kit")
UPDATE_URL = os.getenv("ZPOV_KIT_UPDATE_URL", f"https://github.com/{REPO}/releases/latest/download/latest.json")
APP = BASE / "app"
PREVIOUS = BASE / "app.previous"
TOP = "zscaler-pov-kit/"
HOSTS = ("github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com")


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def _url_ok(u):
    return bool(re.match(r"https://([a-z0-9.-]+)/", u or "")) and u.split("/")[2] in HOSTS


def fetch_release(get=None):
    import requests
    get = get or requests.get
    try:
        r = get(UPDATE_URL, params={"t": int(time.time())}, timeout=15,
                headers={"Accept": "application/json", "Cache-Control": "no-cache"})
    except Exception as e:
        raise KitError(f"Couldn't reach GitHub to check for updates: {e}") from e
    if r.status_code != 200:
        raise KitError(f"The update check failed: HTTP {r.status_code}. If your laptop's web policy blocks GitHub "
                       f"downloads, ask IT to allow {', '.join(HOSTS)}.")
    info = r.json()
    if not (info.get("version") and _url_ok(info.get("zip_url")) and re.fullmatch(r"[0-9a-f]{64}", info.get("sha256", ""))):
        raise KitError("The release information was incomplete or not in the expected format.")
    return info


def check(get=None):
    info = fetch_release(get)
    return info, vtuple(info["version"]) > vtuple(VERSION)


def install(info, get=None, app=APP, previous=PREVIOUS):
    import requests
    get = get or requests.get
    r = get(info["zip_url"], timeout=120)
    data = r.content
    if hashlib.sha256(data).hexdigest() != info["sha256"]:
        raise KitError("The download didn't match its published SHA-256, so nothing was installed.")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
        if not names or not all(n.startswith(TOP) and ".." not in n for n in names):
            raise KitError("The release zip isn't laid out as expected, so nothing was installed.")
        staging = Path(str(app) + ".new")
        shutil.rmtree(staging, ignore_errors=True)
        z.extractall(staging)
    if previous.exists():
        shutil.rmtree(previous)
    if app.exists():
        app.rename(previous)
    (staging / TOP.rstrip("/")).rename(app)
    shutil.rmtree(staging, ignore_errors=True)
    (app / "installed.json").write_text(json.dumps({"version": info["version"], "at": time.time()}), encoding="utf-8")
    return info["version"]


def rollback(app=APP, previous=PREVIOUS):
    if not previous.exists():
        raise KitError("There's no previous version to roll back to.")
    tmp = Path(str(app) + ".rollback")
    shutil.rmtree(tmp, ignore_errors=True)
    if app.exists():
        app.rename(tmp)
    previous.rename(app)
    if tmp.exists():
        tmp.rename(previous)
