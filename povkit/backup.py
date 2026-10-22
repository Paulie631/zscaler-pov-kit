"""Encrypted backups of what a POV needs to clean up after itself, so a lost laptop can't strand objects in a
customer's tenant.

After every change to the tenant (apply, Fix drift, teardown, recover, handover) the kit writes one file per POV,
<backup folder>/<pov-id>.zpovbak, holding pov.json, ledger.json, approval.json and plan.json. No secrets are in any of
them; the plan does hold customer names (the pilot group, the app's domains), so the file is encrypted with a key
derived from a passphrase the SE chooses (scrypt, then AES via Fernet). The passphrase is kept in this laptop's
keychain for automatic backups, and in the SE's password manager for a restore on a new laptop.

Pick a folder that is synced off the laptop (OneDrive, Google Drive, iCloud Drive). Backups never block the work:
if one fails, the kit logs a warning and status says so.
"""
from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path

from .core import KitError, secrets
from .core import pov as povs

PASS = ("_global", "backup-passphrase")
FILES = ("pov.json", "ledger.json", "approval.json", "plan.json")
MAGIC = "zpovbak1"


def kit_cfg_path() -> Path:
    return povs.BASE / "kit.json"


def kit_cfg() -> dict:
    p = kit_cfg_path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def save_kit_cfg(cfg):
    povs.BASE.mkdir(parents=True, exist_ok=True)
    kit_cfg_path().write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def folder() -> Path | None:
    d = kit_cfg().get("backup_dir")
    return Path(d).expanduser() if d else None


def _key(passphrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    raw = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def encrypt(data: dict, passphrase: str) -> bytes:
    from cryptography.fernet import Fernet
    salt = os.urandom(16)
    token = Fernet(_key(passphrase, salt)).encrypt(json.dumps(data).encode("utf-8"))
    return json.dumps({"format": MAGIC, "salt": base64.b64encode(salt).decode(), "data": token.decode()}).encode()


def decrypt(blob: bytes, passphrase: str) -> dict:
    from cryptography.fernet import Fernet, InvalidToken
    try:
        env = json.loads(blob)
        assert env.get("format") == MAGIC
    except Exception as e:
        raise KitError("That isn't a POV kit backup file.") from e
    try:
        return json.loads(Fernet(_key(passphrase, base64.b64decode(env["salt"]))).decrypt(env["data"].encode()))
    except InvalidToken as e:
        raise KitError("Wrong passphrase for this backup.") from e


def setup(directory: str, passphrase: str):
    if len(passphrase or "") < 12:
        raise KitError("Use a passphrase of 12 characters or more, and keep it in your password manager: it's the "
                       "only way to restore on a new laptop.")
    d = Path(directory).expanduser()
    d.mkdir(parents=True, exist_ok=True)
    probe = d / ".zpov-write-test"
    probe.write_text("ok", encoding="utf-8")
    probe.unlink()
    secrets.put(*PASS, passphrase)
    cfg = kit_cfg()
    cfg["backup_dir"] = str(d)
    save_kit_cfg(cfg)
    for pid in povs.all_povs():   # back up every POV now
        save(povs.Pov(pid))
    return d


def save(pov, quiet=True):
    """Back up one POV. Never raises unless quiet=False: a failed backup must not stop apply or teardown."""
    d, pw = folder(), secrets.get(*PASS)
    if not d or not pw:
        return None
    try:
        data = {"pov_id": pov.id, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "files": {}}
        for name in FILES:
            p = pov.path(name)
            if p.exists():
                data["files"][name] = p.read_text(encoding="utf-8")
        out = d / f"{pov.id}.zpovbak"
        tmp = out.with_suffix(".tmp")
        tmp.write_bytes(encrypt(data, pw))
        tmp.replace(out)
        pov.cfg.setdefault("backup", {})["at"] = data["at"]
        pov.save()
        return out
    except Exception as e:
        pov.log("backup", f"backup failed: {str(e)[:160]}", "warn")
        if not quiet:
            raise
        return None


def restore(src: str, passphrase: str, overwrite=False):
    """Recreate a POV folder from a backup file. -> the Pov."""
    p = Path(src).expanduser()
    if not p.exists() and folder():
        p = folder() / f"{src}.zpovbak"
    if not p.exists():
        raise KitError(f"No backup at {src}.")
    data = decrypt(p.read_bytes(), passphrase)
    d = povs.POVS / data["pov_id"]
    if (d / "pov.json").exists() and not overwrite:
        raise KitError(f"POV {data['pov_id']} is already on this laptop. Use --overwrite to replace its files.")
    if (d / "ledger.json").exists():   # never trade a newer local ledger for an older backup
        local = {e["id"] for e in json.loads((d / "ledger.json").read_text(encoding="utf-8")).get("entries", [])
                 if e.get("state") in ("owned", "adopted")}
        theirs = {e["id"] for e in json.loads(data["files"].get("ledger.json") or '{"entries": []}').get("entries", [])}
        missing = local - theirs
        if missing:
            raise KitError(f"This laptop's ledger has {len(missing)} POV objects the backup doesn't know about, so "
                           "restoring it would lose track of them. Nothing was changed. Run `pov-kit backup now` "
                           "here instead, or `pov-kit recover` to check the tenant.")
    d.mkdir(parents=True, exist_ok=True)
    for name, text in data["files"].items():
        if name in FILES:
            (d / name).write_text(text, encoding="utf-8")
    pov = povs.Pov(data["pov_id"])
    pov.cfg["clients"] = {k: None for k in (pov.cfg.get("clients") or {})}   # secrets don't travel: connect again
    pov.save()
    povs.use(pov.id)
    pov.log("backup", f"restored from a backup made {data['at']}")
    return pov


def check(pov):
    """A status check: is this POV's ledger safe off the laptop?"""
    from .core.checks import INFO, OK, WARN
    from .core.checks import check as mk
    from .core.ledger import Ledger
    active = Ledger(pov.path("ledger.json"), pov.id, pov.prefix).active()
    at = (pov.cfg.get("backup") or {}).get("at")
    if not folder():
        return mk("backup", "Ledger backed up off this laptop", WARN if active else INFO, "not set up",
                  "`pov-kit backup setup FOLDER` (a folder synced to OneDrive, Google Drive or iCloud). Without it, a "
                  "lost laptop leaves `pov-kit recover` as the only way to find the POV's objects.")
    return mk("backup", "Ledger backed up off this laptop", OK if at else WARN, f"last backup {at or 'never'}",
              "" if at else "Run `pov-kit backup now`.")
