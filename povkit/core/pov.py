"""One POV = one folder under ~/.zscaler-pov-kit/povs/<pov-id>/ holding its settings, discovery snapshot,
change list, approval, ledger, probe results, activity log and report. Secrets are in the keychain."""
from __future__ import annotations

import json
import os
import re
import secrets as _rand
import shutil
import time
from pathlib import Path

from . import KitError, naming

BASE = Path(os.getenv("ZPOV_HOME", str(Path.home() / ".zscaler-pov-kit")))
POVS = BASE / "povs"
CURRENT = BASE / "current"


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:24] or "pov"


class Pov:
    def __init__(self, pov_id: str):
        self.id = pov_id
        self.dir = POVS / pov_id
        self.file = self.dir / "pov.json"
        if not self.file.exists():
            raise KitError(f"No POV '{pov_id}'. Start one with `pov-kit new <customer>`.")
        self.cfg = json.loads(self.file.read_text(encoding="utf-8"))

    @property
    def prefix(self):
        return self.cfg.get("prefix", naming.DEFAULT_PREFIX)

    @property
    def products(self):
        return self.cfg.get("products", [])

    def save(self):
        self.file.write_text(json.dumps(self.cfg, indent=2), encoding="utf-8")

    def path(self, name) -> Path:
        return self.dir / name

    def read_json(self, name, default=None):
        p = self.path(name)
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default

    def write_json(self, name, data):
        self.path(name).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def log(self, kind, summary, level="info", **detail):
        """The activity log (Logs tab, diagnostics). Callers pass no secrets; diagnostics redacts again anyway."""
        rec = {"t": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": kind, "level": level,
               "summary": summary, **detail}
        with (self.dir / "activity.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")

    def purge_customer_data(self) -> list[str]:
        """At handover: remove discovery data and the plan bodies; keep the report, approval and ledger."""
        gone = []
        for name in ("discovery.json", "plan.html"):
            p = self.path(name)
            if p.exists():
                p.unlink()
                gone.append(name)
        return gone


def new(customer: str, products: list[str], prefix: str = naming.DEFAULT_PREFIX) -> Pov:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{1,11}", prefix):
        raise KitError("The prefix must be 2 to 12 letters, digits or dashes, starting with a letter.")
    pov_id = f"{slug(customer)}-{_rand.token_hex(2)}"
    d = POVS / pov_id
    d.mkdir(parents=True, exist_ok=False)
    cfg = {"pov_id": pov_id, "customer": customer, "products": products, "prefix": prefix,
           "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "placement": "top",
           "pilot_group": None, "vanity_domain": None, "cloud": None,
           "clients": {"discovery": None, "apply": None}, "state": "new"}
    (d / "pov.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    use(pov_id)
    return Pov(pov_id)


def use(pov_id: str):
    BASE.mkdir(parents=True, exist_ok=True)
    CURRENT.write_text(pov_id, encoding="utf-8")


def current(pov_id: str | None = None) -> Pov:
    pid = pov_id or (CURRENT.read_text(encoding="utf-8").strip() if CURRENT.exists() else "")
    if not pid:
        raise KitError("No POV selected. Start one with `pov-kit new <customer>` or pick one with --pov ID.")
    return Pov(pid)


def all_povs() -> list[str]:
    return sorted(p.name for p in POVS.iterdir() if (p / "pov.json").exists()) if POVS.exists() else []


def remove_folder(pov: Pov, keep=("report.html", "approval.json", "ledger.json", "pov.json")):
    for p in pov.dir.iterdir():
        if p.name not in keep:
            shutil.rmtree(p) if p.is_dir() else p.unlink()
