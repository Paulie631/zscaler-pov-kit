"""A library of use cases that worked, reusable in the next POV with no AI call and nothing sent anywhere.

`pov-kit usecase save UC-01` (or Save to library in the console) copies a use case's prompt, changes, directions and
test into the library, with the customer's names taken out: the POV's customer names, emails and domains become
placeholders, and changes that only made sense in that tenant (a ZPA app's domains) are dropped. Reusing an entry
validates it against the new tenant like any proposal, so anything that doesn't fit there becomes directions.

The library is a folder of JSON files: ~/.zscaler-pov-kit/library by default, or a shared folder for the team
(`pov-kit usecase library --folder PATH`, e.g. a synced Teams or Google Drive folder).
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from . import VERSION, evidence, pseudo
from .core import KitError
from .core import pov as povs

TENANT_ONLY = {"zpa_app"}   # a private app's domains belong to one customer


def folder() -> Path:
    from .backup import kit_cfg
    d = kit_cfg().get("library_dir")
    return Path(d).expanduser() if d else povs.BASE / "library"


def set_folder(path: str) -> Path:
    from .backup import kit_cfg, save_kit_cfg
    d = Path(path).expanduser()
    d.mkdir(parents=True, exist_ok=True)
    cfg = kit_cfg()
    cfg["library_dir"] = str(d)
    save_kit_cfg(cfg)
    return d


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:48] or "use-case"


def entries():
    d = folder()
    out = []
    for f in sorted(d.glob("*.json")) if d.exists() else []:
        try:
            e = json.loads(f.read_text(encoding="utf-8"))
            e["file"] = f.name
            out.append(e)
        except ValueError:
            continue
    return out


def get(name):
    e = next((x for x in entries() if x["id"] == name or x["file"] == name), None)
    if not e:
        raise KitError(f"No library entry '{name}'. `pov-kit usecase library` lists them.")
    return e


GENERIC = re.compile(r"\b(NAME|EMAIL|DOMAIN|ORG)_\d+\b")


class _Generic:
    """Masks the customer's names as readable, generic words: '[name]', '[email]', '[domain]'."""
    def __init__(self, m):
        self.m = m

    def mask(self, text):
        return GENERIC.sub(lambda x: f"[{x.group(1).lower().replace('org', 'organization')}]", self.m.mask(text))


def save(pov, uc, title=None, by="SE"):
    snaps = (pov.read_json("discovery.json", {}) or {}).get("products") or {}
    vals = pseudo.values(pov, snaps, json.dumps(uc["spec"]) + " " + uc["prompt"] + " " + (title or ""))
    m = _Generic(pseudo.Masker(vals))
    s = uc["spec"]
    rows = {r["criterion"]["id"]: r["status"] for r in evidence.evaluate(pov, [uc["id"]])}
    changes = [c for c in s["changes"] if c["kind"] not in TENANT_ONLY]
    dropped = [c["kind"] for c in s["changes"] if c["kind"] in TENANT_ONLY]
    entry = {"id": slug(title or uc["spec"]["summary"] or uc["prompt"]), "title": m.mask(title or uc["prompt"])[:120],
             "prompt": m.mask(uc["prompt"]), "summary": m.mask(s["summary"]),
             "products": sorted({c["kind"] for c in changes}), "spec": json.loads(m.mask(json.dumps({
                 "summary": s["summary"], "changes": changes, "directions": s["directions"], "test": s["test"]}))),
             "proved": rows.get(uc["id"]) == "pass", "saved": time.strftime("%Y-%m-%d", time.gmtime()), "by": by,
             "left_out": dropped, "kit": VERSION}
    d = folder()
    d.mkdir(parents=True, exist_ok=True)
    f = d / f"{entry['id']}.json"
    n = 2
    while f.exists():
        f = d / f"{entry['id']}-{n}.json"
        n += 1
    entry["id"] = f.stem
    f.write_text(json.dumps(entry, indent=2), encoding="utf-8")
    pov.log("usecase", f"{uc['id']} saved to the library as '{entry['id']}'")
    return entry


def use(pov, snaps, name, by="SE"):
    """A new use case from a library entry, validated against this tenant. No AI call."""
    from . import usecases
    e = get(name)
    spec = usecases.validate(pov, snaps, e["spec"])
    if e.get("left_out"):
        spec["directions"].append({"product": "zpa", "console_page": "", "steps": [
            "The library entry had a ZPA app for another customer's domains; ask Claude for one here, or set it up "
            "with this customer's app."]})
    ucs = usecases.load(pov)
    uc = {"id": usecases.next_id(ucs), "prompt": e["prompt"], "by": by, "from_library": e["id"],
          "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "status": "proposed", "spec": spec,
          "shared": "none", "masked": 0, "raw": "", "history": []}
    ucs.append(uc)
    usecases.save(pov, ucs)
    pov.log("usecase", f"{uc['id']} from the library entry '{e['id']}'")
    return uc
