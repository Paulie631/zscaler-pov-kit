"""Proving success criteria. A criterion passes only when every proof it lists agrees.

  probe     the newest imported probe run that covers it: every probe spec got its expected outcome
  api       the product's automated API proof (`pov-kit test --api`: ZIA rule state, scoping and URL categories,
            connector health, Detection API scans, device scores...). Where a criterion has none, an attestation
            stands in for it, marked so in the report
  attested  a person's note (and optional screenshot) recorded with `pov-kit attest`
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

from . import products
from .core import KitError

PASS, FAIL_, INCOMPLETE = "pass", "fail", "incomplete"


def selected_criteria(pov, ids=None):
    """The criteria of the POV's products: all of them, or the ones agreed with the customer
    (`pov-kit set criteria ...`), or the ids asked for."""
    from . import usecases
    out = [c for p in products.selected(pov.products) for c in p.criteria()] + usecases.criteria(pov)
    if ids:
        return [c for c in out if c["id"] in ids]
    chosen = set(pov.cfg.get("criteria") or [])
    return [c for c in out if not chosen or c["id"] in chosen or c.get("usecase")]


def import_probe(pov, src: Path):
    data = json.loads(Path(src).read_text(encoding="utf-8"))
    if not {"run_id", "results"} <= data.keys():
        raise KitError(f"{src} isn't a POV probe results file.")
    d = pov.path("probe")
    d.mkdir(exist_ok=True)
    dst = d / f"{data['at'][:10]}-{data['run_id']}.json"
    shutil.copyfile(src, dst)
    pov.log("probe", f"imported probe run {data['run_id']} from {data.get('device')}")
    return data


def probe_runs(pov):
    d = pov.path("probe")
    runs = [json.loads(f.read_text(encoding="utf-8")) for f in sorted(d.glob("*.json"))] if d.exists() else []
    return sorted(runs, key=lambda r: r["at"])


def attest(pov, cid, note, by, file=None):
    if not note.strip():
        raise KitError("Say what was seen: `pov-kit attest ID --note \"...\"`.")
    recs = pov.read_json("attestations.json", [])
    rec = {"criterion": cid, "note": note.strip(), "by": by, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if file:
        d = pov.path("attest")
        d.mkdir(exist_ok=True)
        dst = d / f"{cid}-{int(time.time())}{Path(file).suffix}"
        shutil.copyfile(file, dst)
        rec["file"] = dst.name
    recs.append(rec)
    pov.write_json("attestations.json", recs)
    return rec


def evaluate(pov, ids=None):
    runs, atts = probe_runs(pov), pov.read_json("attestations.json", [])
    apis = pov.read_json("api_proofs.json", {}) or {}
    rows = []
    for c in selected_criteria(pov, ids):
        proofs, overall = {}, PASS
        if "probe" in c["proofs"]:
            covering = [r for r in runs if any(x["criterion"] == c["id"] for x in r["results"])]
            if not covering:
                proofs["probe"] = {"status": INCOMPLETE, "detail": "no probe run covers it yet"}
            else:
                run = covering[-1]
                res = [x for x in run["results"] if x["criterion"] == c["id"]]
                ok = all(x["pass"] for x in res)
                proofs["probe"] = {"status": PASS if ok else FAIL_, "run": run["run_id"], "at": run["at"],
                                   "device": run.get("device"), "results": res}
        mine = [a for a in atts if a["criterion"] == c["id"]]
        if "api" in c["proofs"]:
            auto = apis.get(c["id"])
            if auto and auto["status"] in (PASS, FAIL_):
                proofs["api"] = dict(auto, automated=True)
            elif mine:
                proofs["api"] = {"status": PASS, "detail": "attested (no automated API proof for this one)",
                                 "attestation": mine[-1]}
            else:
                proofs["api"] = {"status": INCOMPLETE, "detail": (auto or {}).get("detail")
                                 or "run `pov-kit test --api`, or attest it if there's no automated proof"}
        if "attested" in c["proofs"] or c.get("attest"):
            proofs["attested"] = ({"status": PASS, "attestation": mine[-1]} if mine else
                                  {"status": INCOMPLETE, "detail": c.get("attest") or "needs an attestation"})
        sts = {p["status"] for p in proofs.values()}
        overall = FAIL_ if FAIL_ in sts else INCOMPLETE if INCOMPLETE in sts else PASS
        rows.append({"criterion": c, "status": overall, "proofs": proofs})
    return rows


def probe_pack(pov, ids=None):
    """The probe tests for this POV, with its values filled in ({zpa.domain}...), for `pov-kit probe --pack`."""
    zpa = pov.cfg.get("zpa") or {}
    port = str((zpa.get("tcp_ports") or ["443"])[0]).split("-")[0]
    values = {"{zpa.domain}": (zpa.get("domains") or [""])[0], "{zpa.port}": port}
    crit = []
    for c in selected_criteria(pov, ids):
        if not c.get("probe"):
            continue
        specs = []
        for sp in c["probe"]:
            sp = {k: (values.get(v, v) if isinstance(v, str) else v) for k, v in sp.items()}
            if sp.get("port") is not None and str(sp["port"]).isdigit():
                sp["port"] = int(sp["port"])
            if any(isinstance(v, str) and v.startswith("{") and v.endswith("}") for v in sp.values()) or \
                    any(v == "" for v in sp.values()):
                continue   # a value this POV hasn't set
            specs.append(sp)
        if specs:
            crit.append({"id": c["id"], "title": c["title"], "probe": specs})
    return {"pov": pov.id, "customer": pov.cfg["customer"], "criteria": crit}
