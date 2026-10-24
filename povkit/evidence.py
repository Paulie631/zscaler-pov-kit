"""Proving success criteria. A criterion passes only when every proof it lists agrees.

  probe     the newest imported probe run that covers it: every probe spec got its expected outcome
  api       the product's automated API proof (`pov-kit test --api`: ZIA rule state, scoping and URL categories,
            connector health, Detection API scans, device scores...). Where a criterion has none, an attestation
            stands in for it, marked so in the report
  attested  a person's note (and optional screenshot) recorded with `pov-kit attest`
"""
from __future__ import annotations

import hashlib
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
    if "aiguard" in pov.products:   # the customer's own prompt packs (AI Guard tab)
        from . import aiguard_runner
        out += aiguard_runner.criteria(pov)
    if ids:
        return [c for c in out if c["id"] in ids]
    chosen = set(pov.cfg.get("criteria") or [])
    # optional criteria (industry packs) count only when chosen: `pov-kit set criteria ...,AI-AIG-P2`
    return [c for c in out if c.get("usecase") or c["id"] in chosen or (not chosen and not c.get("optional"))]


def import_probe(pov, src: Path):
    data = json.loads(Path(src).read_text(encoding="utf-8"))
    if not {"run_id", "results"} <= data.keys():
        raise KitError(f"{src} isn't a POV probe results file.")
    if data.get("pov") and data["pov"] != pov.id:
        raise KitError(f"{Path(src).name} has results for POV {data['pov']}, not {pov.id}: switch to that POV first "
                       "(`pov-kit use ID`), or check the device has this POV's probe pack.")
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


def _ag_enabled():
    """Detectors on in the POV's AI Guard policy template (either side)."""
    try:
        from .products import aiguard as ag
        return {d for side in ag.template_detectors().values() for d in side}
    except Exception:   # noqa: BLE001
        return None


def evaluate(pov, ids=None):
    runs, atts = probe_runs(pov), pov.read_json("attestations.json", [])
    apis = pov.read_json("api_proofs.json", {}) or {}
    rows = []
    for c in selected_criteria(pov, ids):
        proofs, overall = {}, PASS
        if "probe" in c["proofs"] or edits(pov)["added"].get(c["id"]):
            covering = [r for r in runs if any(x["criterion"] == c["id"] for x in r["results"])]
            now = test_hash(pov, c)
            current = [r for r in covering if not stale(r, c["id"], now)]
            if not covering:
                proofs["probe"] = {"status": INCOMPLETE, "detail": "no probe run covers it yet"}
            elif not current:
                run = covering[-1]
                proofs["probe"] = {"status": INCOMPLETE, "run": run["run_id"], "at": run["at"], "stale": True,
                                   "device": run.get("device"),
                                   "detail": "its tests changed after the last run (pack "
                                             f"{run.get('pack_id') or '?'}): send the devices the new probe pack and "
                                             "run them again"}
            else:
                run = current[-1]
                res = [x for x in run["results"] if x["criterion"] == c["id"]]
                ok = all(x["pass"] for x in res)
                proofs["probe"] = {"status": PASS if ok else FAIL_, "run": run["run_id"], "at": run["at"],
                                   "device": run.get("device"), "results": res}
                if not ok:
                    from .proof_explain import explain_probe
                    proofs["probe"]["explain"] = explain_probe(res)
        mine = [a for a in atts if a["criterion"] == c["id"]]
        if "api" in c["proofs"]:
            auto = apis.get(c["id"])
            from .lifecycle import tests_hash
            if auto and c.get("probe") and auto.get("tests") != tests_hash(c) and not c.get("aiguard"):
                proofs["api"] = {"status": INCOMPLETE, "stale": True, "at": auto.get("at"),
                                 "detail": "its tests changed after this was last checked: Test with the API again "
                                           "(it runs by itself when Success criteria opens)"}
            elif auto and auto["status"] in (PASS, FAIL_):
                proofs["api"] = dict(auto, automated=True)
                if auto["status"] == FAIL_:
                    from .proof_explain import explain, explain_ai_guard
                    ag_rows = auto.get("results") if (c["product"] == "aiguard" or c.get("aiguard")) else None
                    proofs["api"]["explain"] = (explain_ai_guard(ag_rows, _ag_enabled()) if ag_rows and any(
                        isinstance(x, dict) and x.get("pass") is False for x in ag_rows) else []) or \
                        explain(auto.get("detail"), auto["status"])
            elif mine:
                proofs["api"] = {"status": PASS, "detail": "demonstrated live (no automated API proof for this one)",
                                 "attestation": mine[-1]}
            else:
                proofs["api"] = {"status": INCOMPLETE, "detail": (auto or {}).get("detail")
                                 or "not checked yet (the kit checks after Apply and with Status; or Check again)"}
                if auto and auto.get("detail"):
                    from .proof_explain import explain
                    proofs["api"]["explain"] = explain(auto["detail"], "incomplete")
        if "attested" in c["proofs"] or c.get("attest"):
            proofs["attested"] = ({"status": PASS, "attestation": mine[-1]} if mine else
                                  {"status": INCOMPLETE, "detail": c.get("attest") or "show it live, then mark it Demonstrated"})
        sts = {p["status"] for p in proofs.values()}
        overall = FAIL_ if FAIL_ in sts else INCOMPLETE if INCOMPLETE in sts else PASS
        rows.append({"criterion": c, "status": overall, "proofs": proofs})
    return rows


def _h(x):
    return hashlib.sha256(json.dumps(x, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:10]


# ---------------------------------------------------------------- the SE's review of the pack: tests added or left out
EDITS = "probe_edits.json"   # {"added": {criterion: [spec + id, by, at]}, "skipped": [test ids]}
EXTRA = {"id": "SE-EXTRA", "title": "Extra checks the SE added", "product": "zia"}
EXPECTS = {"http": ("block", "allow", "caution", "isolate"), "tls_issuer": ("Zscaler", "not-Zscaler"),
           "tcp": ("block", "open"), "dns": ("block", "resolved")}


def edits(pov):
    e = pov.read_json(EDITS, {}) or {}
    return {"added": e.get("added") or {}, "skipped": list(e.get("skipped") or [])}


def spec_id(cid, sp):
    return _h([cid, {k: v for k, v in sp.items() if k not in ("id", "by", "at")}])


from .demo import describe_spec  # noqa: E402,F401  (shared with the device runner)


def add_test(pov, cid, kind, by="SE", **v):
    """A test the SE adds to a criterion (or to the extra checks). -> the spec"""
    import re as _re
    if kind not in EXPECTS:
        raise KitError("Test types: web page (http), HTTPS inspection (tls_issuer), port (tcp), DNS name (dns).")
    exp = str(v.get("expect") or "")
    if exp not in EXPECTS[kind]:
        raise KitError(f"Expect one of: {', '.join(EXPECTS[kind])}.")
    host_re = r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    if kind == "http":
        url = str(v.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        if not _re.fullmatch(r"https?://" + host_re + r"(:\d+)?(/\S*)?", url):
            raise KitError("Give a web address, like https://www.example.com/.")
        sp = {"type": "http", "url": url, "expect": exp}
    elif kind in ("tls_issuer", "tcp"):
        host = str(v.get("host") or "").strip()
        if not _re.fullmatch(host_re, host):
            raise KitError("Give a host name, like www.example.com.")
        sp = {"type": kind, "host": host, "expect": exp}
        if kind == "tcp":
            port = int(v.get("port") or 0)
            if not 0 < port < 65536:
                raise KitError("Give a port from 1 to 65535.")
            sp["port"] = port
    else:
        name = str(v.get("name") or "").strip()
        if not _re.fullmatch(host_re, name):
            raise KitError("Give a name to look up, like www.example.com.")
        sp = {"type": "dns", "server": "8.8.8.8", "name": name, "expect": exp}
    ids = {c["id"] for c in selected_criteria(pov)}
    if cid != EXTRA["id"] and cid not in ids:
        raise KitError(f"{cid} isn't one of this POV's criteria.")
    e = edits(pov)
    rec = dict(sp, id=spec_id(cid, sp), by=str(by)[:80], at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    if any(x["id"] == rec["id"] for x in e["added"].get(cid, [])):
        raise KitError("That test is already in the pack.")
    e["added"].setdefault(cid, []).append(rec)
    pov.write_json(EDITS, e)
    pov.log("probe", f"test added to {cid}: {describe_spec(sp)}")
    return rec


def remove_test(pov, cid, sid):
    """An added test is deleted; a catalog (or use case) test is left out of the pack, and can come back."""
    e = edits(pov)
    added = e["added"].get(cid, [])
    if any(x["id"] == sid for x in added):
        e["added"][cid] = [x for x in added if x["id"] != sid]
    elif sid not in e["skipped"]:
        e["skipped"].append(sid)
    pov.write_json(EDITS, e)
    pov.log("probe", f"test {sid} taken out of {cid}'s pack")


def restore_test(pov, sid):
    e = edits(pov)
    e["skipped"] = [x for x in e["skipped"] if x != sid]
    pov.write_json(EDITS, e)


def _pack_specs(pov, c, values, with_skipped=False):
    e = edits(pov)
    specs = []
    for sp in list(c.get("probe") or []) + [{k: v for k, v in x.items() if k not in ("id", "by", "at")}
                                             for x in e["added"].get(c["id"], [])]:
        sp = {k: (values.get(v, v) if isinstance(v, str) else v) for k, v in sp.items()}
        if sp.get("port") is not None and str(sp["port"]).isdigit():
            sp["port"] = int(sp["port"])
        if any(isinstance(v, str) and v.startswith("{") and v.endswith("}") for v in sp.values()) or \
                any(v == "" for v in sp.values()):
            continue   # a value this POV hasn't set
        if not with_skipped and spec_id(c["id"], sp) in e["skipped"]:
            continue
        specs.append(sp)
    return specs


def _values(pov):
    from .products.zpa import app_of
    app = app_of(pov.cfg)
    return {"{zpa.domain}": app["domains"][0], "{zpa.port}": str(app["tcp_ports"][0]).split("-")[0]}


def test_hash(pov, c):
    """The version of a criterion's probe tests as the pack gives them (its specs with this POV's values)."""
    return _h(_pack_specs(pov, c, _values(pov)))


def stale(run, cid, now):
    """A run is stale for a criterion when it recorded that criterion's test version and the tests changed since.
    Runs from packs made before 0.9.25 recorded none, and count as current."""
    was = (run.get("tests") or {}).get(cid)
    return bool(was) and was != now


# what the traffic generator sends for each criterion (ZIA): the pack's traffic profile
TRAFFIC = {"IS-URL-01": ["web"], "IS-URL-02": ["web"], "IS-TEN-01": ["web"], "IS-SSL-01": ["web"], "IS-SSL-02": ["web"],
           "IS-CBI-01": ["web"], "IS-THR-01": ["threats"], "IS-THR-02": ["threats"], "IS-CAC-01": ["saas", "files"],
           "IS-DLP-01": ["dlp"], "AI-GEN-01": ["genai"], "AI-GEN-02": ["genai", "dlp"], "IS-FTC-01": ["files"],
           "IS-FW-01": ["ports"], "IS-DNS-01": ["dns"]}
TRAFFIC_ORDER = ("web", "saas", "genai", "threats", "dlp", "files", "dns", "ports")
UC_EXPECT = {"BLOCK": "block", "CAUTION": "caution", "ISOLATE": "isolate", "ALLOW": "allow"}


def traffic_profile(pov, crit):
    """Which traffic types the POV's criteria call for, plus its use cases' own sites and blocked ports."""
    if "zia" not in pov.products:
        return {"types": [], "web": [], "block_ports": []}
    from . import usecases
    ids = {c["id"] for c in crit}
    types = {t for cid in ids for t in TRAFFIC.get(cid, [])} | {"web"}   # web: the tenant check, always
    web, ports = [], []
    for u, _n, _i, ch in usecases.changes(pov, "zia"):
        if u["id"] not in ids:
            continue
        if ch["kind"] == "url_filtering" and ch.get("urls"):
            for d in ch["urls"][:5]:
                web.append({"url": f"https://{d.lstrip('.')}/", "category": f"{u['id']} {ch['name']}",
                            "expect": UC_EXPECT.get(ch["action"], "allow")})
            types.add("web")
        elif ch["kind"] == "firewall" and ch["action"] != "ALLOW" and not ch.get("dest_addresses"):
            ports += [int(p.split("-")[0]) for p in ch.get("tcp_ports") or []][:5]
            types.add("ports")
        elif ch["kind"] in ("dlp", "file_type", "cloud_app_control", "dns"):
            types.add({"dlp": "dlp", "file_type": "files", "cloud_app_control": "saas", "dns": "dns"}[ch["kind"]])
    return {"types": [t for t in TRAFFIC_ORDER if t in types], "web": web, "block_ports": sorted(set(ports))}


def probe_pack(pov, ids=None):
    """The probe tests for this POV, with its values filled in ({zpa.domain}...), for pilot devices
    (`pov-probe pack install`, then `pov-probe test`). It carries a pack ID and each criterion's test version, so
    results show which tests they ran, and the traffic generator's profile for the POV's criteria."""
    from . import VERSION
    values = _values(pov)
    chosen = selected_criteria(pov, ids)
    crit = []
    for c in chosen:
        specs = _pack_specs(pov, c, values)
        if specs:
            crit.append({"id": c["id"], "title": c["title"], "probe": specs, "hash": _h(specs)})
    extra = _pack_specs(pov, dict(EXTRA, probe=[]), values)
    if extra:
        crit.append({"id": EXTRA["id"], "title": EXTRA["title"], "probe": extra, "hash": _h(extra)})
    prof = traffic_profile(pov, chosen)
    return {"pov": pov.id, "customer": pov.cfg["customer"], "pack_id": _h([crit, prof]),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kit_version": VERSION,
            "criteria": crit, "traffic": prof}


def pack_review(pov):
    """Every test the pack would carry, criterion by criterion, in plain words, with where it came from and whether
    the SE left it out."""
    values, e = _values(pov), edits(pov)
    rows = []
    for c in selected_criteria(pov) + [dict(EXTRA, probe=[])]:
        added = {x["id"]: x for x in e["added"].get(c["id"], [])}
        tests = []
        for sp in _pack_specs(pov, c, values, with_skipped=True):
            sid = spec_id(c["id"], sp)
            tests.append({"id": sid, "text": describe_spec(sp), "type": sp.get("type"),
                          "source": "added by " + added[sid]["by"] if sid in added else
                          ("use case" if c.get("usecase") else "catalog"),
                          "skipped": sid in e["skipped"]})
        if tests or "probe" in (c.get("proofs") or []) or c["id"] == EXTRA["id"]:
            rows.append({"criterion": c["id"], "title": c["title"], "tests": tests,
                         "probe_proof": "probe" in (c.get("proofs") or []) or bool(added)})
    p = probe_pack(pov)
    return {"rows": rows, "pack_id": p["pack_id"], "tests": sum(len(c["probe"]) for c in p["criteria"]),
            "traffic": p["traffic"]["types"], "expects": EXPECTS}


def pack_status(pov):
    """-> {pack_id, criteria with tests, need: [criteria no current run covers], stale: [...], runs}"""
    pack = probe_pack(pov)
    runs = probe_runs(pov)
    need, old = [], []
    for c in pack["criteria"]:
        covering = [r for r in runs if any(x["criterion"] == c["id"] for x in r["results"])]
        if not covering:
            need.append(c["id"])
        elif all(stale(r, c["id"], c["hash"]) for r in covering):
            old.append(c["id"])
    last = runs[-1] if runs else None
    return {"pack_id": pack["pack_id"], "criteria": len(pack["criteria"]), "need": need, "stale": old,
            "runs": len(runs), "devices": sorted({r.get("device") or "?" for r in runs}),
            "last_run": {k: last.get(k) for k in ("run_id", "at", "device", "pack_id")} if last else None,
            "traffic": pack["traffic"]}
