"""The customer's success criteria in, a POV out: read their list (pasted, or a Word, PDF, Excel or CSV file), split it
into criteria, map each to the kit's catalog, and turn the rest into use cases with their own configuration and tests.

  read(name, data)       a file's text, on this laptop (docx, xlsx, csv, txt, md; pdf with pypdf)
  split(text)            one criterion per line, bullet or row, without Claude
  map_all(pov, items)    Claude (through AI Guard, like the use-case assistant) maps each criterion to catalog IDs or
                         writes a use case for it; without Claude, a keyword match to the catalog suggests IDs
  build(pov, snaps, rows, log)
                         the POV's criteria become the mapped catalog IDs; each use-case row is proposed (config and
                         tests) and accepted when it has changes the kit can build, or kept as directions to attest.
                         Everything lands in the change list, which the customer approves as usual.

The rows, with the customer's own wording, are kept in customer_criteria.json, so the report can show each of their
criteria next to the proof.
"""
from __future__ import annotations

import csv
import io
import json
import re
import time
import zipfile
from xml.etree import ElementTree

from . import ai, products
from .core import KitError

FILE = "customer_criteria.json"
MAX_ROWS = 60
STOP = set("the a an and or of to in on for with by is are be can that this from as at it its their our your all any "
           "must should will shall have has into via per each every not no when who which than then".split())


# ---------------------------------------------------------------- reading files (on the laptop; nothing leaves it here)
def _xml_text(xml):
    return ElementTree.fromstring(xml)


def read(name, data: bytes) -> str:
    n = (name or "").lower()
    if n.endswith(".docx"):
        z = zipfile.ZipFile(io.BytesIO(data))
        ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
        root = _xml_text(z.read("word/document.xml"))
        paras = []
        for p in root.iter(f"{{{ns['w']}}}p"):
            t = "".join(x.text or "" for x in p.iter(f"{{{ns['w']}}}t")).strip()
            if t:
                paras.append(t)
        return "\n".join(paras)
    if n.endswith(".xlsx"):
        z = zipfile.ZipFile(io.BytesIO(data))
        S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            for si in _xml_text(z.read("xl/sharedStrings.xml")).iter(f"{S}si"):
                shared.append("".join(t.text or "" for t in si.iter(f"{S}t")))
        rows = []
        for sheet in sorted(x for x in z.namelist() if re.match(r"xl/worksheets/sheet\d+\.xml$", x)):
            for r in _xml_text(z.read(sheet)).iter(f"{S}row"):
                cells = []
                for c in r.iter(f"{S}c"):
                    v = c.find(f"{S}v")
                    if c.get("t") == "s" and v is not None:
                        cells.append(shared[int(v.text)])
                    elif c.get("t") == "inlineStr":
                        cells.append("".join(t.text or "" for t in c.iter(f"{S}t")))
                    elif v is not None:
                        cells.append(v.text or "")
                line = " | ".join(x.strip() for x in cells if x and x.strip())
                if line:
                    rows.append(line)
        return "\n".join(rows)
    if n.endswith(".pdf"):
        try:
            from pypdf import PdfReader
        except ImportError as e:
            raise KitError("Reading PDFs needs the kit's newest libraries: update the kit, or paste the text.") from e
        return "\n".join((pg.extract_text() or "") for pg in PdfReader(io.BytesIO(data)).pages)
    if n.endswith(".csv"):
        text = data.decode("utf-8-sig", errors="replace")
        return "\n".join(" | ".join(c.strip() for c in row if c.strip()) for row in csv.reader(io.StringIO(text)))
    if n.endswith((".txt", ".md", "")) or "." not in n:
        return data.decode("utf-8-sig", errors="replace")
    raise KitError("Use a Word (.docx), PDF, Excel (.xlsx), CSV or text file, or paste the text.")


# ---------------------------------------------------------------- splitting and keyword mapping (no Claude)
BULLET = re.compile(r"^\s*(?:[-*•▪◦·]|\(?\d{1,3}[.)]|\(?[a-zA-Z][.)]|[A-Z]{1,4}-\d{1,3}[:.)]?)\s+")
HEADERISH = re.compile(r"^(success criteria|criteria|requirement|id|#|use case|test case|description)( \|.*)?$", re.I)


def split(text: str) -> list[str]:
    out = []
    for raw in (text or "").replace("\r", "").split("\n"):
        line = BULLET.sub("", raw).strip(" \t|")
        if len(line) < 12 or HEADERISH.match(line) or not re.search(r"[a-zA-Z]{3}", line):
            continue
        out.append(line[:600])
    seen, uniq = set(), []
    for x in out:
        k = x.lower()
        if k not in seen:
            seen.add(k)
            uniq.append(x)
    return uniq[:MAX_ROWS]


def words(s):
    return {w for w in re.findall(r"[a-z0-9]+", s.lower()) if w not in STOP and len(w) > 2}


def catalog(pov=None):
    names = set(pov.products) if pov else None
    return [c for c in products.base.load_catalog() if names is None or c["product"] in names]


def keyword_match(text, cat):
    """The best catalog criterion by shared words, if it shares enough. -> (id or None, score)"""
    w = words(text)
    best, score = None, 0.0
    for c in cat:
        cw = words(c["title"] + " " + c.get("statement", ""))
        if not cw:
            continue
        s = len(w & cw) / max(4, len(w))
        if s > score:
            best, score = c["id"], s
    return (best, round(score, 2)) if score >= 0.25 else (None, round(score, 2))


# ---------------------------------------------------------------- mapping with Claude
SYSTEM = """You map a customer's proof-of-value success criteria for Zscaler to a kit's catalog of provable criteria.
You get the customer's criteria (numbered), the POV's products, and the catalog (id, product, title, statement).
For EACH customer criterion decide:
  - "catalog": the catalog IDs that prove it (one or more), when the catalog covers it as stated or close enough;
  - otherwise "usecase": one or two sentences an engineer could hand to a configuration assistant, describing what
    to set up for the POV's pilot users and how to show it works (e.g. "Block uploads of files to personal Dropbox
    for the pilot group, and show a blocked upload"). Only things the POV's products can do.
  - "out_of_scope": true (with a reason in "note") when no product in the POV can prove it (e.g. a commercial or
    support requirement). Don't invent capabilities.
Keep the customer's meaning; prefer the catalog when it fits. Call the tool with one entry per customer criterion, in
order, with "n" the criterion's number."""

TOOL = {"name": "map_criteria", "description": "Map each customer criterion to catalog IDs or a use case.",
        "input_schema": {"type": "object", "required": ["rows"], "properties": {"rows": {"type": "array", "items": {
            "type": "object", "required": ["n"], "properties": {
                "n": {"type": "integer"}, "catalog": {"type": "array", "items": {"type": "string"}},
                "usecase": {"type": "string"}, "out_of_scope": {"type": "boolean"}, "note": {"type": "string"}}}}}}}


def message(pov, items):
    cat = [{"id": c["id"], "product": c["product"], "title": c["title"], "statement": c.get("statement", "")}
           for c in catalog(pov)]
    lines = "\n".join(f"{i}. {t}" for i, t in enumerate(items, 1))
    return (f"POV products: {', '.join(pov.products)}\n\nCustomer success criteria:\n{lines}\n\n"
            f"Catalog:\n{json.dumps(cat, ensure_ascii=False)}")


def map_all(pov, items, use_ai=True):
    """-> rows: [{n, text, catalog: [ids], usecase, out_of_scope, note, how: 'claude'|'keywords'}]"""
    if not items:
        raise KitError("No criteria found. Paste them one per line, or upload the customer's document.")
    cat = catalog(pov)
    ids = {c["id"] for c in cat}
    rows = [{"n": i, "text": t, "catalog": [], "usecase": "", "out_of_scope": False, "note": "", "include": True}
            for i, t in enumerate(items, 1)]
    got = None
    if use_ai:
        key, _ = ai.proxy_key()
        if key and ai.consent(pov):
            used, text = ai.ask(pov, SYSTEM, message(pov, items), max_tokens=6000, tool=TOOL)
            got = (used or {}).get("rows") if used else None
            if got is None:
                from .usecases import parse
                got = parse(text).get("rows")
    for r in rows:
        if got is not None:
            g = next((x for x in got if isinstance(x, dict) and x.get("n") == r["n"]), {}) or {}
            r["catalog"] = [x for x in (g.get("catalog") or []) if x in ids][:4]
            r["usecase"] = str(g.get("usecase") or "")[:600] if not r["catalog"] else ""
            r["out_of_scope"] = bool(g.get("out_of_scope")) and not r["catalog"] and not r["usecase"]
            r["note"] = str(g.get("note") or "")[:300]
            r["how"] = "claude"
        else:
            best, score = keyword_match(r["text"], cat)
            r["catalog"] = [best] if best else []
            r["usecase"] = "" if best else r["text"]
            r["note"] = f"keyword match ({score})" if best else "no catalog match: becomes a use case"
            r["how"] = "keywords"
        if r["out_of_scope"]:
            r["include"] = False
    return rows


def save(pov, rows, source):
    pov.write_json(FILE, {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "source": source, "rows": rows})
    pov.log("criteria", f"customer criteria imported from {source}: {len(rows)}")


def load(pov):
    return pov.read_json(FILE, {}) or {}


# ---------------------------------------------------------------- build: catalog choice + use cases
def build(pov, snaps, rows, log=lambda *a: None, by="SE"):
    """Set the POV's criteria to the mapped catalog IDs, and propose (then accept) a use case per use-case row.
    -> summary. Use cases need Claude; without it they're listed for the SE to add."""
    from . import settings, usecases
    rows = [r for r in rows if r.get("include", True)]
    chosen = sorted({i for r in rows for i in r.get("catalog") or []})
    settings.set_value(pov, "criteria", chosen)
    log("ok", f"{len(chosen)} catalog criteria chosen for the POV")
    data = load(pov)
    keep = {r["n"]: r for r in data.get("rows") or []}
    made, directions, skipped = [], [], []
    can_ai = bool(ai.proxy_key()[0]) and bool(ai.consent(pov))
    for r in rows:
        if r.get("catalog") or not r.get("usecase"):
            continue
        if not can_ai:
            skipped.append(r["n"])
            continue
        log("info", f"Criterion {r['n']}: writing its configuration and tests…")
        try:
            uc = usecases.propose(pov, snaps, r["usecase"], by=by)
        except KitError as e:
            log("warn", f"Criterion {r['n']}: {e}")
            skipped.append(r["n"])
            continue
        if uc["spec"]["changes"]:
            usecases.set_status(pov, uc["id"], "accepted")
            made.append(uc["id"])
            log("ok", f"Criterion {r['n']} → {uc['id']}: {len(uc['spec']['changes'])} changes, tests: "
                      + (", ".join(k for k in ("probe", "aiguard") if uc["spec"]["test"][k]) or "attestation"))
        else:
            usecases.set_status(pov, uc["id"], "directions")
            directions.append(uc["id"])
            log("info", f"Criterion {r['n']} → {uc['id']}: steps for a person, proved by attestation")
        if r["n"] in keep:
            keep[r["n"]]["usecase_id"] = uc["id"]
    if keep:
        data["rows"] = list(keep.values())
        data["built_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        pov.write_json(FILE, data)
    if skipped:
        log("warn", "Use cases not written (Claude isn't set up for this POV, or it failed): criteria "
                    + ", ".join(map(str, skipped)) + ". Add them in the Use cases tab.")
    return {"catalog": chosen, "usecases": made, "directions": directions, "skipped": skipped}


def customer_view(pov):
    """{criterion or use-case id: [the customer's wording]}, for the report."""
    out = {}
    for r in (load(pov).get("rows") or []):
        if not r.get("include", True):
            continue
        for i in (r.get("catalog") or []) + ([r["usecase_id"]] if r.get("usecase_id") else []):
            out.setdefault(i, []).append(r["text"])
    return out
