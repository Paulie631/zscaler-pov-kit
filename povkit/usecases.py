"""Use cases from a prompt: an SE or the customer describes what they want to see ("marketing can use ChatGPT but
can't upload files to it"), Claude proposes how, and the kit decides what it can build.

Claude's answer is a proposal, never an action:
  changes      ZIA objects of a few allowed kinds, with fields the kit checks against the tenant's own categories,
               engines and file types. Every one is scoped to the pilot group and named by the kit; Claude can't
               widen scope, rename, or touch the customer's objects. When the SE accepts, the changes join the change
               list as ordinary items, so the plan's hash changes and the customer must approve again before apply.
  directions   console steps for a person, for anything the kit doesn't build (other products, tenant-wide
               settings, the customer's own objects) and for any change that failed validation (with the reason).
  test         a success criterion for the use case, with probe tests of the kinds the probe already runs, or an
               attestation, so the use case is proved in the report like the catalog's.

Use cases live in the POV folder (usecases.json). IDs are UC-01, UC-02...
"""
from __future__ import annotations

import json
import re
import time

from . import ai
from .core import KitError, naming
from .core.changelist import item

STATUSES = ("proposed", "accepted", "directions", "discarded")
ACTIONS = {
    "url_filtering": {"action": {"BLOCK", "CAUTION", "ALLOW", "ISOLATE"}},
    "ssl": {"action": {"DECRYPT", "DO_NOT_DECRYPT"}},
    "cloud_app_control": {},
    "file_type": {"filtering_action": {"BLOCK", "ALLOW", "CAUTION"}, "operation": {"DOWNLOAD", "UPLOAD", "UPLOAD_DOWNLOAD"}},
    "dlp": {"action": {"BLOCK", "ALLOW"}},
    "dns": {"action": {"BLOCK", "ALLOW"}},
}
PROBE = {"http": ({"url", "expect"}, {"block", "caution", "allow", "isolate"}),
         "tcp": ({"host", "port", "expect"}, {"block", "open"}),
         "dns": ({"server", "name", "expect"}, {"block", "resolved"}),
         "tls_issuer": ({"host", "expect"}, {"Zscaler", "not-Zscaler"}),
         "dlp_post": ({"url", "expect"}, {"block", "allow"})}
DOMAIN = re.compile(r"^\.?([a-z0-9-]+\.)+[a-z]{2,}$", re.I)
NAME_MAX = 20   # Claude's short name; with 'ZPOV: UC1 ' it fits ZIA's 31 characters
SNAPSHOT_MAX = 150_000

SYSTEM = """You help a Zscaler sales engineer prove a customer's use case during a proof of value (POV).
You get the use case, the POV's products, and a read-only snapshot of the customer's tenant.
Answer with ONE JSON object and nothing else, in this shape:
{
  "summary": "one sentence: what the POV will show and how",
  "already_covered_by": ["criterion IDs from the POV's catalog that already prove this, if any"],
  "changes": [ ... ZIA objects the kit can create, see below; [] if none ... ],
  "directions": [ {"product": "zia|zcc|zpa|aiguard|zdx|casb", "console_page": "page name", "steps": ["..."]} ],
  "test": {"title": "short", "statement": "what passing shows, one sentence",
           "probe": [ ... probe tests, see below; [] if a person must check it ... ],
           "attest": "what a person checks and where, if the probe can't"}
}
Changes: only these kinds and fields. The kit names each object, scopes it to the pilot group, places it, and
checks every value against the tenant; anything else you put in a change is ignored.
  {"kind": "url_filtering", "name": "<=20 chars", "action": "BLOCK|CAUTION|ALLOW|ISOLATE",
   "url_categories": [category IDs from the snapshot] OR "urls": ["example.com", ".example.org"]}
  {"kind": "ssl", "name": ..., "action": "DECRYPT|DO_NOT_DECRYPT", "url_categories": [...]}
  {"kind": "cloud_app_control", "name": ..., "rule_type": "e.g. AI_ML, FILE_SHARE, WEBMAIL",
   "applications": ["e.g. CHATGPT_AI"], "actions": ["e.g. BLOCK_AI_ML_UPLOAD"]}
  {"kind": "file_type", "name": ..., "filtering_action": "BLOCK|ALLOW|CAUTION",
   "operation": "DOWNLOAD|UPLOAD|UPLOAD_DOWNLOAD", "file_types": [file type names from the snapshot]}
  {"kind": "dlp", "name": ..., "action": "BLOCK|ALLOW", "engines": [DLP engine names from the snapshot]}
  {"kind": "dns", "name": ..., "action": "BLOCK|ALLOW", "res_categories": [category IDs from the snapshot]}
  Every change may have "why": one sentence.
Probe tests (run on a pilot device; only these types):
  {"type": "http", "url": "https://...", "expect": "block|caution|allow|isolate"}
  {"type": "tcp", "host": "...", "port": 1234, "expect": "block|open"}
  {"type": "dns", "server": "8.8.8.8", "name": "...", "expect": "block|resolved"}
  {"type": "tls_issuer", "host": "...", "expect": "Zscaler|not-Zscaler"}
  {"type": "dlp_post", "url": "https://httpbin.org/post", "expect": "block|allow"}
Rules: prefer the smallest change; never change tenant-wide settings or the customer's own objects (write
directions instead); anything outside those kinds (ZPA, AI Guard, Client Connector, ZDX, CASB, admin settings)
is directions. Use public test sites the customer doesn't own. Use only category, engine and file type values
that appear in the snapshot. If the use case is already proved by a catalog criterion, say so and propose no changes."""


def path(pov):
    return pov.path("usecases.json")


def load(pov):
    return pov.read_json("usecases.json", []) or []


def save(pov, ucs):
    pov.write_json("usecases.json", ucs)


def get(pov, uid):
    uc = next((u for u in load(pov) if u["id"] == uid), None)
    if not uc:
        raise KitError(f"No use case {uid}.")
    return uc


def next_id(ucs):
    n = max([int(u["id"].split("-")[1]) for u in ucs] or [0]) + 1
    return f"UC-{n:02d}"


# ---------------------------------------------------------------- the prompt
def build_message(pov, snaps, request):
    from . import evidence
    snap = json.dumps(snaps, default=str)
    if len(snap) > SNAPSHOT_MAX:
        snap = snap[:SNAPSHOT_MAX] + " ...(cut)"
    covered = [{"id": c["id"], "title": c["title"]} for c in evidence.selected_criteria(pov)]
    return (f"Use case: {request.strip()}\n\nPOV products: {', '.join(pov.products)}\n"
            f"Pilot group: {pov.cfg.get('pilot_group')}\n"
            f"Criteria the POV already proves: {json.dumps(covered)}\n\n"
            f"Tenant snapshot (read-only discovery, JSON):\n{snap}")


def parse(text):
    a, b = text.find("{"), text.rfind("}")
    if a < 0 or b <= a:
        raise KitError("Claude's answer wasn't the expected JSON. Try again, or rephrase the use case.")
    try:
        return json.loads(text[a:b + 1])
    except ValueError as e:
        raise KitError(f"Claude's answer wasn't valid JSON ({e}). Try again.") from e


# ---------------------------------------------------------------- validation (the kit decides, not Claude)
def short_name(n):
    n = re.sub(r"[^A-Za-z0-9 _.()-]", "", str(n or "")).strip()
    return (n or "use case")[:NAME_MAX].rstrip()


def validate_change(ch, zia):
    """-> (clean change, None) or (None, why). Only whitelisted fields survive, and every value is checked."""
    kind = ch.get("kind")
    if kind not in ACTIONS:
        return None, f"the kit doesn't build '{kind}' objects"
    out = {"kind": kind, "name": short_name(ch.get("name")), "why": str(ch.get("why") or "")[:200]}
    for field, allowed in ACTIONS[kind].items():
        v = str(ch.get(field) or "").upper()
        if v not in allowed:
            return None, f"{field} '{ch.get(field)}' isn't one of {', '.join(sorted(allowed))}"
        out[field] = v
    cats = set(zia.get("url_categories") or [])
    if kind in ("url_filtering", "ssl", "dns"):
        field = "res_categories" if kind == "dns" else "url_categories"
        vals = [str(x) for x in ch.get(field) or []]
        bad = [x for x in vals if cats and x not in cats]
        if bad:
            return None, f"categories not in this tenant: {', '.join(bad)}"
        if vals:
            out[field] = vals
        if kind == "url_filtering" and ch.get("urls"):
            urls = [str(u).strip().lower() for u in ch["urls"] if str(u).strip()]
            bad = [u for u in urls if not DOMAIN.match(u)]
            if bad:
                return None, f"not domains: {', '.join(bad)}"
            if len(urls) > 25:
                return None, "more than 25 URLs; a person should build a list that long"
            out["urls"] = urls
        if not out.get(field) and not out.get("urls"):
            return None, "no categories or URLs"
        if out.get("action") == "ISOLATE" and not zia.get("cbi"):
            return None, "this tenant has no Cloud Browser Isolation profile"
    if kind == "cloud_app_control":
        rt = str(ch.get("rule_type") or "").upper()
        apps = [str(a).upper() for a in ch.get("applications") or []]
        acts = [str(a).upper() for a in ch.get("actions") or []]
        if not re.fullmatch(r"[A-Z_]{3,40}", rt) or not apps or not acts or \
                not all(re.fullmatch(r"[A-Z0-9_]{2,60}", x) for x in apps + acts):
            return None, "needs a rule type, applications and actions as ZIA names them"
        out.update(rule_type=rt, applications=apps[:20], actions=acts[:6])
    if kind == "file_type":
        types_ = [str(x) for x in ch.get("file_types") or []]
        known = set(zia.get("file_types") or [])
        bad = [x for x in types_ if known and x not in known]
        if bad or not types_:
            return None, f"file types not in this tenant: {', '.join(bad) or 'none given'}"
        out["file_types"] = types_
    if kind == "dlp":
        engines = [str(x) for x in ch.get("engines") or []]
        known = zia.get("dlp_engines") or {}
        bad = [x for x in engines if x not in known]
        if bad or not engines:
            return None, f"DLP engines not in this tenant: {', '.join(bad) or 'none given'}"
        out["engines"] = engines
    return out, None


def validate_probe(sp):
    t = sp.get("type")
    if t not in PROBE:
        return None
    fields, expects = PROBE[t]
    out = {k: sp.get(k) for k in fields}
    if any(v in (None, "") for v in out.values()) or str(out["expect"]) not in expects:
        return None
    if "url" in out and not str(out["url"]).startswith("https://"):
        return None
    if t == "tcp":
        if not str(out["port"]).isdigit() or not 1 <= int(out["port"]) <= 65535:
            return None
        out["port"] = int(out["port"])
    return dict(out, type=t)


def validate(pov, snaps, proposal):
    zia = (snaps or {}).get("zia") or {}
    changes, dropped = [], []
    can_build = "zia" in pov.products
    for ch in (proposal.get("changes") or [])[:8]:
        clean, why = validate_change(ch if isinstance(ch, dict) else {}, zia) if can_build else \
            (None, "ZIA isn't in this POV")
        if clean:
            changes.append(clean)
        else:
            dropped.append({"change": ch, "why": why})
    directions = [{"product": str(d.get("product") or "")[:20], "console_page": str(d.get("console_page") or "")[:80],
                   "steps": [str(s)[:300] for s in (d.get("steps") or [])][:12]}
                  for d in (proposal.get("directions") or []) if isinstance(d, dict)][:8]
    for d in dropped:   # what the kit won't build, a person can: it becomes a direction, with the reason
        kind = str((d["change"] or {}).get("kind") or "") if isinstance(d["change"], dict) else ""
        directions.append({"product": "zia" if kind in ACTIONS else "", "console_page": "", "steps": [
            f"Not built by the kit ({d['why']}). Claude suggested: {json.dumps(d['change'])[:300]}"]})
    test = proposal.get("test") or {}
    probe = [p for p in (validate_probe(x) for x in (test.get("probe") or []) if isinstance(x, dict)) if p][:6]
    return {"summary": str(proposal.get("summary") or "")[:400],
            "already_covered_by": [str(x) for x in proposal.get("already_covered_by") or []][:6],
            "changes": changes, "dropped": dropped, "directions": directions,
            "test": {"title": str(test.get("title") or "Use case")[:80], "statement": str(test.get("statement") or "")[:300],
                     "probe": probe, "attest": str(test.get("attest") or "")[:300]}}


# ---------------------------------------------------------------- lifecycle of a use case
def propose(pov, snaps, request, by="SE"):
    if not (request or "").strip():
        raise KitError("Describe the use case first.")
    raw = ai.ask(pov, SYSTEM, build_message(pov, snaps, request))
    spec = validate(pov, snaps, parse(raw))
    ucs = load(pov)
    uc = {"id": next_id(ucs), "prompt": request.strip()[:2000], "by": by,
          "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "status": "proposed", "spec": spec,
          "raw": raw[:20000]}
    ucs.append(uc)
    save(pov, ucs)
    pov.log("usecase", f"{uc['id']} proposed: {len(spec['changes'])} changes, {len(spec['directions'])} directions")
    return uc


def set_status(pov, uid, status):
    if status not in STATUSES:
        raise KitError(f"Status is one of {', '.join(STATUSES)}.")
    ucs = load(pov)
    uc = next((u for u in ucs if u["id"] == uid), None)
    if not uc:
        raise KitError(f"No use case {uid}.")
    if status == "accepted" and not uc["spec"]["changes"]:
        raise KitError(f"{uid} has no changes the kit can build; keep it as directions instead.")
    uc["status"] = status
    uc[f"{status}_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save(pov, ucs)
    pov.log("usecase", f"{uid} {status}")
    return uc


def accepted(pov):
    return [u for u in load(pov) if u["status"] == "accepted"]


def criteria(pov):
    """Success criteria for accepted use cases and saved directions, so the report proves them too."""
    out = []
    for u in load(pov):
        if u["status"] not in ("accepted", "directions"):
            continue
        t = u["spec"]["test"]
        proofs = (["probe"] if t["probe"] else []) + (["attested"] if t["attest"] or not t["probe"] else [])
        prod = "zia" if u["status"] == "accepted" else next(
            (d["product"] for d in u["spec"]["directions"] if d["product"] in pov.products), pov.products[0])
        out.append({"id": u["id"], "product": prod if prod in pov.products else pov.products[0], "phase": "pov",
                    "title": t["title"], "statement": t["statement"] or u["spec"]["summary"], "proofs": proofs,
                    "probe": t["probe"], "attest": t["attest"] or "Confirm the use case works as described.",
                    "usecase": True})
    return out


# ---------------------------------------------------------------- change-list items (for ZIA's plan)
def zia_items(pov, snap, scope, affects, placement, cac_actions):
    """Items for accepted use cases, as ZIA's plan adds them. -> (items, notes)"""
    P, pid, out, notes = pov.prefix, pov.id, [], []
    for u in accepted(pov):
        n = int(u["id"].split("-")[1])
        for i, ch in enumerate(u["spec"]["changes"], 1):
            key = f"zia.uc{n:02d}.{i}"
            nm = naming.name(P, f"UC{n} {ch['name']}")
            desc = naming.describe(pid, f"{u['id']}: {u['spec']['summary'][:120]}")
            body, rule_type = dict(scope, name=nm, description=desc), None
            if ch["kind"] in ("url_filtering", "ssl"):
                cats = list(ch.get("url_categories") or [])
                if ch.get("urls"):
                    cname = naming.safe_name(naming.name(P, f"UC{n} {ch['name']}"), P)
                    ckey = f"zia.url_category.uc{n:02d}-{i}"
                    out.append(item("zia", "url_category", ckey, cname, criteria=[u["id"]],
                                    affects="nobody until a rule uses it", why=f"Sites for {u['id']}.",
                                    body={"configured_name": cname, "super_category": "USER_DEFINED",
                                          "urls": ch["urls"], "custom_category": True, "description": desc}))
                    cats.append("{ref:" + ckey + "}")
                if ch["kind"] == "ssl":
                    from .products.zia import SSL_ACTIONS
                    body.update(action=SSL_ACTIONS[ch["action"]], url_categories=cats)
                else:
                    iso = ch["action"] == "ISOLATE"
                    body.update(action=ch["action"], url_categories=cats,
                                protocols=["HTTPS_RULE", "HTTP_RULE"] if iso else ["ANY_RULE"],
                                request_methods=["CONNECT", "GET", "HEAD"] if ch["action"] in ("CAUTION", "ISOLATE")
                                else ["CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "OTHER", "POST", "PUT", "TRACE"])
                    if iso:
                        from .products.zia import BROWSERS
                        body.update(user_agent_types=BROWSERS, cbi_profile=snap.get("cbi"))
            elif ch["kind"] == "cloud_app_control":
                got = cac_actions.get(key) or {}
                if not got.get("actions"):
                    notes.append(f"{u['id']} '{ch['name']}' left out: {got.get('why') or 'actions not checked yet'}")
                    continue
                rule_type = ch["rule_type"]
                body.update(applications=got["apps"], actions=got["actions"])
            elif ch["kind"] == "file_type":
                body.update(filtering_action=ch["filtering_action"], operation=ch["operation"], file_types=ch["file_types"],
                            protocols=["FOHTTP_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"])
            elif ch["kind"] == "dlp":
                body.update(action=ch["action"], dlp_engines=[snap["dlp_engines"][e] for e in ch["engines"]],
                            protocols=["FTP_RULE", "HTTPS_RULE", "HTTP_RULE"],
                            severity="RULE_SEVERITY_HIGH" if ch["action"] == "BLOCK" else "RULE_SEVERITY_MEDIUM")
            elif ch["kind"] == "dns":
                body.update(action=ch["action"], res_categories=ch["res_categories"])
            out.append(item("zia", ch["kind"], key, nm, rule_type=rule_type, placement=placement, affects=affects,
                            criteria=[u["id"]], why=f"{u['id']}: {ch['why'] or u['spec']['summary']}"[:300], body=body))
    return out, notes


def cac_wanted(pov):
    """Cloud App Control changes in accepted use cases, for discovery to resolve against the tenant."""
    out = []
    for u in accepted(pov):
        n = int(u["id"].split("-")[1])
        for i, ch in enumerate(u["spec"]["changes"], 1):
            if ch["kind"] == "cloud_app_control":
                out.append((f"zia.uc{n:02d}.{i}", ch))
    return out


def directions_md(uc):
    s = uc["spec"]
    lines = [f"# {uc['id']}: {s['summary'] or uc['prompt']}", "", f"Asked: {uc['prompt']}", ""]
    for d in s["directions"]:
        lines.append(f"## {d['product'].upper() or 'Steps'}" + (f": {d['console_page']}" if d["console_page"] else ""))
        lines += [f"{i}. {st}" for i, st in enumerate(d["steps"], 1)] + [""]
    t = s["test"]
    lines += ["## How to prove it", t["statement"] or ""]
    lines += [f"- probe: {json.dumps(p)}" for p in t["probe"]]
    if t["attest"]:
        lines.append(f"- check: {t['attest']}")
    return "\n".join(lines) + "\n"
