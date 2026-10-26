"""Use cases from a prompt: an SE or the customer describes what they want to see ("marketing can use ChatGPT but
can't upload files to it"), Claude proposes how, and the kit decides what it can build.

Claude's answer is a proposal, never an action:
  changes      new objects of a few allowed kinds in each product of the POV (KINDS below), with fields the kit
               checks against that product's discovery: ZIA rules, a ZPA application with its own access rule, an
               AI Guard app with its own blocking policy, ZDX deep traces, a report-only CASB DLP rule. Every one is
               scoped to the pilot users and named by the kit; Claude can't widen scope, rename, or touch the
               customer's objects. When the SE accepts, the changes join the change list as ordinary items, so the
               plan's hash changes and the customer must approve again before apply.
  directions   console steps for a person, for anything the kit doesn't build (Client Connector profiles,
               tenant-wide settings, the customer's own objects, products outside the POV) and for any change that
               failed validation (with the reason).
  test         a success criterion for the use case: probe tests of the kinds the probe already runs, AI Guard test
               prompts (scanned through the Detection API, like AI-AIG-01), or an attestation, so the use case is
               proved in the report like the catalog's.

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
    "firewall": {"action": {"BLOCK_DROP", "BLOCK_RESET", "ALLOW"}},
}
# kind -> the product that builds it
KINDS = {"url_filtering": "zia", "ssl": "zia", "cloud_app_control": "zia", "file_type": "zia", "dlp": "zia", "dns": "zia",
         "firewall": "zia",
         "zpa_app": "zpa", "aiguard_block": "aiguard", "zdx_deeptrace": "zdx", "casb_dlp": "casb"}
SHORT = {"zia": "ZIA", "zcc": "Client Connector", "zpa": "ZPA", "aiguard": "AI Guard", "zdx": "ZDX", "casb": "CASB", "eai": "Endpoint AI",
         "aispm": "AI-SPM", "dspm": "DSPM", "airt": "AI Red Teaming"}
IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
PORTS = re.compile(r"^(\d{1,5})(-(\d{1,5}))?$")
PROBE = {"http": ({"url", "expect"}, {"block", "caution", "allow", "isolate"}),
         "tcp": ({"host", "port", "expect"}, {"block", "open"}),
         "dns": ({"server", "name", "expect"}, {"block", "resolved"}),
         "tls_issuer": ({"host", "expect"}, {"Zscaler", "not-Zscaler"}),
         "dlp_post": ({"url", "expect"}, {"block", "allow"})}
DOMAIN = re.compile(r"^\.?([a-z0-9-]+\.)+[a-z]{2,}$", re.I)
NAME_MAX = 20   # Claude's short name; with 'ZPOV: UC1 ' it fits ZIA's 31 characters
SNAPSHOT_MAX = 150_000

SYSTEM = """You help a Zscaler sales engineer prove a customer's use case during a proof of value (POV).
You get the use case, the POV's products, and a read-only snapshot of the customer's tenant, one section per product.
Answer with ONE JSON object and nothing else, in this shape:
{
  "summary": "one sentence: what the POV will show and how",
  "already_covered_by": ["criterion IDs from the POV's catalog that already prove this, if any"],
  "changes": [ ... objects the kit can create, see below; [] if none ... ],
  "directions": [ {"product": "zia|zcc|zpa|aiguard|zdx|casb", "console_page": "page name", "steps": ["..."]} ],
  "test": {"title": "short", "statement": "what passing shows, one sentence",
           "probe": [ ... probe tests, see below; [] if none ... ],
           "aiguard": [ ... AI Guard test prompts, see below; [] if none ... ],
           "attest": "what a person checks and where, if the tests can't"}
}
Changes: only these kinds and fields, and only for products in the POV. The kit names each object, scopes it to the
pilot users, places it, and checks every value against the snapshot; anything else you put in a change is ignored.
Every change has "name" (20 characters at most) and may have "why" (one sentence).
ZIA (Internet Access), scoped to the pilot group:
  {"kind": "url_filtering", "action": "BLOCK|CAUTION|ALLOW|ISOLATE",
   "url_categories": [category IDs from the snapshot] OR "urls": ["example.com", ".example.org"]}
  {"kind": "ssl", "action": "DECRYPT|DO_NOT_DECRYPT", "url_categories": [...]}
  {"kind": "cloud_app_control", "rule_type": "e.g. AI_ML, FILE_SHARE, WEBMAIL",
   "applications": ["e.g. CHATGPT_AI"], "actions": ["e.g. BLOCK_AI_ML_UPLOAD"]}
  {"kind": "file_type", "filtering_action": "BLOCK|ALLOW|CAUTION",
   "operation": "DOWNLOAD|UPLOAD|UPLOAD_DOWNLOAD", "file_types": [file type names from the snapshot]}
  {"kind": "dlp", "action": "BLOCK|ALLOW", "engines": [DLP engine names from the snapshot]}
  {"kind": "dns", "action": "BLOCK|ALLOW", "res_categories": [category IDs from the snapshot]}
  {"kind": "firewall", "action": "BLOCK_DROP|BLOCK_RESET|ALLOW", "tcp_ports": ["3389", "6000-6010"],
   "udp_ports": ["..."], "dest_addresses": ["203.0.113.10", "198.51.100.0/24"] (optional; any destination if empty)}
  (Firewall rules see traffic only from devices on Z-Tunnel 2.0.)
ZPA (Private Access): another private app, published through the POV's own App Connectors, with its own access rule
for the pilot users only. Its domains must not belong to a customer segment (zpa.segment_domains in the snapshot).
  {"kind": "zpa_app", "domains": ["app.internal.example", "10.1.2.3"], "tcp_ports": ["443", "8000-8080"],
   "access": "ALLOW|DENY"}
AI Guard: a separate POV app with its own key and its own policy (every detector on, the ones you name set to block),
so the customer's AI Guard apps and policies are untouched. Detector names from aiguard.detectors in the snapshot.
  {"kind": "aiguard_block", "detectors": ["prompt_injection", "pii"], "direction": "prompts|responses|both"}
ZDX: a deep trace on each pilot device, for an app ZDX already monitors (zdx.apps in the snapshot).
  {"kind": "zdx_deeptrace", "app": "app name from the snapshot", "minutes": 5-60}
CASB: a report-only CASB DLP rule over the SaaS tenant the customer connected (it never quarantines or deletes),
for the pilot group's files. Engine names from casb.engines in the snapshot.
  {"kind": "casb_dlp", "engines": ["5 or more Credit Card Numbers"]}
Client Connector (app and forwarding profiles, bypasses, device posture): directions only.
Probe tests (run on a pilot device; only these types):
  {"type": "http", "url": "https://...", "expect": "block|caution|allow|isolate"}
  {"type": "tcp", "host": "...", "port": 1234, "expect": "block|open"}
  {"type": "dns", "server": "8.8.8.8", "name": "...", "expect": "block|resolved"}
  {"type": "tls_issuer", "host": "...", "expect": "Zscaler|not-Zscaler"}
  {"type": "dlp_post", "url": "https://httpbin.org/post", "expect": "block|allow"}
AI Guard test prompts (the kit scans them through the Detection API with the POV's key; use made-up data only):
  {"text": "the test prompt", "expect": "the detector that should trigger", "direction": "IN|OUT"}
Rules: prefer the smallest change; never change tenant-wide settings or the customer's own objects (write
directions instead); a product not in the POV, or not readable in the snapshot, is directions. Use public test
sites the customer doesn't own. Use only values that appear in the snapshot. If the use case is already proved by a
catalog criterion, say so and propose no changes."""


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
    snap = json.dumps(snaps, default=str, ensure_ascii=False)   # as text, so masking sees 'Zürich', not 'Z\u00fcrich'
    if len(snap) > SNAPSHOT_MAX:
        snap = snap[:SNAPSHOT_MAX] + " ...(cut)"
    covered = [{"id": c["id"], "title": c["title"]} for c in evidence.selected_criteria(pov)]
    return (f"Use case: {request.strip()}\n\nPOV products: {', '.join(pov.products)}\n"
            f"Pilot group: {pov.cfg.get('pilot_group')}\n"
            f"Criteria the POV already proves: {json.dumps(covered, ensure_ascii=False)}\n\n"
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


def validate_change(ch, snaps, pov=None):
    """-> (clean change, None) or (None, why). Only whitelisted fields survive, and every value is checked."""
    kind = ch.get("kind")
    product = KINDS.get(kind)
    if not product:
        return None, f"the kit doesn't build '{kind}' objects"
    if pov is not None and product not in pov.products:
        return None, f"{SHORT[product]} isn't in this POV"
    snap = (snaps or {}).get(product) or {}
    if product != "zia" and not snap.get("readable"):
        return None, f"{SHORT[product]} wasn't readable in discovery"
    out = {"kind": kind, "name": short_name(ch.get("name")), "why": str(ch.get("why") or "")[:200]}
    check = {"zia": zia_change, "zpa": zpa_change, "aiguard": aiguard_change, "zdx": zdx_change,
             "casb": casb_change}[product]
    return check(ch, out, snap, snaps or {})


def zia_change(ch, out, zia, snaps):
    kind = out["kind"]
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
    if kind == "firewall":
        tcp = [str(x).strip() for x in ch.get("tcp_ports") or [] if str(x).strip()]
        udp = [str(x).strip() for x in ch.get("udp_ports") or [] if str(x).strip()]
        bad = [x for x in tcp + udp if not PORTS.match(x) or any(int(n) > 65535 or int(n) < 1
                                                                  for n in re.findall(r"\d+", x))]
        if bad or not (tcp or udp):
            return None, f"not ports: {', '.join(bad) or 'none given'}"
        if len(tcp) + len(udp) > 20:
            return None, "more than 20 ports; a person should build a service that large"
        dests = [str(x).strip() for x in ch.get("dest_addresses") or [] if str(x).strip()]
        bad = [x for x in dests if not IPV4.match(x) or x.endswith("/0")]
        if bad:
            return None, f"not IPv4 addresses or ranges: {', '.join(bad)}"
        out.update(tcp_ports=tcp, udp_ports=udp, dest_addresses=dests[:20])
    if kind == "dlp":
        engines = [str(x) for x in ch.get("engines") or []]
        known = zia.get("dlp_engines") or {}
        bad = [x for x in engines if x not in known]
        if bad or not engines:
            return None, f"DLP engines not in this tenant: {', '.join(bad) or 'none given'}"
        out["engines"] = engines
    return out, None


def zpa_change(ch, out, zpa, snaps):
    if not (zpa.get("pilot_group") or zpa.get("pilot_saml")) or not zpa.get("enrollment_cert") or \
            not (zpa.get("app") or {}).get("domains"):
        return None, "the POV's ZPA base isn't ready (pilot users, connector certificate and the POV app come first)"
    doms = [str(d).strip().lower().rstrip(".") for d in ch.get("domains") or [] if str(d).strip()]
    bad = [d for d in doms if not (DOMAIN.match(d) or IPV4.match(d))]
    if bad or not doms:
        return None, f"not domains or IP addresses: {', '.join(bad) or 'none given'}"
    if len(doms) > 10:
        return None, "more than 10 domains; a person should build an app that large"
    if any(d.startswith(".") or "*" in d for d in doms) or any(d.endswith("/0") for d in doms):
        return None, "wildcards and whole networks reach too much for a POV app"
    theirs = set(zpa.get("segment_domains") or [])
    hit = [d for d in doms if d in theirs]
    if hit:
        return None, f"already in a customer segment: {', '.join(hit)} (ZPA would match theirs)"
    mine = set((zpa.get("app") or {}).get("domains") or [])
    if set(doms) & mine:
        return None, "those domains are already the POV app's"
    ports = [str(p).strip() for p in ch.get("tcp_ports") or ["443"] if str(p).strip()]
    for p in ports:
        m = PORTS.match(p)
        lo, hi = (int(m.group(1)), int(m.group(3) or m.group(1))) if m else (0, 0)
        if not m or not 1 <= lo <= hi <= 65535:
            return None, f"not a TCP port or range: {p}"
        if hi - lo > 1000:
            return None, f"port range {p} is wider than a POV app needs"
    access = str(ch.get("access") or "ALLOW").upper()
    if access not in ("ALLOW", "DENY"):
        return None, f"access '{ch.get('access')}' isn't ALLOW or DENY"
    out.update(domains=doms, tcp_ports=ports[:10], access=access)
    return out, None


def aiguard_change(ch, out, ag, snaps):
    det = ag.get("detectors") or {}
    direction = str(ch.get("direction") or "both").lower()
    if direction not in ("prompts", "responses", "both"):
        return None, f"direction '{ch.get('direction')}' isn't prompts, responses or both"
    sides = ["prompts", "responses"] if direction == "both" else [direction]
    names = [str(x).strip() for x in ch.get("detectors") or [] if str(x).strip()]
    known = set().union(*[set(det.get(sd) or []) for sd in sides]) if det else set()
    bad = [x for x in names if x not in known]
    if bad or not names:
        return None, f"detectors that can't block {direction} in AI Guard: {', '.join(bad) or 'none given'}"
    out.update(detectors=names[:10], direction=direction)
    return out, None


def zdx_change(ch, out, zdx, snaps):
    apps = {a["name"]: a["id"] for a in zdx.get("apps") or [] if a.get("name")}
    app = str(ch.get("app") or "")
    if app not in apps:
        return None, f"'{app}' isn't an app ZDX monitors in this tenant"
    if not zdx.get("devices"):
        return None, "no pilot devices report to ZDX yet"
    try:
        minutes = int(ch.get("minutes") or 15)
    except (TypeError, ValueError):
        return None, f"minutes '{ch.get('minutes')}' isn't a number"
    if not 5 <= minutes <= 60:
        return None, "a deep trace runs 5 to 60 minutes"
    out.update(app=app, minutes=minutes)
    return out, None


def casb_change(ch, out, casb, snaps):
    if not casb.get("tenant"):
        return None, "no SaaS tenant is connected for SaaS security"
    if not (snaps.get("zia") or {}).get("pilot_group"):
        return None, "the ZIA pilot group wasn't found, and CASB rules are scoped to it"
    engines = [str(x) for x in ch.get("engines") or []]
    known = casb.get("engines") or {}
    bad = [x for x in engines if x not in known]
    if bad or not engines:
        return None, f"DLP engines not in this tenant: {', '.join(bad) or 'none given'}"
    out["engines"] = engines[:5]
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


def validate_prompt(x, snaps):
    """An AI Guard test prompt. -> clean or None."""
    det = ((snaps or {}).get("aiguard") or {}).get("detectors") or {}
    known = set(det.get("prompts") or []) | set(det.get("responses") or []) | set(det.get("all") or [])
    text, expect = str(x.get("text") or "").strip(), str(x.get("expect") or "").strip()
    direction = str(x.get("direction") or "IN").upper()
    if not text or len(text) > 600 or direction not in ("IN", "OUT") or (known and expect not in known) or not expect:
        return None
    return {"text": text, "expect": expect, "direction": direction}


def validate(pov, snaps, proposal):
    changes, dropped = [], []
    for ch in (proposal.get("changes") or [])[:8]:
        clean, why = validate_change(ch if isinstance(ch, dict) else {}, snaps, pov)
        if clean:
            changes.append(clean)
        else:
            dropped.append({"change": ch, "why": why})
    directions = [{"product": str(d.get("product") or "")[:20], "console_page": str(d.get("console_page") or "")[:80],
                   "steps": [str(s)[:300] for s in (d.get("steps") or [])][:12]}
                  for d in (proposal.get("directions") or []) if isinstance(d, dict)][:8]
    for d in dropped:   # what the kit won't build, a person can: it becomes a direction, with the reason
        kind = str((d["change"] or {}).get("kind") or "") if isinstance(d["change"], dict) else ""
        directions.append({"product": KINDS.get(kind, ""), "console_page": "", "steps": [
            f"Not built by the kit ({d['why']}). Claude suggested: {json.dumps(d['change'])[:300]}"]})
    test = proposal.get("test") or {}
    probe = [p for p in (validate_probe(x) for x in (test.get("probe") or []) if isinstance(x, dict)) if p][:6]
    prompts = [p for p in (validate_prompt(x, snaps) for x in (test.get("aiguard") or []) if isinstance(x, dict)) if p][:6]
    if "aiguard" not in pov.products:
        prompts = []
    return {"summary": str(proposal.get("summary") or "")[:400],
            "already_covered_by": [str(x) for x in proposal.get("already_covered_by") or []][:6],
            "changes": changes, "dropped": dropped, "directions": directions,
            "test": {"title": str(test.get("title") or "Use case")[:80], "statement": str(test.get("statement") or "")[:300],
                     "probe": probe, "aiguard": prompts, "attest": str(test.get("attest") or "")[:300]}}


# ---------------------------------------------------------------- lifecycle of a use case
# the answer's shape, as a tool Claude must call: the API then returns it as structured input, not text to parse
TOOL = {"name": "propose_use_case",
        "description": "Propose how the POV proves the use case: changes the kit builds, directions, and a test.",
        "input_schema": {"type": "object", "required": ["summary", "changes", "directions", "test"], "properties": {
            "summary": {"type": "string"},
            "already_covered_by": {"type": "array", "items": {"type": "string"}},
            "changes": {"type": "array", "items": {"type": "object", "required": ["kind", "name"],
                                                   "properties": {"kind": {"type": "string", "enum": sorted(KINDS)},
                                                                  "name": {"type": "string"}, "why": {"type": "string"}}}},
            "directions": {"type": "array", "items": {"type": "object", "properties": {
                "product": {"type": "string"}, "console_page": {"type": "string"},
                "steps": {"type": "array", "items": {"type": "string"}}}}},
            "test": {"type": "object", "properties": {
                "title": {"type": "string"}, "statement": {"type": "string"},
                "probe": {"type": "array", "items": {"type": "object"}},
                "aiguard": {"type": "array", "items": {"type": "object"}}, "attest": {"type": "string"}}}}}}


def _ask(pov, snaps, message):
    """Mask (names only), ask Claude (ai.route), unmask. -> (proposal dict, raw reply for the record)"""
    from . import pseudo
    m = pseudo.for_pov(pov, snaps, message) if ai.share(pov) == "names_only" else None
    sent = m.mask(message) if m else message
    used, text = ai.ask(pov, SYSTEM + ("\nNames are placeholders (NAME_1, EMAIL_2, DOMAIN_3...): use them as given."
                                       if m else ""), sent, tool=TOOL)
    proposal = used if used is not None else parse(text)
    if m:
        proposal = m.unmask(proposal)
    raw = json.dumps(proposal) if used is not None else (m.unmask(text) if m else text)
    return proposal, raw, (len(m) if m else 0)


def propose(pov, snaps, request, by="SE"):
    if not (request or "").strip():
        raise KitError("Describe the use case first.")
    proposal, raw, masked = _ask(pov, snaps, build_message(pov, snaps, request))
    spec = validate(pov, snaps, proposal)
    ucs = load(pov)
    uc = {"id": next_id(ucs), "prompt": request.strip()[:2000], "by": by,
          "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "status": "proposed", "spec": spec,
          "shared": ai.share(pov), "masked": masked, "raw": raw[:20000], "history": []}
    ucs.append(uc)
    save(pov, ucs)
    pov.log("usecase", f"{uc['id']} proposed: {len(spec['changes'])} changes, {len(spec['directions'])} directions")
    return uc


def refine(pov, snaps, uid, feedback, by="SE"):
    """A follow-up on a proposal ("make it Caution, not Block"): Claude gets the earlier proposal and the feedback,
    and the use case gets the new proposal. An accepted use case goes back to proposed, so it leaves the change
    list until it's accepted again."""
    if not (feedback or "").strip():
        raise KitError("Say what to change.")
    ucs = load(pov)
    uc = next((u for u in ucs if u["id"] == uid), None)
    if not uc:
        raise KitError(f"No use case {uid}.")
    earlier = {k: uc["spec"][k] for k in ("summary", "changes", "directions", "test")}
    msg = (build_message(pov, snaps, uc["prompt"]) + "\n\nYour earlier proposal (as the kit validated it):\n"
           + json.dumps(earlier, ensure_ascii=False) + "\n\nThe SE's feedback on it: " + feedback.strip()
           + "\nPropose again, the whole answer, with the feedback applied.")
    proposal, raw, masked = _ask(pov, snaps, msg)
    uc.setdefault("history", []).append({"at": uc.get("refined_at") or uc["at"], "spec": uc["spec"],
                                         "status": uc["status"], "feedback": feedback.strip()[:1000]})
    uc.update(spec=validate(pov, snaps, proposal), status="proposed", raw=raw[:20000], masked=masked,
              shared=ai.share(pov), refined_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), refined_by=by)
    save(pov, ucs)
    pov.log("usecase", f"{uid} refined: {len(uc['spec']['changes'])} changes")
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


def product_of(pov, uc):
    """The product a use case's criterion belongs to: its first change's, else its tests', else its directions'."""
    s = uc["spec"]
    for ch in s["changes"] if uc["status"] == "accepted" else []:
        return KINDS[ch["kind"]]
    if s["test"].get("aiguard") and "aiguard" in pov.products:
        return "aiguard"
    return next((d["product"] for d in s["directions"] if d["product"] in pov.products), pov.products[0])


def criteria(pov):
    """Success criteria for accepted use cases and saved directions, so the report proves them too."""
    out = []
    for u in load(pov):
        if u["status"] not in ("accepted", "directions"):
            continue
        t = u["spec"]["test"]
        prompts = t.get("aiguard") or []
        proofs = (["probe"] if t["probe"] else []) + (["api"] if prompts else []) + \
            (["attested"] if t["attest"] or not (t["probe"] or prompts) else [])
        out.append({"id": u["id"], "product": product_of(pov, u), "phase": "pov",
                    "title": t["title"], "statement": t["statement"] or u["spec"]["summary"], "proofs": proofs,
                    "probe": t["probe"], "aiguard": prompts, "attest": t["attest"] or "Confirm the use case works as described.",
                    "usecase": True})
    return out


def changes(pov, product):
    """(use case, its number, change number, change) for every accepted change one product builds."""
    for u in accepted(pov):
        n = int(u["id"].split("-")[1])
        for i, ch in enumerate(u["spec"]["changes"], 1):
            if KINDS.get(ch["kind"]) == product:
                yield u, n, i, ch


def uc_name(pov, n, ch, suffix="", limit=None):
    return naming.name(pov.prefix, f"UC{n} {ch['name']}{suffix}", *([limit] if limit else []))


def why(u, ch):
    return f"{u['id']}: {ch['why'] or u['spec']['summary']}"[:300]


def aiguard_secret(key):
    """Keychain name for an AI Guard key's secret: the POV's main key, or one per use case."""
    return "aiguard-detection-key" if key == "aiguard.key" else "aiguard-key-" + key.split(".", 1)[1].replace(".", "-")


def secret_names(pov):
    """Every keychain name use cases may have made, so handover can delete them all."""
    out = []
    for u in load(pov):
        n = int(u["id"].split("-")[1])
        for i, ch in enumerate(u["spec"]["changes"], 1):
            if ch["kind"] == "aiguard_block":
                out.append(aiguard_secret(f"aiguard.uc{n:02d}.{i}.key"))
    return out


# ---------------------------------------------------------------- change-list items (for ZIA's plan)
def zia_items(pov, snap, scope, affects, placement, cac_actions):
    """Items for accepted use cases, as ZIA's plan adds them. -> (items, notes)"""
    P, pid, out, notes = pov.prefix, pov.id, [], []
    for u, n, i, ch in changes(pov, "zia"):
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
        elif ch["kind"] == "firewall":   # its own network service, then the rule that uses it
            sname = naming.safe_name(naming.name(P, f"UC{n} {ch['name']}"), P)
            skey = f"zia.network_service.uc{n:02d}-{i}"
            # the SDK takes (dest, protocol, start[, end]) per port or range
            ports = ([["dest", "tcp", *p.split("-")] for p in ch.get("tcp_ports") or []]
                     + [["dest", "udp", *p.split("-")] for p in ch.get("udp_ports") or []])
            out.append(item("zia", "network_service", skey, sname, criteria=[u["id"]],
                            affects="nobody until a rule uses it", why=f"Ports for {u['id']}.",
                            body={"name": sname, "ports": ports, "description": desc}))
            body.update(action=ch["action"], nw_services=["{ref:" + skey + "}"], enable_full_logging=True)
            if ch.get("dest_addresses"):
                body["dest_addresses"] = ch["dest_addresses"]
        out.append(item("zia", ch["kind"], key, nm, rule_type=rule_type, placement=placement, affects=affects,
                        criteria=[u["id"]], why=f"{u['id']}: {ch['why'] or u['spec']['summary']}"[:300], body=body))
    return out, notes


def cac_wanted(pov):
    """Cloud App Control changes in accepted use cases, for discovery to resolve against the tenant."""
    return [(f"zia.uc{n:02d}.{i}", ch) for u, n, i, ch in changes(pov, "zia") if ch["kind"] == "cloud_app_control"]


def zpa_items(pov, snap, who, affects):
    """A ZPA app per accepted change: its own segment in the POV's segment and server groups, and its own access
    rule for the pilot users, placed first (it names only its own segment, so its place can't affect anyone else)."""
    from .products.zpa import port_pairs
    out = []
    for u, n, i, ch in changes(pov, "zpa"):
        k, nm = f"zpa.uc{n:02d}.{i}", uc_name(pov, n, ch, "", 60)
        desc = naming.describe(pov.id, f"{u['id']}: {u['spec']['summary'][:120]}")
        out.append(item("zpa", "app_segment", f"{k}.segment", nm, affects=affects, criteria=[u["id"]], why=why(u, ch),
                        body={"name": nm, "description": desc, "enabled": True, "domain_names": ch["domains"],
                              "segment_group_id": "{ref:zpa.segment_group}", "server_group_ids": ["{ref:zpa.server_group}"],
                              "tcp_port_ranges": port_pairs(ch["tcp_ports"]), "bypass_type": "NEVER",
                              "health_reporting": "ON_ACCESS", "is_cname_enabled": True}))
        rn = uc_name(pov, n, ch, " access", 60)
        body = {"name": rn, "description": desc, "action": ch["access"].lower(),
                "conditions": [["app", ["{ref:" + k + ".segment}"]], who]}
        if ch["access"] == "ALLOW":
            body["app_connector_group_ids"] = ["{ref:zpa.connector_group}"]
        out.append(item("zpa", "access_rule", f"{k}.rule", rn, affects=affects, placement="top", criteria=[u["id"]],
                        why=f"{'Allows' if ch['access'] == 'ALLOW' else 'Denies'} the pilot users to "
                            f"{', '.join(ch['domains'])} only.", body=body))
    return out


def aiguard_items(pov, snap, order):
    """Per accepted change: a policy (every detector on, the named ones blocking), an app, a key and a rule that
    sends only that app to that policy. -> (items, next rule order)"""
    from .products.aiguard import SIDES, _set_action, apply_profile, template
    out = []
    for u, n, i, ch in changes(pov, "aiguard"):
        k = f"aiguard.uc{n:02d}.{i}"
        pol = apply_profile(template((pov.cfg.get("aiguard") or {}).get("competitor", "Competitor Inc")), "monitor")
        sides = {"prompts": [SIDES[0]], "responses": [SIDES[1]], "both": list(SIDES)}[ch["direction"]]
        for side in sides:
            for d in pol.get(side, []):
                if d.get("enabled") and d.get("detector") in ch["detectors"]:
                    _set_action(d, "BLOCK")
        names = {x: uc_name(pov, n, ch, f" {x}", 60) for x in ("policy", "app", "key", "rule")}
        affects = f"only traffic sent with the {u['id']} app's key"
        pol.update(name=names["policy"], description=naming.describe(pov.id, f"{u['id']}: blocks {', '.join(ch['detectors'])}"))
        out += [
            item("aiguard", "policy", f"{k}.policy", names["policy"], affects=affects, criteria=[u["id"]], why=why(u, ch),
                 body=pol),
            item("aiguard", "app", f"{k}.app", names["app"], affects=affects, criteria=[u["id"]],
                 body={"name": names["app"], "applicationSettings": {"includeEventContents": True,
                                                                    "encryptEventContents": False}}),
            item("aiguard", "key", f"{k}.key", names["key"], affects=affects,
                 why="A Detection API key for this use case's app; its secret goes to the SE's keychain.",
                 body={"name": names["key"], "applicationId": "{ref:" + k + ".app}", "mode": "DETECTIONS"}),
            item("aiguard", "rule", f"{k}.rule", names["rule"], affects=affects, placement="bottom",
                 why=f"Matches the {u['id']} app only.",
                 body={"name": names["rule"], "policyId": "{ref:" + k + ".policy}", "enabled": True, "ruleOrder": order,
                       "matchCriteria": {"type": "DAS_APPLICATION", "llmApplications": [
                           {"applicationId": "{ref:" + k + ".app}", "applicationCredentialsIds": ["{ref:" + k + ".key}"]}]}}),
        ]
        order += 1
    return out, order


def zdx_items(pov, snap):
    apps = {a["name"]: a["id"] for a in snap.get("apps") or []}
    out = []
    for u, n, i, ch in changes(pov, "zdx"):
        if ch["app"] not in apps:
            continue
        for d in snap.get("devices") or []:
            nm = uc_name(pov, n, ch, f" {d['name'] or d['id']}", 60)
            out.append(item("zdx", "deeptrace", f"zdx.uc{n:02d}.{i}.{d['id']}", nm, rule_type=d["id"],
                            affects=f"device {d['name'] or d['id']} only, for {ch['minutes']} minutes",
                            criteria=[u["id"]], why=why(u, ch),
                            body={"session_name": nm, "app_id": apps[ch["app"]], "session_length_minutes": ch["minutes"],
                                  "probe_device": True}))
    return out


def casb_items(pov, snap, grp, order, rule_type, action):
    out = []
    for u, n, i, ch in changes(pov, "casb"):
        ids = [snap["engines"][e] for e in ch["engines"] if e in (snap.get("engines") or {})]
        if not ids:
            continue
        nm = uc_name(pov, n, ch)
        out.append(item("casb", "casb_dlp_rule", f"casb.uc{n:02d}.{i}", nm, rule_type=rule_type,
                        affects=f"files owned by members of '{grp['name']}' in {snap['tenant']['name']}",
                        criteria=[u["id"]], placement="bottom", why=why(u, ch) + " Reports incidents only.",
                        body={"name": nm, "type": rule_type, "enabled": True, "action": action, "rank": 7,
                              "order": order, "severity": "RULE_SEVERITY_MEDIUM",
                              "cloud_app_tenant_ids": [snap["tenant"]["id"]], "dlp_engines": ids,
                              "groups": [grp["id"]], "without_content_inspection": False,
                              "description": naming.describe(pov.id, f"{u['id']}: report-only SaaS DLP")}))
        order += 1
    return out


def planned_names(pov, product):
    """Names the accepted use cases will create in one product, for discovery's name-clash check."""
    out = set()
    for _u, n, _i, ch in changes(pov, product):
        if product == "aiguard":
            out |= {uc_name(pov, n, ch, f" {x}", 60) for x in ("policy", "app", "key", "rule")}
        else:
            out.add(uc_name(pov, n, ch))
    return out


def directions_md(uc):
    s = uc["spec"]
    lines = [f"# {uc['id']}: {s['summary'] or uc['prompt']}", "", f"Asked: {uc['prompt']}", ""]
    for d in s["directions"]:
        lines.append(f"## {SHORT.get(d['product']) or d['product'].upper() or 'Steps'}" + (f": {d['console_page']}" if d["console_page"] else ""))
        lines += [f"{i}. {st}" for i, st in enumerate(d["steps"], 1)] + [""]
    t = s["test"]
    lines += ["## How to prove it", t["statement"] or ""]
    lines += [f"- probe: {json.dumps(p)}" for p in t["probe"]]
    lines += [f"- AI Guard prompt ({p['direction']}), expect {p['expect']}: {p['text']}" for p in t.get("aiguard") or []]
    if t["attest"]:
        lines.append(f"- check: {t['attest']}")
    return "\n".join(lines) + "\n"
