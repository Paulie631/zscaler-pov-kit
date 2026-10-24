"""Tenant logs, live: the POV's ZIA web logs streamed to the console as the device tests happen (Cloud NSS).

For when a device can't be linked: the device runs its tests on its own, and the console sees what Zscaler logged for
them, within a minute or two. ZIA's analytics API (Z-Insights) answers only for whole 7- or 14-day windows, so the
only per-transaction route is a Cloud NSS feed: ZIA posts each web log line to an HTTPS address.

  console  the feed posts to this console's device listener, through the Cloudflare quick tunnel (devlink.py). The
           console matches each line to the POV's device tests (the probe tags every test URL with zpov_run=<run>),
           shows a live log view, and can count a run it saw in full as evidence ("tenant logs").
  siem     the feed posts to the customer's own SIEM (a Splunk HTTP Event Collector address and token); the console
           doesn't see these logs.

The feed is one change-list item, filtered to the POV's pilot users (their department for the POV's test users, or
the named pilot users), so no one else's traffic leaves the tenant. Its address and key are filled in at apply, never
written into the change list, so the approval stays valid when the tunnel's address changes; 'Update the feed
address' points the POV's own feed at the new one.
"""
from __future__ import annotations

import json
import re
import secrets
import threading
import time
from collections import deque
from urllib.parse import parse_qs, urlsplit

from .core import KitError, naming, secrets as keychain

KEY = "zia.nss_feed"
SIEM_SECRET = "logfeed-siem-token"
EVENTS: dict[str, deque] = {}       # pov id -> recent events (newest last)
SEEN: dict[str, dict] = {}          # pov id -> {"last": ts, "count": n}
LOCK = threading.Lock()
KEEP = 3000


# ---------------------------------------------------------------- settings
def cfg(pov):
    return pov.cfg.get("logfeed") or {}


def mode(pov):
    return cfg(pov).get("mode") or "off"


def set_mode(pov, mode_, siem_url=None, siem_token=None):
    if mode_ not in ("off", "console", "siem"):
        raise KitError("Log feed: off, console or siem.")
    c = dict(cfg(pov), mode=mode_)
    if mode_ == "siem":
        url = str(siem_url or c.get("siem_url") or "").strip()
        if not re.match(r"^https://", url):
            raise KitError("The SIEM's address is an https:// URL (a Splunk HTTP Event Collector, for example "
                           "https://splunk.acme.com:8088/services/collector).")
        c["siem_url"] = url
        if siem_token:
            keychain.put(pov.id, SIEM_SECRET, str(siem_token).strip())
        if not keychain.get(pov.id, SIEM_SECRET):
            raise KitError("Paste the SIEM's token too (it goes to this computer's keychain).")
    pov.cfg["logfeed"] = c
    pov.save()
    return c


def token(pov):
    from . import devlink
    st = devlink._state(pov)
    if not st.get("nss"):
        st = devlink._save(pov, nss=secrets.token_urlsafe(24))
    return st["nss"]


def connection(pov):
    """-> (url, header) the feed posts to now."""
    if mode(pov) == "siem":
        tok = keychain.get(pov.id, SIEM_SECRET)
        if not tok:
            raise KitError("The SIEM token isn't in this computer's keychain: set the log feed up again.")
        return cfg(pov)["siem_url"], f"Authorization:Splunk {tok}"
    from . import devlink
    if not devlink.LISTEN.get("url"):
        raise KitError("The log feed posts to this console through the Cloudflare tunnel, which isn't running. "
                       "Device tests › Link a device › Turn on: same network + anywhere, then try again.")
    tok = token(pov)
    return f"{devlink.LISTEN['url']}/nss/{tok}/services/collector", f"Authorization:Splunk {tok}"


def resolve(pov, body):
    url, header = connection(pov)
    out = dict(body)
    out["connection_url"] = url
    out["connection_headers"] = [header]
    return out


# ---------------------------------------------------------------- discovery and the change list
def _find_fmt(x):
    if isinstance(x, str) and "%" in x and "{" in x:
        return x
    if isinstance(x, dict):
        for v in x.values():
            f = _find_fmt(v)
            if f:
                return f
    if isinstance(x, (list, tuple)):
        for v in x:
            f = _find_fmt(v)
            if f:
                return f
    return None


def discover(t, pov, snap, checks):
    """Read-only: is Cloud NSS there, its default JSON web-log format, and the pilot users' IDs. -> nss snapshot"""
    from .core.checks import FAIL, OK, WARN, check
    from .tenant import g, items
    out = {"format": None, "users": []}
    try:
        out["format"] = _find_fmt(t.call("cloud_nss", "list_feed_output",
                                         query_params={"type": "WEBLOG", "field_format": "JSON"}))
        checks.append(check("zia-nss", "Cloud NSS available (log feed)", OK if out["format"] else WARN,
                            "web-log JSON format read" if out["format"] else "no web-log JSON format returned",
                            "" if out["format"] else "Check Administration > Nanolog Streaming Service in the ZIA "
                            "console: Cloud NSS needs its subscription."))
    except Exception as e:   # noqa: BLE001
        checks.append(check("zia-nss", "Cloud NSS available (log feed)", FAIL, str(e)[:160],
                            "Cloud NSS needs its subscription (and the API client needs access to NSS). Or turn the "
                            "log feed off: Device tests › Tenant logs."))
    for em in pov.cfg.get("pilot_emails") or []:
        try:
            rows = items(t.call("user_management", "list_users", query_params={"search": em}))
            hit = next((r for r in rows if str(g(r, "email") or "").lower() == em.lower()), None)
            if hit:
                out["users"].append({"id": g(hit, "id"), "name": str(g(hit, "name") or em)})
        except Exception:   # noqa: BLE001
            pass
    return out


def plan_item(pov, snap, prefix, pov_id):
    """-> (item or None, note or None)"""
    from .core.changelist import item
    if mode(pov) == "off":
        return None
    nss = snap.get("nss") or {}
    if not nss.get("format"):
        return None, "Log feed left out: Cloud NSS isn't available in this tenant (see the checks)."
    if snap.get("test_users"):
        filt = {"departments": [{"id": "{ref:zia.department}"}]}
        who = "the POV's test users (their department)"
    elif nss.get("users"):
        filt = {"users": [{"id": u["id"]} for u in nss["users"]]}
        who = "the pilot users named in Pilot users: " + ", ".join(u["name"] for u in nss["users"])
    else:
        return None, ("Log feed left out: the feed must be limited to the pilot users, and none could be named. Add "
                      "the pilot users' emails in Setup › Pilot users (or use the POV's test users).")
    name = naming.safe_name(naming.name(prefix, "web logs"), prefix)
    where = "this console (through the Cloudflare tunnel)" if mode(pov) == "console" else \
        f"the customer's SIEM ({urlsplit(cfg(pov).get('siem_url', '')).hostname})"
    body = dict({"name": name, "feed_status": "ENABLED", "nss_type": "NSS_FOR_WEB", "nss_log_type": "WEBLOG",
                 "nss_feed_type": "JSON", "siem_type": "SPLUNK", "feed_output_format": nss["format"],
                 "user_obfuscation": "DISABLED", "time_zone": "GMT", "json_array_toggle": False,
                 "connection_url": "{filled in at apply}", "connection_headers": ["{filled in at apply}"]}, **filt)
    return item("zia", "nss_feed", KEY, name, affects=f"nobody: it copies the web logs of {who}",
                criteria=[], body=body,
                why=f"Streams those web logs to {where} within a minute or two, so the console can show each device "
                    "test as Zscaler logged it. Removed at teardown."), None


def update_address(pov, tenant_raw, log=lambda *a: None):
    """Points the POV's own feed at the current address (the tunnel's changes when the console restarts)."""
    from . import lifecycle
    from .core.changelist import ChangeList
    from .core.guard import LedgerTenant
    from .products.zia import KINDS, ZIA
    led = lifecycle.ledger(pov)
    e = led.find(KEY)
    if not e:
        raise KitError("The POV has no log feed yet: it's in the change list; approve and apply it first.")
    it = next((i for i in ChangeList(pov.dir).plan().get("items", []) if i["key"] == KEY), None)
    if not it:
        raise KitError("The log feed isn't in the current change list.")
    z = ZIA()
    t = LedgerTenant(tenant_raw, led, [])
    live = z.live_object(t, e)
    if not live:
        raise KitError("The POV's log feed is gone from ZIA. Status › Fix drift recreates it.")
    body = resolve(pov, it["body"])
    k = KINDS["nss_feed"]
    t.update(e, live, k["res"], k["upd"], *z._args(e), **body)
    url = body["connection_url"]
    pov.log("logfeed", f"log feed now posts to {urlsplit(url).hostname}")
    log("ok", "The POV's log feed posts to the new address")
    return url


# ---------------------------------------------------------------- receiving
def parse(raw: bytes):
    """Splunk-style events (one or more JSON objects, or an array) -> [event dicts]."""
    text = raw.decode("utf-8", "replace").strip()
    out, dec, i = [], json.JSONDecoder(), 0
    while i < len(text):
        while i < len(text) and text[i] in " \r\n\t,":
            i += 1
        if i >= len(text):
            break
        try:
            obj, i = dec.raw_decode(text, i)
        except ValueError:
            nxt = text.find("{", i + 1)
            if nxt < 0:
                break
            i = nxt
            continue
        for o in (obj if isinstance(obj, list) else [obj]):
            if isinstance(o, dict):
                ev = o.get("event") if isinstance(o.get("event"), dict) else o
                out.append({str(k).lower(): v for k, v in ev.items()})
    return out


def field(ev, *names):
    for n in names:
        v = ev.get(n)
        if v not in (None, "", "None", "NA"):
            return str(v)
    return ""


def outcome(ev):
    """What the user saw, from the log line: block, caution, isolate or allow."""
    action = field(ev, "action").lower()
    reason = field(ev, "reason").lower()
    if "isolat" in reason or "isolat" in action:
        return "isolate"
    if "caution" in reason or "caution" in action:
        return "caution"
    if action.startswith("block") or "block" in reason or "not allowed" in reason:
        return "block"
    return "allow"


def run_of(ev):
    q = parse_qs(urlsplit(("https://x/" if "://" not in field(ev, "url") else "") + field(ev, "url")).query)
    return (q.get("zpov_run") or [None])[0] or (re.search(r"zpov_run=([0-9a-f]{8})", field(ev, "url")) or [None, None])[1]


def ingest(pov, raw):
    evs = parse(raw)
    now = time.time()
    with LOCK:
        q = EVENTS.setdefault(pov.id, deque(maxlen=KEEP))
        for ev in evs:
            ev["_at"] = now
            ev["_run"] = run_of(ev)
            ev["_outcome"] = outcome(ev)
            q.append(ev)
        s = SEEN.setdefault(pov.id, {"count": 0})
        s.update(last=now, count=s["count"] + len(evs))
    if evs:
        try:
            with open(pov.path("logfeed.jsonl"), "a", encoding="utf-8") as f:
                for ev in evs:
                    f.write(json.dumps(ev, default=str) + "\n")
        except OSError:
            pass
    return len(evs)


def handle(pov, path, raw):
    """POST /nss/<token>/... from ZIA's feed. -> (code, obj)"""
    import hmac
    m = re.match(r"^/nss/([^/]+)/", path + "/")
    if not m or not hmac.compare_digest(m.group(1), token(pov)):
        return 403, {"text": "Invalid token", "code": 4}
    n = ingest(pov, raw)
    return 200, {"text": "Success", "code": 0, "events": n}


# ---------------------------------------------------------------- the console's view
def _host(u):
    u = str(u or "")
    return (urlsplit(u if "://" in u else "https://" + u).hostname or "").removeprefix("www.")


def events(pov, n=200):
    with LOCK:
        return list(EVENTS.get(pov.id, []))[-n:]


def _web_specs(pov):
    from . import devtests
    out = []
    for cid, _, sid, sp in devtests._specs(pov):
        host = _host(sp.get("url")) if sp.get("type") in ("http", "eicar", "dlp_post") else ""
        out.append((cid, sid, sp, host))
    return out


def matches(ev, sp, host):
    if not host:
        return False
    eh = _host(field(ev, "hostname", "host") or field(ev, "url"))
    if not (eh == host or eh.endswith("." + host) or host.endswith("." + eh)):
        return False
    if sp.get("type") == "dlp_post":
        return field(ev, "requestmethod", "reqmethod").upper() in ("POST", "") or bool(field(ev, "dlpengine"))
    return True


def view(pov, n=150):
    """The live log view: recent events, newest first, each with the device test it belongs to."""
    specs = _web_specs(pov)
    rows = []
    for ev in reversed(events(pov, n)):
        hit = next(((cid, sid, sp) for cid, sid, sp, host in specs if matches(ev, sp, host)), None)
        rows.append({"at": time.strftime("%H:%M:%S", time.localtime(ev["_at"])),
                     "time": field(ev, "datetime", "time"), "user": field(ev, "user", "login"),
                     "action": field(ev, "action"), "reason": field(ev, "reason"),
                     "category": field(ev, "urlcategory", "urlcat"), "url": field(ev, "url")[:200],
                     "host": field(ev, "hostname", "host"), "threat": field(ev, "threatname"),
                     "dlp": field(ev, "dlpengine"), "app": field(ev, "appname"), "run": ev.get("_run"),
                     "outcome": ev["_outcome"],
                     "test": {"criterion": hit[0], "id": hit[1], "expect": hit[2].get("expect"),
                              "pass": ev["_outcome"] == hit[2].get("expect")} if hit else None})
    s = SEEN.get(pov.id) or {}
    return {"mode": mode(pov), "events": rows, "count": s.get("count", 0),
            "last": int(time.time() - s["last"]) if s.get("last") else None, "runs": runs(pov),
            "feed": _feed_state(pov)}


def _feed_state(pov):
    from . import devlink, lifecycle
    e = lifecycle.ledger(pov).find(KEY)
    st = {"applied": bool(e), "tunnel": devlink.LISTEN.get("url"), "posts_to": None}
    return st


def runs(pov):
    """Device test runs seen in the logs (by the zpov_run tag), with how many of the POV's web tests each covered."""
    specs = [(cid, sid, sp, host) for cid, sid, sp, host in _web_specs(pov) if host]
    by = {}
    for ev in events(pov, KEEP):
        r = ev.get("_run")
        if not r:
            continue
        d = by.setdefault(r, {"run": r, "user": field(ev, "user", "login"), "first": ev["_at"], "last": ev["_at"],
                              "tests": {}})
        d["last"] = ev["_at"]
        for cid, sid, sp, host in specs:
            if matches(ev, sp, host):
                d["tests"][sid] = {"criterion": cid, "outcome": ev["_outcome"], "expect": sp.get("expect"),
                                   "pass": ev["_outcome"] == sp.get("expect")}
    out = []
    for d in sorted(by.values(), key=lambda x: -x["last"]):
        t = d["tests"]
        out.append({"run": d["run"], "user": d["user"], "at": time.strftime("%H:%M", time.localtime(d["last"])),
                    "seen": len(t), "ok": sum(1 for x in t.values() if x["pass"]), "web_tests": len(specs)})
    return out[:10]


def record(pov, run_id):
    """Counts what the logs show for one device run as evidence: the criteria all of whose tests are web tests the
    logs saw. -> {criteria, skipped}"""
    from . import evidence, probe
    pack = evidence.probe_pack(pov)
    evs = [e for e in events(pov, KEEP) if e.get("_run") == run_id]
    if not evs:
        raise KitError("No log lines for that run (yet). Logs arrive a minute or two after the tests.")
    results, full, skipped = [], [], []
    for c in pack["criteria"]:
        got = []
        for sp in c.get("probe") or []:
            host = _host(sp.get("url")) if sp.get("type") in ("http", "eicar", "dlp_post") else ""
            ev = next((e for e in reversed(evs) if matches(e, sp, host)), None)
            got.append((sp, ev))
        if got and all(ev for _, ev in got):
            full.append(c["id"])
            for sp, ev in got:
                results.append({"spec": sp, "criterion": c["id"], "outcome": ev["_outcome"],
                                "expect": sp.get("expect"), "pass": ev["_outcome"] == sp.get("expect"),
                                "detail": f"tenant log: {field(ev, 'action')} · {field(ev, 'reason')} · "
                                          f"{field(ev, 'urlcategory')} · {field(ev, 'user')}"[:240]})
        elif any(ev for _, ev in got):   # seen in part: not every one of its tests is in this run's logs
            skipped.append(c["id"])
    if pov.cfg.get("switches"):
        raise KitError("The policy is switched for a demo: put it back as planned before counting results.")
    if not results:
        raise KitError("The logs for that run don't cover every test of any criterion (firewall, DNS and "
                       "certificate tests aren't in web logs).")
    user = field(evs[-1], "user", "login")
    rec = {"run_id": f"{run_id}-log", "device": f"tenant logs ({user or 'pilot user'})", "os": "seen in ZIA's web logs",
           "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "pov": pov.id, "pack_id": pack.get("pack_id"),
           "tests": {c["id"]: c.get("hash") for c in pack["criteria"] if c["id"] in full and c.get("hash")},
           "results": results, "source": "tenant logs"}
    path = pov.path(f"logfeed-{run_id}.json")
    probe.save(rec, path)
    try:
        evidence.import_probe(pov, path)
    finally:
        path.unlink(missing_ok=True)
    pov.log("logfeed", f"counted tenant logs of run {run_id}: {', '.join(full)}")
    return {"criteria": full, "skipped": sorted(set(skipped) - set(full))}
