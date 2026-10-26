"""The Device tests tab: the POV's pilot-device tests run from the console, test by test, and guided demos built on them.

This is the AI Guard test runner's counterpart for Internet Access and Client Connector. It runs on THIS computer, so
it is for when the computer running the console is a pilot device, signed in to Client Connector as the pilot user (a
customer's device uses the device command and imports its results). The probe checks the tenant first, as always, and
sends nothing else if the device isn't the POV's.

A criterion's results count as evidence only when every one of its tests ran in that run (a run of two tests out of a
criterion's five proves nothing about the other three). Guided demos are short stories, each a few of the POV's tests
with what to say first, what to point at, and what to say after.
"""
from __future__ import annotations

import json
import time

from . import evidence, probe
from .demo import LOGS, SAMPLE_CARDS, STORIES, open_url, show  # noqa: F401  (shared with the device runner)
from .core import KitError

def _specs(pov):
    """[(criterion, title, spec id, spec)] for every test the pack carries, in pack order."""
    out = []
    for c in evidence.probe_pack(pov)["criteria"]:
        for sp in c["probe"]:
            out.append((c["id"], c["title"], evidence.spec_id(c["id"], sp), sp))
    return out


def open_here(pov, test_id, device=None):
    """Opens a test's page in this computer's default browser (the room sees the user's view). Only the POV's own
    test pages. -> the URL"""
    import webbrowser
    sp = next((sp for _, _, sid, sp in _specs(pov) if sid == test_id), None)
    if not sp:
        raise KitError("That test isn't in this POV.")
    url = open_url(sp)
    if not url:
        raise KitError("That test has no page to open.")
    if device:   # a linked device opens it in its own browser
        from . import devlink
        devlink.open_on(device, url)
        return url
    if not webbrowser.open(url):
        raise KitError("No browser could be opened on this computer.")
    return url


def library(pov):
    rows, by = [], {}
    for cid, title, sid, sp in _specs(pov):
        if cid not in by:
            by[cid] = {"criterion": cid, "title": title, "tests": []}
            rows.append(by[cid])
        by[cid]["tests"].append({"id": sid, "text": evidence.describe_spec(sp), "type": sp.get("type"),
                                 "open": open_url(sp), "show": show(sp)})
    from . import competitive
    diff = competitive.badges(pov)
    for r in rows:
        if r["criterion"] in diff:
            r["differentiator"] = diff[r["criterion"]]
    have = set(by)
    stories = [dict(s, tests=[t["id"] for c in s["criteria"] if c in by for t in by[c]["tests"]])
               for s in STORIES if have & set(s["criteria"])]
    return {"criteria": rows, "stories": stories, "logs": LOGS}


def run(pov, ids=None, log=lambda *a: None, on_result=None, stop=None, on_device=None):
    """Runs the chosen tests (all of them without ids) on this computer, or on a linked device. -> summary"""
    from . import device
    pack = evidence.probe_pack(pov)
    every = _specs(pov)
    want = set(ids) if ids else {sid for _, _, sid, _ in every}
    chosen = [(cid, title, sid, sp) for cid, title, sid, sp in every if sid in want]
    if not chosen:
        raise KitError("Pick some tests first.")
    if not on_device:   # a linked device checks the tenant itself, before any test
        try:
            device.gate(pack["criteria"])
        except device.DeviceError as e:
            raise KitError(str(e)) from e
    crit, sid_of = [], {}
    sw = switched_expect(pov)
    for cid, title, sid, sp in chosen:
        hit = next(((name, exp) for key, (name, exp) in sw.items() if rule_matches(key, sp)), None)
        if hit:   # the policy is switched for the demo: the test expects what the switch does
            sp = dict(sp, expect=hit[1], switched=hit[0])
        if not crit or crit[-1]["id"] != cid:
            h = next((c.get("hash") for c in pack["criteria"] if c["id"] == cid), None)
            crit.append({"id": cid, "title": title, "probe": [], "hash": h})
        crit[-1]["probe"].append(sp)
        sid_of[(cid, json.dumps(sp, sort_keys=True))] = sid

    def landed(r):
        r["id"] = sid_of.get((r["criterion"], json.dumps(r["spec"], sort_keys=True)))
        r["text"] = evidence.describe_spec(r["spec"])
        r["open"] = open_url(r["spec"])
        r["show"] = show(r["spec"])
        if r["spec"].get("switched"):
            r["switched"] = r["spec"]["switched"]
        log("ok" if r["pass"] else "warn", f"{r['criterion']}: {r['text']}: got {r['outcome']}")
        if on_result:
            on_result(r)
    if on_device:
        from . import devlink
        gate_ = [c for c in pack["criteria"] if c["id"] == "IS-TEN-01"]
        res = devlink.run_on(on_device, crit, {"pov": pack.get("pov"), "pack_id": pack.get("pack_id")},
                             on_result=landed, stop=stop, gate=gate_)
        where = f"on {res.get('device') or 'a linked device'}"
    else:
        res = probe.run(crit, pack=pack, on_result=landed, stop=stop)
        where = "on this computer"
    # evidence: only the criteria whose every test ran
    full = {c["id"] for c in pack["criteria"]
            if sum(1 for r in res["results"] if r["criterion"] == c["id"]) == len(c["probe"])}
    rec = dict(res, results=[r for r in res["results"] if r["criterion"] in full],
               tests={k: v for k, v in (res.get("tests") or {}).items() if k in full})
    ev = []
    switched = pov.cfg.get("switches") or {}
    if switched:   # a demo switch changed what the policy does: these results don't prove the planned policy
        rec["results"] = []
    if rec["results"]:
        path = pov.path(f"devtests-{res['run_id']}.json")
        probe.save(rec, path)
        try:
            evidence.import_probe(pov, path)
        finally:
            path.unlink(missing_ok=True)
        ev = sorted(full)
    ok = sum(1 for r in res["results"] if r["pass"])
    pov.log("probe", f"device tests {where}: {ok} of {len(res['results'])} as expected"
            + (" (stopped)" if res.get("stopped") else ""))
    return {"run_id": res["run_id"], "ok": ok, "total": len(res["results"]), "stopped": bool(res.get("stopped")),
            "evidence": ev, "device": res.get("device"),
            "switched": sorted(v.get("name", k) for k, v in switched.items()), "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


# ---------------------------------------------------------------- readiness
def readiness(pov, device=None, zcc=None, facts=None, gate=None):
    """Before Run: can the tests run where they're pointed, and will the results count? Read-only, a few seconds.
    -> {"ready": bool, "checks": [{"id", "label", "state": ok|bad|warn|skip, "detail", "fix"}]}

    A "bad" check stops Run; "warn" lets it run with a caveat. zcc/facts/gate are for tests."""
    checks = []

    def add(cid, label, state, detail="", fix=""):
        checks.append({"id": cid, "label": label, "state": state, "detail": detail, "fix": fix})
    pack = evidence.probe_pack(pov)
    if device:
        from . import devlink
        row = next((d for d in devlink.devices(pov) if d["id"] == device), None)
        if row and row.get("online"):
            add("linked", "Linked device online", "ok", f"{row.get('name') or 'device'}"
                + (f" · {row['user']}" if row.get("user") else "") + f" · asked for work {row['seen']}s ago")
        else:
            add("linked", "Linked device online", "bad", "The device hasn't asked for work in the last minute.",
                "On the device, run the link command again and leave its window open.")
        add("tenant", "In the POV's tenant as the pilot user", "skip",
            "The linked device checks this itself before any test.")
    else:
        running = probe.zcc_running() if zcc is None else zcc
        add("zcc", "Client Connector running", "ok" if running else "bad",
            "" if running else "No Client Connector process on this computer.",
            "" if running else "Open Client Connector and sign in as the pilot user, or pick a linked device.")
        try:
            f = probe.zscaler_facts() if facts is None else facts
            if f.get("through"):
                add("through", "Traffic goes through Zscaler", "ok",
                    " · ".join(x for x in (f.get("datacenter"), f.get("cloud")) if x))
            else:
                add("through", "Traffic goes through Zscaler", "bad", "ip.zscaler.com says this traffic isn't.",
                    "Turn on Internet Security in Client Connector, then Check again.")
        except Exception as e:   # noqa: BLE001
            add("through", "Traffic goes through Zscaler", "warn", f"ip.zscaler.com didn't answer ({type(e).__name__}).")
        if any(c["id"] == "IS-TEN-01" for c in pack["criteria"]):
            from . import device as _device
            try:
                (gate or _device.gate)(pack["criteria"])
                add("tenant", "In the POV's tenant as the pilot user", "ok", "The POV's own check page is blocked here.")
            except _device.DeviceError:
                add("tenant", "In the POV's tenant as the pilot user", "bad",
                    "The POV's own check page isn't blocked, so this isn't the POV's tenant or the pilot user.",
                    "Sign in to Client Connector as the pilot user. A work laptop on its company's Zscaler can't be "
                    "a pilot device.")
            except Exception as e:   # noqa: BLE001
                add("tenant", "In the POV's tenant as the pilot user", "warn", f"Couldn't check ({type(e).__name__}).")
        else:
            add("tenant", "In the POV's tenant as the pilot user", "skip", "This POV has no tenant check (IS-TEN-01).")
    sw = pov.cfg.get("switches") or {}
    if sw:
        add("policy", "Policy as planned", "warn", "Switched for the demo: " + ", ".join(
            v.get("name", k) for k, v in sw.items()) + ". Results won't count as evidence.", "Put back as planned.")
    else:
        add("policy", "Policy as planned", "ok", "Results will count as evidence.")
    return {"ready": not any(c["state"] == "bad" for c in checks), "checks": checks, "device": device or None}


# ---------------------------------------------------------------- demo switches
# which device tests each of the template's rules decides (a switch changes what those tests should see)
RULE_TESTS = {
    "zia.url_filtering.block-gambling": ("http", ["bet365", "pokerstars"]),
    "zia.url_filtering.block-anonymizers": ("http", []),
    "zia.url_filtering.caution-social": ("http", ["facebook"]),
    "zia.url_filtering.isolate-games": ("http", ["steampowered"]),
    "zia.ssl.bypass-finance-and-health": ("tls_issuer", ["chase.com"]),
    "zia.ssl.inspect-pilot-group": ("tls_issuer", ["wikipedia"]),
    "zia.cloud_app_control.block-risky-genai": ("http", ["poe.com"]),
    "zia.cloud_app_control.allow-genai": ("http", ["chatgpt.com"]),
    "zia.cloud_app_control.isolate-genai": ("http", ["perplexity.ai"]),
    "zia.dlp.block-card-numbers": ("dlp_post", [""]),
}
EXPECT_FOR = {"BLOCK": "block", "CAUTION": "caution", "ISOLATE": "isolate", "ALLOW": "allow",
              "DECRYPT": "Zscaler", "DO_NOT_DECRYPT": "not-Zscaler"}


def rule_matches(key, sp):
    kind, needles = RULE_TESTS.get(key, (None, []))
    where = str(sp.get("url") or sp.get("host") or "")
    return sp.get("type") == kind and any(n in where for n in needles)


def switched_expect(pov):
    """{rule key: (label, expected outcome)} for the rules switched away from the plan."""
    from .products.zia import ACTION_LABEL
    out = {}
    for key, v in (pov.cfg.get("switches") or {}).items():
        kind = key.split(".")[1] if key.count(".") >= 2 else ""
        label = ACTION_LABEL.get((kind, v["to"]), v["to"].title())
        out[key] = (f"{v.get('name', key)} switched to {label}", EXPECT_FOR.get(v["to"], v["to"].lower()))
    return out


def policy(pov):
    """The POV rules that can be switched in a demo, each with the device tests it changes."""
    from .products import get
    if "zia" not in pov.products:
        return {"switches": [], "switched": False}
    sw = get("zia").switches(pov)
    tests = {}
    for cid, _, sid, _ in _specs(pov):
        tests.setdefault(cid, []).append(sid)
    specs = _specs(pov)
    for x in sw:
        if x["key"] in RULE_TESTS:
            x["tests"] = [sid for _, _, sid, sp in specs if rule_matches(x["key"], sp)]
        else:   # a use case's rule: the tests of its criteria
            x["tests"] = [t for c in x["criteria"] for t in tests.get(c, [])]
    return {"switches": sw, "switched": any(x["current"] != x["planned"] for x in sw)}


def switch(pov, tenant, key, to, log=lambda *a: None):
    from .core.guard import LedgerTenant
    from .products import get
    from . import lifecycle
    led = lifecycle.ledger(pov)
    t = LedgerTenant(tenant, led, [])
    now = get("zia").switch(t, pov, led, key, to, log)
    pov.log("policy", f"demo switch: {key} -> {now}")
    return now


def put_back(pov, tenant, log=lambda *a: None):
    """Every switched POV rule back to its planned action. -> names put back"""
    done = []
    for key, v in list((pov.cfg.get("switches") or {}).items()):
        switch(pov, tenant, key, "planned", log)
        done.append(v.get("name", key))
    return done


# ---------------------------------------------------------------- a result, opened
def detail(pov, test_id, tenant=None, result=None):
    """Everything about one test for the opened result: the POV rule that decides it (with its switches), Zscaler's
    category for the site, connection facts from this computer, earlier runs, the block page text, where to find it
    in the Zscaler console, and the tenant log line when the log feed is on. Read-only."""
    import re as _re
    from urllib.parse import urlsplit
    sp = next((x for _, _, sid, x in _specs(pov) if sid == test_id), None)
    if not sp:
        raise KitError("That test isn't in this POV.")
    cid = next(c for c, _, sid, _ in _specs(pov) if sid == test_id)
    host = sp.get("host") or (urlsplit(sp.get("url") or "").hostname or "")
    out = {"id": test_id, "criterion": cid, "text": evidence.describe_spec(sp), "host": host, "type": sp.get("type")}
    # the POV rule(s) that decide it
    out["rules"] = [x for x in policy(pov)["switches"] if test_id in x["tests"]]
    # Zscaler's own view of the site (read-only URL lookup)
    if tenant is not None and host and sp.get("type") in ("http", "tls_issuer", "eicar", "dlp_post"):
        try:
            from .core.guard import ReadOnlyTenant
            from .tenant import g, items
            res = ReadOnlyTenant(tenant).call("url_categories", "lookup", urls=[host])
            res = res[0] if isinstance(res, tuple) else res
            rows = res if isinstance(res, list) else items(res)
            cats = sorted({str(c) for r in rows for c in (g(r, "url_classifications") or [])})
            sec = sorted({str(c) for r in rows for c in (g(r, "url_classifications_with_security_alert") or [])})
            out["category"] = {"categories": [c.replace("_", " ").title() for c in cats],
                               "security": [c.replace("_", " ").title() for c in sec]}
        except Exception as e:   # noqa: BLE001
            out["category"] = {"error": str(e)[:160]}
    # connection facts, from this computer
    facts = {}
    try:
        facts.update(probe.zscaler_facts())
    except Exception as e:   # noqa: BLE001
        facts["error"] = f"ip.zscaler.com: {type(e).__name__}"
    if host and sp.get("type") in ("http", "tls_issuer", "dlp_post", "eicar") and (sp.get("url") or "https").startswith("https"):
        try:
            facts["cert"] = probe.cert_facts(host)
        except Exception as e:   # noqa: BLE001
            facts["cert"] = {"error": f"{type(e).__name__}: {str(e)[:80]}"}
    out["connection"] = facts
    # earlier runs of this test
    hist = []
    for run in evidence.probe_runs(pov):
        for r in run.get("results") or []:
            spec = {k: v for k, v in (r.get("spec") or {}).items() if k != "switched"}
            if r.get("criterion") == cid and evidence.spec_id(cid, spec) == test_id:
                hist.append({"at": run.get("at"), "outcome": r.get("outcome"), "pass": r.get("pass"),
                             "device": run.get("device"), "run": run.get("run_id"), "detail": r.get("detail")})
    out["history"] = sorted(hist, key=lambda h: h["at"] or "", reverse=True)[:10]
    # the block page, as the result recorded it
    d = str((result or {}).get("detail") or "")
    m = _re.match(r"HTTP (\d+)(?::\s*(.*))?$", d)
    if m and m.group(2):
        parts = [x.strip() for x in m.group(2).split("·")]
        out["page"] = {"status": m.group(1), "title": parts[0], "text": " · ".join(parts[1:])}
    # where to see it in the Zscaler console
    run_id = (result or {}).get("run_id")
    users = list(pov.cfg.get("pilot_emails") or [])
    if not users:   # the POV's own test users
        try:
            from .core.changelist import ChangeList
            users = [i["body"].get("email") for i in ChangeList(pov.dir).plan().get("items", [])
                     if i["kind"] == "user" and i["body"].get("email")]
        except Exception:   # noqa: BLE001
            pass
    out["console"] = {"where": LOGS, "user": users[0] if users else "the pilot user", "url": host,
                      "tag": f"zpov_run={run_id}" if run_id else None, "at": (result or {}).get("at")}
    # the tenant's log line, when the log feed is on
    try:
        from . import logfeed
        if logfeed.mode(pov) == "console":
            evs = [e for e in logfeed.events(pov, 500) if logfeed.matches(e, sp, logfeed._host(sp.get("url") or host))]
            if run_id:
                evs = [e for e in evs if e.get("_run") in (run_id, None)] or evs
            if evs:
                e = evs[-1]
                out["log"] = {k: logfeed.field(e, *n) for k, n in (("action", ("action",)), ("reason", ("reason",)),
                              ("category", ("urlcategory", "urlcat")), ("user", ("user", "login")),
                              ("rule", ("rulelabel", "rule")), ("threat", ("threatname",)), ("url", ("url",)))}
    except Exception:   # noqa: BLE001
        pass
    return out


# ---------------------------------------------------------------- demo helpers for the products a browser can't show
HELPERS = {
    "workflow": {"title": "DLP incidents (Workflow Automation)", "product": "zia", "criteria": ["IS-DLP-02"],
                 "say": "A DLP block isn't the end: the incident lands in a queue with the user, the data and the "
                        "evidence, ready for the security team.",
                 "steps": ["Run Card numbers leave the company (or the IS-DLP-01 test) from the pilot device.",
                           "Zscaler console: Workflow Automation > Incidents: the new incident for the pilot user, "
                           "with the engine that matched.",
                           "Open it: the evidence, the severity, and assign or close it to show the workflow.",
                           "Success criteria › IS-DLP-02 checks for it through the API."]},
    "zpa": {"title": "Private Access (ZPA)", "criteria": ["PA-APP-01", "PA-APP-02", "PA-CON-01"],
            "say": "The private app is reachable for the pilot group only, and it is never exposed to the internet.",
            "steps": ["On this pilot device, open {app}: it opens, through ZPA.",
                      "Sign in to Client Connector as someone outside the pilot group (or use a second device): the "
                      "same address is refused.",
                      "Zscaler console: Private Access > Diagnostics > Live logs (or Analytics > Private Access), "
                      "filtered to the POV app: the allowed and the denied attempts, by user.",
                      "The POV's App Connectors: healthy, and only outbound connections (nothing listening)."]},
    "zdx": {"title": "Digital Experience (ZDX)", "criteria": ["DX-SCR-01"],
            "say": "When a user says “it’s slow”, ZDX shows where: the device, the Wi-Fi, the ISP, Zscaler or the app.",
            "steps": ["Zscaler console: Digital Experience > Dashboard: the pilot device’s ZDX score.",
                      "Applications > the POV’s app: its score over the last day and what drags it down.",
                      "Troubleshooting > Deep Tracing: start a short trace on the pilot device now, and show it at the "
                      "end of the block."]},
    "casb": {"title": "SaaS security (CASB)", "criteria": ["CS-SAS-01"],
             "say": "Your own SaaS tenant, checked for risky settings and exposed data, with no agent.",
             "steps": ["Zscaler console: SaaS Security > Posture: the findings from the first scan of the connected "
                       "tenant.",
                       "Open one high-risk finding: what it is, who it affects, how to fix it.",
                       "Data at rest: files shared publicly or externally, if the scan found any."]},
}


def helpers(pov):
    """The demo helpers for this POV's products, with each criterion's current state."""
    rows = {r["criterion"]["id"]: r for r in evidence.evaluate(pov)}
    vals = {}
    try:
        v = evidence._values(pov)
        port = v["{zpa.port}"]
        vals["app"] = f"http{'s' if port == '443' else ''}://{v['{zpa.domain}']}" + ("" if port in ("80", "443") else f":{port}")
    except Exception:   # noqa: BLE001
        vals["app"] = "the POV app"
    out = []
    for prod, h in HELPERS.items():
        if h.get("product", prod) not in pov.products:
            continue
        crit = [{"id": c, "title": rows[c]["criterion"]["title"], "status": rows[c]["status"],
                 "detail": "; ".join(str(p.get("detail") or "") for p in rows[c]["proofs"].values() if p.get("detail"))}
                for c in h["criteria"] if c in rows]
        out.append({"product": h.get("product", prod), "title": h["title"], "say": h["say"],
                    "steps": [s.format(**vals) for s in h["steps"]], "criteria": crit})
    traffic = "zia" in pov.products
    return {"helpers": out, "traffic": traffic}


def warm_up(pov, rounds=3, log=lambda *a: None, stop=None):
    """Test traffic from THIS computer (a pilot device), so the dashboards have something to show. -> summary"""
    from . import device, traffic
    pack = evidence.probe_pack(pov)
    try:
        device.gate(pack["criteria"])
    except device.DeviceError as e:
        raise KitError(str(e)) from e
    total = errors = 0
    for i in range(max(1, min(int(rounds or 1), 10))):
        if stop and stop():
            break
        r = traffic.run(count=4, log=log, stop=stop, profile=pack.get("traffic"), quiet=True)
        total += r.get("total", 0)
        errors += r.get("errors", 0)
        log("ok", f"round {i + 1}: {r.get('summary')}")
    pov.log("traffic", f"dashboards warmed up from this computer: {total} requests")
    return {"total": total, "errors": errors}
