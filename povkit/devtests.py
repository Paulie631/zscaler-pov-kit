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
from .core import KitError

# where to see a test's events (the console's own menus; no deep links, which change by tenant and release)
LOGS = "Zscaler console: Analytics > Web Insights > Logs, filtered to the pilot user and the last 15 minutes"

STORIES = [
    {"id": "follows-user", "title": "Policy follows the user", "criteria": ["IS-TEN-01", "IS-ZCC-01"],
     "for": "Everyone",
     "say": "This laptop is a pilot user’s. Only the pilot group gets the POV’s rules; nobody else in the company sees a "
            "change.",
     "point": "The POV’s block page on www.example.com, and Client Connector running with Zscaler confirmed.",
     "after": "Same policy on any network: office, home, hotel."},
    {"id": "gambling", "title": "A user tries a gambling site", "criteria": ["IS-URL-01"], "for": "Security",
     "say": "Watch what happens when someone opens a site in a category the company doesn’t allow.",
     "point": "The block page: the category, the policy and the user are named.",
     "after": "Find the same event in Web Insights: who, what, when, which rule."},
    {"id": "coach", "title": "Coaching instead of blocking", "criteria": ["IS-URL-02"], "for": "Security, CISO",
     "say": "Not everything should be blocked. Some categories get a reminder and a choice.",
     "point": "The caution page, then Continue.",
     "after": "Users learn the policy; you keep the record of who went ahead."},
    {"id": "inspect", "title": "Malware hidden in HTTPS", "criteria": ["IS-SSL-01", "IS-SSL-02", "IS-THR-01"],
     "for": "Security engineers",
     "say": "Most attacks arrive encrypted. Here is a malware test file over HTTPS.",
     "point": "The certificate issuer on wikipedia.org (Zscaler: inspected) and chase.com (not: banking is bypassed), "
              "then the EICAR download blocked.",
     "after": "Inspection where it protects, bypass where privacy matters."},
    {"id": "phish", "title": "A phishing link", "criteria": ["IS-THR-02"], "for": "Security",
     "say": "A user clicks a phishing link from an email.",
     "point": "The known phishing and malware pages never load.",
     "after": "Threat intelligence updated continuously, applied inline."},
    {"id": "dlp", "title": "Card numbers leave the company", "criteria": ["IS-DLP-01"], "for": "Security, CISO",
     "say": "Someone uploads a list of card numbers to a website.",
     "point": "The DLP block, even though the upload is over HTTPS.",
     "after": "The DLP event names the rule, the user and the data type."},
    {"id": "genai", "title": "Safe use of GenAI", "criteria": ["AI-GEN-01", "AI-GEN-02"], "for": "CISO",
     "say": "Your people use AI. Approved apps stay open; risky ones and leaking data don’t.",
     "point": "ChatGPT opens; poe.com is blocked; card numbers sent to an AI app are blocked.",
     "after": "Pair this with AI Guard for the company’s own AI apps."},
    {"id": "files", "title": "Risky downloads and file sharing", "criteria": ["IS-FTC-01", "IS-CAC-01"],
     "for": "Security",
     "say": "An executable from the web, and an unsanctioned file-sharing app.",
     "point": "The .exe download stopped; the file-sharing app handled by Cloud App Control.",
     "after": "Control by file type and by app, not just by site."},
    {"id": "isolate", "title": "A risky site, opened safely", "criteria": ["IS-CBI-01"], "for": "Security",
     "say": "Some sites are useful but risky. They can run in the cloud instead of on the laptop.",
     "point": "The site opening in browser isolation (in a browser on this computer).",
     "after": "Nothing from the site reaches the device."},
    {"id": "network", "title": "Not just the web", "criteria": ["IS-FW-01", "IS-DNS-01"], "for": "IT, networking",
     "say": "Every port and every DNS lookup goes through the same policy, not only web traffic.",
     "point": "TCP 2222 blocked by the cloud firewall; a DNS lookup for a blocked category refused.",
     "after": "One policy for all traffic, with Z-Tunnel 2.0."},
]


def _specs(pov):
    """[(criterion, title, spec id, spec)] for every test the pack carries, in pack order."""
    out = []
    for c in evidence.probe_pack(pov)["criteria"]:
        for sp in c["probe"]:
            out.append((c["id"], c["title"], evidence.spec_id(c["id"], sp), sp))
    return out


def open_url(sp):
    """A page to open in a browser for the same test, where there is one."""
    if sp.get("type") == "http":
        return sp.get("url")
    if sp.get("type") == "tls_issuer":
        return f"https://{sp.get('host')}/"
    if sp.get("type") == "dlp_post":
        return "https://dlptest.com/http-post/"
    if sp.get("type") == "eicar":
        return "https://www.eicar.org/download-anti-malware-testfile/"
    return None


def library(pov):
    rows, by = [], {}
    for cid, title, sid, sp in _specs(pov):
        if cid not in by:
            by[cid] = {"criterion": cid, "title": title, "tests": []}
            rows.append(by[cid])
        by[cid]["tests"].append({"id": sid, "text": evidence.describe_spec(sp), "type": sp.get("type"),
                                 "open": open_url(sp)})
    have = set(by)
    stories = [dict(s, tests=[t["id"] for c in s["criteria"] if c in by for t in by[c]["tests"]])
               for s in STORIES if have & set(s["criteria"])]
    return {"criteria": rows, "stories": stories, "logs": LOGS}


def run(pov, ids=None, log=lambda *a: None, on_result=None, stop=None):
    """Runs the chosen tests (all of them without ids) on this computer. -> summary"""
    from . import device
    pack = evidence.probe_pack(pov)
    every = _specs(pov)
    want = set(ids) if ids else {sid for _, _, sid, _ in every}
    chosen = [(cid, title, sid, sp) for cid, title, sid, sp in every if sid in want]
    if not chosen:
        raise KitError("Pick some tests first.")
    try:
        device.gate(pack["criteria"])
    except device.DeviceError as e:
        raise KitError(str(e)) from e
    crit, sid_of = [], {}
    for cid, title, sid, sp in chosen:
        if not crit or crit[-1]["id"] != cid:
            h = next((c.get("hash") for c in pack["criteria"] if c["id"] == cid), None)
            crit.append({"id": cid, "title": title, "probe": [], "hash": h})
        crit[-1]["probe"].append(sp)
        sid_of[(cid, json.dumps(sp, sort_keys=True))] = sid

    def landed(r):
        r["id"] = sid_of.get((r["criterion"], json.dumps(r["spec"], sort_keys=True)))
        r["text"] = evidence.describe_spec(r["spec"])
        r["open"] = open_url(r["spec"])
        log("ok" if r["pass"] else "warn", f"{r['criterion']}: {r['text']}: got {r['outcome']}")
        if on_result:
            on_result(r)
    res = probe.run(crit, pack=pack, on_result=landed, stop=stop)
    # evidence: only the criteria whose every test ran
    full = {c["id"] for c in pack["criteria"]
            if sum(1 for r in res["results"] if r["criterion"] == c["id"]) == len(c["probe"])}
    rec = dict(res, results=[r for r in res["results"] if r["criterion"] in full],
               tests={k: v for k, v in (res.get("tests") or {}).items() if k in full})
    ev = []
    if rec["results"]:
        path = pov.path(f"devtests-{res['run_id']}.json")
        probe.save(rec, path)
        try:
            evidence.import_probe(pov, path)
        finally:
            path.unlink(missing_ok=True)
        ev = sorted(full)
    ok = sum(1 for r in res["results"] if r["pass"])
    pov.log("probe", f"device tests on this computer: {ok} of {len(res['results'])} as expected"
            + (" (stopped)" if res.get("stopped") else ""))
    return {"run_id": res["run_id"], "ok": ok, "total": len(res["results"]), "stopped": bool(res.get("stopped")),
            "evidence": ev, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


# ---------------------------------------------------------------- demo helpers for the products a browser can't show
HELPERS = {
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
        if prod not in pov.products:
            continue
        crit = [{"id": c, "title": rows[c]["criterion"]["title"], "status": rows[c]["status"],
                 "detail": "; ".join(str(p.get("detail") or "") for p in rows[c]["proofs"].values() if p.get("detail"))}
                for c in h["criteria"] if c in rows]
        out.append({"product": prod, "title": h["title"], "say": h["say"],
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
