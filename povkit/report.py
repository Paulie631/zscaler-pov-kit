"""Customer-facing pages: the change list to approve (plan.html) and the evidence report (report.html).
Self-contained HTML, printable to PDF. No secrets; the customer's policy appears only where an item needs it."""
from __future__ import annotations

import html
import json
import time

from . import VERSION
from .console import path_for

CSS = """
:root{--ink:#1d2330;--quiet:#5b6475;--rule:#d9dde5;--bg:#fff;--card:#f6f7f9;--ok:#1f7a4d;--bad:#b3261e;--mid:#946200}
@media (prefers-color-scheme:dark){:root{--ink:#e7e9ee;--quiet:#a3abba;--rule:#353b47;--bg:#14171c;--card:#1d2129}}
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;color:var(--ink);background:var(--bg);margin:0;padding:24px 16px}
main{max-width:920px;margin:0 auto}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px}
.meta{color:var(--quiet);font-size:13px}table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;vertical-align:top;padding:8px 6px;border-bottom:1px solid var(--rule)}th{color:var(--quiet);font-weight:600}
code,pre{font:12.5px ui-monospace,Menlo,Consolas,monospace}pre{background:var(--card);padding:8px;overflow:auto;border-radius:6px}
.pass{color:var(--ok);font-weight:600}.fail{color:var(--bad);font-weight:600}.incomplete{color:var(--mid);font-weight:600}
.id{white-space:nowrap;font:12.5px ui-monospace,Menlo,Consolas,monospace}
.box{background:var(--card);border-radius:8px;padding:12px 16px;margin:12px 0}.sig{margin-top:32px;border-top:1px solid var(--rule);padding-top:12px}
input{font:inherit;color:var(--ink);background:var(--bg);border:1px solid var(--rule);border-radius:6px;padding:7px 9px}
button{font:inherit;font-weight:600;color:#fff;background:#1d63ed;border:0;border-radius:6px;padding:9px 16px;cursor:pointer}
@media print{body{padding:0}details{display:block}details>summary{display:none}#zf{display:none}}
@media (max-width:600px){td,th{display:block;border:0;padding:2px 0}tr{display:block;border-bottom:1px solid var(--rule);padding:8px 0}
tr.head{display:none}}
"""
ACTION = {"create": "Create", "create_or_adopt": "Create (or build by hand and adopt)", "customer_action": "Customer action"}
KIND = {"label": "rule label", "url_category": "custom URL category", "network_service": "network service",
        "url_filtering": "URL filtering rule", "ssl": "SSL inspection rule", "cloud_app_control": "Cloud App Control rule",
        "file_type": "file type control rule", "dlp": "DLP rule", "firewall": "firewall rule", "dns": "DNS control rule",
        "forwarding_profile": "forwarding profile", "app_profile": "app profile",
        "connector_group": "App Connector group", "provisioning_key": "provisioning key", "server_group": "server group",
        "segment_group": "segment group", "app_segment": "application segment", "access_rule": "access policy rule",
        "policy": "detection policy", "app": "AI app", "key": "Detection API key", "rule": "policy rule",
        "deeptrace": "deep trace", "casb_dlp_rule": "CASB DLP rule", "group": "pilot group", "user": "user",
        "members": "group members", "user_group": "user group", "department": "department"}
PRODUCT = {"zid": "ZIdentity", "zia": "Internet Access", "zcc": "Client Connector", "zpa": "Private Access", "aiguard": "AI Guard",
           "zdx": "Digital Experience", "casb": "SaaS security"}
PROOF = {"probe": "Probe", "api": "API", "attested": "Attested"}


def ids(xs):
    return " ".join(f"<span class='id'>{e(x)}</span>" for x in xs)


def e(s):
    return html.escape(str(s if s is not None else ""))


def page(title, body):
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' "
            f"content='width=device-width,initial-scale=1'><title>{e(title)}</title><style>{CSS}</style></head>"
            f"<body><main>{body}</main></body></html>")


def render_plan(pov, items, notes, h):
    creates = [i for i in items if i["action"] != "customer_action"]
    actions = [i for i in items if i["action"] == "customer_action"]
    rows = "".join(
        f"<tr><td>{e(ACTION[i['action']])}</td><td><b>{e(i['name'])}</b><div class='meta'>{e(KIND.get(i['kind'], i['kind']))} · "
        f"{e(PRODUCT.get(i['product'], i['product']))}{' · placed at the ' + e(i['placement']) if i.get('placement') else ''}</div>"
        f"{('<div>' + e(i['why']) + '</div>') if i.get('why') else ''}"
        f"{('<div class=meta>If the API refuses it: ' + e(i['spec']) + '</div>') if i.get('spec') else ''}"
        f"<details><summary class='meta'>Exact settings</summary><pre>{e(json.dumps(i['body'], indent=2))}</pre></details></td>"
        f"<td>{e(i['affects'])}</td><td>{ids(i['criteria'])}</td></tr>" for i in creates)
    acts = "".join(f"<tr><td><b>{e(i['name'])}</b><div>{e(i['why'])}</div><div class='meta'>{e(path_for(i.get('console')))}</div></td>"
                   f"<td>{ids(i['criteria'])}</td></tr>" for i in actions)
    body = (f"<h1>Change list for {e(pov.cfg['customer'])}</h1>"
            f"<p class='meta'>POV {e(pov.id)} · prefix <code>{e(pov.prefix)}</code> · {len(creates)} objects to create, "
            f"{len(actions)} customer actions · change list <code>{e(h[:16])}</code></p>"
            f"<div class='box'>The POV kit will create exactly the objects below, each named with <code>{e(pov.prefix)}</code> "
            f"and marked <code>zpov:{e(pov.id)}</code>, and nothing else. It never edits or deletes your existing objects. "
            f"At the end it deletes everything it created, or hands it to you as Terraform.</div>"
            f"<h2>Objects the kit creates</h2><table><tr class='head'><th>Action</th><th>Object</th><th>Applies to</th>"
            f"<th>Criteria</th></tr>{rows}</table>"
            + (f"<h2>Changes only you make</h2><p class='meta'>The kit checks these, but never makes them.</p>"
               f"<table><tr class='head'><th>Change</th><th>Criteria</th></tr>{acts}</table>" if actions else "")
            + (f"<h2>Notes</h2><ul>{''.join('<li>' + e(n) + '</li>' for n in notes)}</ul>" if notes else "")
            + f"<div class='sig'>Approved by ______________________ &nbsp; Date __________ &nbsp; Change list "
              f"<code>{e(h[:16])}</code></div>"
            + approval_form(pov, h, len(creates)))
    return page(f"Change list · {pov.cfg['customer']}", body)


APPROVE_JS = """
(function(){var f=document.getElementById('zf');if(!f)return;var d=JSON.parse(document.getElementById('zd').textContent);
f.onsubmit=function(ev){ev.preventDefault();var by=f.by.value.trim(),title=f.title.value.trim();
 if(!by||!title||!f.ok.checked){document.getElementById('zm').textContent='Fill in your name and title, and tick the box.';return}
 var rec={format:'zpov-approval-1',pov:d.pov,customer:d.customer,hash:d.hash,objects:d.objects,by:by,title:title,
  email:f.email.value.trim(),note:f.note.value.trim(),at:new Date().toISOString(),agent:navigator.userAgent};
 var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(rec,null,2)],{type:'application/json'}));
 a.download='approval-'+d.pov+'-'+d.hash.slice(0,12)+'.json';document.body.appendChild(a);a.click();a.remove();
 document.getElementById('zm').textContent='Saved '+a.download+'. Send it to your Zscaler SE; nothing changes in '+
  'your tenant until they import it and run Apply.'}})();
"""


def approval_form(pov, h, objects):
    """The customer approves on this page itself: the form saves a small approval file (the change list's full
    hash, their name and title) that they send to the SE, and `pov-kit approve --file` checks the hash before
    recording it. The page works offline; nothing is sent anywhere by the page."""
    data = json.dumps({"pov": pov.id, "customer": pov.cfg["customer"], "hash": h, "objects": objects}).replace("</", "<\\/")
    return (f"<h2>Approve this change list</h2><div class='box'><form id='zf'>"
            f"<p>I've reviewed the {objects} objects above and the changes only we make, and I approve change list "
            f"<code>{e(h[:16])}</code> for {e(pov.cfg['customer'])}.</p>"
            f"<p><label>Name<br><input name='by' required style='width:100%;max-width:360px'></label></p>"
            f"<p><label>Title<br><input name='title' required style='width:100%;max-width:360px'></label></p>"
            f"<p><label>Email (optional)<br><input name='email' type='email' style='width:100%;max-width:360px'></label></p>"
            f"<p><label>Note (optional)<br><input name='note' style='width:100%;max-width:560px'></label></p>"
            f"<p><label><input type='checkbox' name='ok'> I'm authorized to approve changes to this tenant.</label></p>"
            f"<p><button type='submit'>Approve and save the approval file</button></p><p id='zm' class='meta'></p></form></div>"
            f"<script type='application/json' id='zd'>{data}</script><script>{APPROVE_JS}</script>")


def _proof(name, p):
    st = f"<span class='{p['status']}'>{p['status']}</span>"
    if name == "probe" and p.get("results"):
        lines = "".join(f"<li>{e(x['spec'].get('url') or x['spec'].get('host') or x['spec']['type'])}: got "
                        f"<b>{e(x['outcome'])}</b>, expected {e(x['expect'])} <span class='meta'>({e(x['detail'])})</span></li>"
                        for x in p["results"])
        return f"<div><b>Probe</b> {st} <span class='meta'>run {e(p['run'])} on {e(p['device'])}, {e(p['at'])}</span><ul>{lines}</ul></div>"
    a = p.get("attestation")
    extra = (f"{e(a['note'])} <span class='meta'>({e(a['by'])}, {e(a['at'])}{', ' + e(a['file']) if a.get('file') else ''})</span>"
             if a else e(p.get("detail", "")))
    return f"<div><b>{PROOF.get(name, name)}</b> {st} {extra}</div>"


def render_report(pov, rows, approval):
    n = {s: sum(1 for r in rows if r["status"] == s) for s in ("pass", "fail", "incomplete")}
    summary = "".join(f"<tr><td><code>{e(r['criterion']['id'])}</code></td><td>{e(r['criterion']['title'])}</td>"
                      f"<td class='{r['status']}'>{e(r['status'])}</td></tr>" for r in rows)
    detail = "".join(f"<h2>{e(r['criterion']['id'])} · {e(r['criterion']['title'])}</h2>"
                     f"<p>{e(r['criterion'].get('statement', ''))}</p>"
                     + "".join(_proof(k, v) for k, v in r["proofs"].items()) for r in rows)
    appr = (f"approved by {e(approval['by'])} on {e(approval['at'][:10])}, change list <code>{e(approval['hash'][:16])}</code>"
            if approval else "change list not approved")
    tally = f"{n['pass']} of {len(rows)} criteria passed"
    if n["fail"]:
        tally += f", {n['fail']} failed"
    if n["incomplete"]:
        tally += f", {n['incomplete']} still to prove"
    stamp = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    from .summary import current
    summ, stale = current(pov)
    exec_ = ""
    if summ:
        lst = lambda title, xs: (f"<h3>{e(title)}</h3><ul>{''.join('<li>' + e(x) + '</li>' for x in xs)}</ul>"  # noqa: E731
                                 if xs else "")
        exec_ = (f"<h2>Executive summary</h2><p><b>{e(summ['headline'])}</b></p>"
                 + lst("Proved", summ["proved"]) + lst("Not proved yet", summ["open"])
                 + lst("What it means", summ["value"]) + lst("Next steps", summ["next_steps"])
                 + f"<p class='meta'>Drafted by Claude from the results below, {e(summ['at'][:10])}"
                 + (" · results have changed since; ask for it again" if stale else "") + "</p>")
    body = (f"<h1>Proof of value: {e(pov.cfg['customer'])}</h1>"
            f"<p class='meta'>POV {e(pov.id)} · {appr} · report {stamp} · POV kit {VERSION}</p>"
            f"<div class='box'><b>{tally}</b>.</div>{exec_}<h2>Results</h2>"
            f"<table><tr class='head'><th>ID</th><th>Criterion</th><th>Result</th></tr>{summary}</table>{detail}")
    return page(f"POV report · {pov.cfg['customer']}", body)
