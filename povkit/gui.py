"""The POV console: a local web page with the setup wizard and tabs for status, criteria, handover and logs.

Built on the demo kit's console pattern: the server listens on 127.0.0.1 only, refuses any other Host header (so a
web page can't reach it through DNS rebinding), and every /api call must carry a token minted for this run and
written into the page. Long operations (apply, status, proofs, handover) run as jobs the page polls. Secrets go
straight to the keychain and never come back to the page, except a test user's password or the ZPA provisioning key
when the SE asks for it by name.
"""
from __future__ import annotations

import json
import secrets as _rand
import threading
import time
import uuid
from pathlib import Path

from . import VERSION, evidence, handover, lifecycle, mcp, products, remind, rolespec, settings
from .core import KitError, pov as povs, secrets
from .core.changelist import ChangeList
from .core.checks import exit_code

HERE = Path(__file__).resolve().parent
JOBS: dict[str, dict] = {}


def real_tenant_for(pov, which):
    from .tenant import Tenant
    return Tenant(pov, which)


TENANT_FOR = real_tenant_for   # tests swap in a fake


def tf(pov, which):
    return TENANT_FOR(pov, which)


# ---------------------------------------------------------------- state for the page
def pov_state(p):
    led = lifecycle.ledger(p)
    cl = ChangeList(p.dir)
    plan = cl.plan() if cl.plan_file.exists() else None
    appr = cl.approval()
    slots = ["main"] if p.cfg.get("client_mode", "single") == "single" else ["discovery", "apply"]
    states = {}
    for e in led.entries:
        states[e["state"]] = states.get(e["state"], 0) + 1
    return {"id": p.id, "customer": p.cfg["customer"], "prefix": p.prefix, "products": p.products,
            "state": p.cfg.get("state"), "settings": settings.snapshot(p),
            "clients": {s: {"client_id": ((p.cfg.get("clients") or {}).get(s) or {}).get("client_id"),
                            "saved": bool(secrets.get(p.id, f"{s}-client-secret"))} for s in slots},
            "plan": {"hash": plan["hash"], "items": len(plan["items"]),
                     "creates": sum(1 for i in plan["items"] if i["action"] != "customer_action")} if plan else None,
            "approval": appr, "ledger": states,
            "test_users": sum(1 for e in led.active("zia") if e["kind"] == "user"),
            "zpa_key": bool(secrets.get(p.id, "zpa-provisioning-key")),
            "end": remind.end_check(p), "backup_at": (p.cfg.get("backup") or {}).get("at"),
            "record": bool(p.cfg.get("record")), "selftest": p.read_json("selftest.json"),
            "mcp": {"consent": mcp.consent(p), "installed": (p.cfg.get("mcp") or {}).get("installed"),
                    "uses": mcp.slot(p)[1], "entry": mcp.entry_name(p)}}


def state():
    cur = povs.CURRENT.read_text().strip() if povs.CURRENT.exists() else ""
    from . import backup
    out = {"version": VERSION, "povs": [], "current": None, "backup_folder": str(backup.folder() or "") or None,
           "products": [{"name": n, "title": products.get(n).title, "phase": products.get(n).phase}
                        for n in products.ORDER]}
    for pid in povs.all_povs():
        p = povs.Pov(pid)
        out["povs"].append({"id": pid, "customer": p.cfg["customer"], "state": p.cfg.get("state")})
        if pid == cur:
            out["current"] = pov_state(p)
    return out


def current():
    return povs.current()


# one cheap read per product, to prove the client signs in and can see that product
PING = {"zia": ("activate", "status"), "zcc": ("zcc.forwarding_profile", "list_by_company"),
        "zpa": ("zpa.idp", "list_idps"), "aiguard": ("aiguard.policies", "list_policies"),
        "zdx": ("zdx.apps", "list_apps"), "casb": ("saas_security_api", "list_casb_tenant_lite")}


def sign_in_check(p, which):
    from .core.guard import ReadOnlyTenant
    t = ReadOnlyTenant(tf(p, which))
    first = next(n for n in products.ORDER if n in p.products)
    t.call(*PING[first])


def diagnostics_zip(q, token):
    if q.get("t") != token:
        return None
    from . import diagnostics
    return diagnostics.build(current())


# ---------------------------------------------------------------- jobs
def start_job(kind, work):
    jid = uuid.uuid4().hex[:8]
    job = JOBS[jid] = {"kind": kind, "done": False, "lines": [], "result": None, "error": None}

    def log(level, msg):
        job["lines"].append({"level": level, "msg": str(msg), "t": time.strftime("%H:%M:%S")})

    def run():
        try:
            job["result"] = work(log)
        except KitError as e:
            job["error"] = str(e)
            log("fail", str(e))
        except Exception as e:   # never let a job thread die silently
            job["error"] = f"{type(e).__name__}: {e}"
            log("fail", job["error"])
        job["done"] = True
    threading.Thread(target=run, daemon=True).start()
    return jid


# ---------------------------------------------------------------- API
def api(method, path, body, q):
    """-> (status, payload). Pure function of the request, so tests can call it without a server."""
    if method == "GET":
        if path == "/api/state":
            return 200, state()
        if path == "/api/rolespec":
            return 200, {"text": rolespec.render(current())}
        if path == "/api/job":
            j = JOBS.get(q.get("id"))
            if not j:
                return 404, {"error": "no such job"}
            since = int(q.get("since", 0))
            return 200, {"done": j["done"], "lines": j["lines"][since:], "result": j["result"], "error": j["error"]}
        if path == "/api/plan":
            p = current()
            cl = ChangeList(p.dir)
            if not cl.plan_file.exists():
                return 200, {"plan": None}
            return 200, {"plan": cl.plan(), "approval": cl.approval()}
        if path == "/api/criteria":
            from . import summary
            summ, stale = summary.current(current())
            return 200, {"rows": evidence.evaluate(current()), "summary": summ, "summary_stale": stale}
        if path == "/api/logs":
            p = current()
            f = p.path("activity.jsonl")
            lines = f.read_text(encoding="utf-8").splitlines()[-500:] if f.exists() else []
            return 200, {"lines": [json.loads(x) for x in lines if x.strip()][::-1]}
        if path == "/api/usecases":
            from . import ai, usecases
            p = current()
            key, where = ai.proxy_key()
            from . import library
            return 200, {"usecases": [{k: v for k, v in u.items() if k != "raw"} for u in usecases.load(p)][::-1],
                         "consent": ai.consent(p), "key": bool(key), "key_source": where, "share": ai.share(p),
                         "model": (p.cfg.get("ai") or {}).get("model") or ai.DEFAULT_MODEL,
                         "library": [{k: e.get(k) for k in ("id", "title", "summary", "products", "proved", "saved")}
                                     for e in library.entries()], "library_folder": str(library.folder())}
        if path == "/api/usecase/directions":
            from . import usecases
            return 200, {"text": usecases.directions_md(usecases.get(current(), q.get("id")))}
        if path == "/api/users":
            p = current()
            plan = {i["key"]: i for i in (ChangeList(p.dir).plan()["items"] if ChangeList(p.dir).plan_file.exists() else [])}
            return 200, {"users": [{"n": e["key"].rsplit(".", 1)[-1],
                                    "email": plan.get(e["key"], {}).get("body", {}).get("email", e["name"])}
                                   for e in lifecycle.ledger(p).active("zia") if e["kind"] == "user"]}
        return 404, {"error": "not found"}

    # ---- POST
    if path == "/api/pov/new":
        names = [x for x in body.get("products") or [] if x in products.REGISTRY]
        if not (body.get("customer") or "").strip():
            raise KitError("Enter the customer's name.")
        if not names:
            raise KitError("Choose at least one product.")
        p = povs.new(body["customer"].strip(), names, (body.get("prefix") or "ZPOV").strip(),
                     remind.parse_date(body["ends"]) if body.get("ends") else None)
        settings.set_value(p, "client_mode", body.get("client_mode") or "single")
        return 200, {"id": p.id}
    if path == "/api/pov/use":
        povs.Pov(body["id"])
        povs.use(body["id"])
        return 200, {"ok": True}
    if path == "/api/settings":
        p = current()
        for k, v in (body.get("values") or {}).items():
            if v in ("", None) and k not in settings.LISTS:
                continue
            settings.set_value(p, k, v, save=False)
        p.save()
        return 200, {"settings": settings.snapshot(p)}
    if path == "/api/connect":
        p = current()
        for k in ("vanity_domain", "cloud", "customer_id"):
            if body.get(k) is not None and str(body[k]).strip():
                settings.set_value(p, k, body[k], save=False)
        slot = body.get("slot") or ("main" if p.cfg.get("client_mode", "single") == "single" else "discovery")
        cid, secret = (body.get("client_id") or "").strip(), (body.get("secret") or "").strip()
        known = ((p.cfg.get("clients") or {}).get(slot) or {}).get("client_id")
        if secret or not known:
            if not (cid and secret):
                raise KitError("Enter the client ID and the secret.")
            secrets.put(p.id, f"{slot}-client-secret", secret)
            p.cfg.setdefault("clients", {})[slot] = {"client_id": cid}
            p.log("connect", f"{slot} client saved")
        p.save()
        sign_in_check(p, "discovery" if slot in ("main", "discovery") else "apply")   # a bad secret shows here
        return 200, {"ok": True}
    if path == "/api/preflight":
        p = current()
        good, why = secrets.keychain_works()
        from .core.checks import FAIL, OK, check
        checks = [check("keychain", "Keychain works on this computer", OK if good else FAIL, why,
                        "" if good else "Unlock the login keychain (Mac) or install a keyring service (Linux).")]
        _, more = lifecycle.discover(p, tf)
        checks += more
        return 200, {"checks": checks, "exit": exit_code(checks)}
    if path == "/api/plan":
        p = current()
        items, notes, h, checks = lifecycle.plan(p, tf)
        return 200, {"items": items, "notes": notes, "hash": h, "checks": checks}
    if path == "/api/approve":
        p = current()
        if not body.get("reviewed"):
            raise KitError("Tick the box to confirm the customer reviewed the change list.")
        rec = ChangeList(p.dir).approve(body.get("by"), body.get("note") or "")
        p.log("approve", f"change list {rec['hash'][:12]} approved by {rec['by']}")
        return 200, {"approval": rec}
    if path == "/api/approve/file":
        p = current()
        text = body.get("content") or ""
        if len(text) > 20000:
            raise KitError("That file is too large to be an approval file.")
        f = p.path("approval-upload.json")
        f.write_text(text, encoding="utf-8")
        try:
            rec = ChangeList(p.dir).approve_file(f)
        finally:
            f.unlink(missing_ok=True)
        p.log("approve", f"change list {rec['hash'][:12]} approved by {rec['by']} on the change-list page")
        return 200, {"approval": rec}
    if path == "/api/summary":
        from . import summary
        p = current()

        def work(log):
            log("info", "Asking Claude through AI Guard for the executive summary (results only, names removed)")
            s = summary.write(p, body.get("note") or "")
            log("ok", s["headline"])
            return s
        return 200, {"job": start_job("summary", work)}
    if path == "/api/apply":
        p = current()
        return 200, {"job": start_job("apply", lambda log: len(lifecycle.apply(p, tf, log).active()))}
    if path == "/api/status":
        p = current()
        return 200, {"job": start_job("status", lambda log: lifecycle.status(p, tf, fix=bool(body.get("fix")), log=log))}
    if path == "/api/mcp":
        p, what = current(), body.get("what")
        if what == "consent":
            mcp.record_consent(p, body.get("by"))
        elif what == "install":
            return 200, {"path": str(mcp.install(p))}
        elif what == "remove":
            return 200, {"removed": mcp.remove(p)}
        elif what == "config":
            return 200, {"config": {"mcpServers": mcp.snippet(p)}}
        return 200, {"ok": True}
    if path == "/api/remind/install":
        return 200, {"message": remind.install()}
    if path == "/api/record":
        p = current()
        p.cfg["record"] = bool(body.get("on"))
        p.save()
        return 200, {"record": p.cfg["record"]}
    if path == "/api/selftest":
        from . import selftest
        p = current()
        if body.get("lab") is not True:
            raise KitError("Tick the box to confirm this is your own lab tenant.")
        return 200, {"job": start_job("selftest", lambda log: selftest.run(p, tf, log, lab=True))}
    if path == "/api/test-api":
        p = current()
        return 200, {"job": start_job("proofs", lambda log: lifecycle.api_proofs(p, tf))}
    if path == "/api/import-probe":
        p = current()
        data = body.get("data")
        if not isinstance(data, dict):
            raise KitError("That isn't a probe results file.")
        tmp = p.path("probe-upload.json")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        try:
            d = evidence.import_probe(p, tmp)
        finally:
            tmp.unlink(missing_ok=True)
        return 200, {"run_id": d["run_id"], "results": len(d["results"])}
    if path == "/api/attest":
        p = current()
        rec = evidence.attest(p, body.get("criterion"), body.get("note") or "", body.get("by") or "SE")
        return 200, {"attestation": rec}
    if path == "/api/probe-pack":
        return 200, evidence.probe_pack(current())
    if path == "/api/backup":
        from . import backup
        d = backup.setup(body.get("folder") or "", body.get("passphrase") or "")
        return 200, {"folder": str(d)}
    if path == "/api/report":
        from .report import render_report
        p = current()
        p.path("report.html").write_text(render_report(p, evidence.evaluate(p), ChangeList(p.dir).approval()),
                                         encoding="utf-8")
        return 200, {"ok": True}
    if path == "/api/aiguard-policy":
        from .core.guard import LedgerTenant
        p = current()
        led = lifecycle.ledger(p)
        out = []
        products.get("aiguard").set_profile(LedgerTenant(tf(p, "apply"), led, []), p, led, body.get("profile"),
                                            lambda lv, m: out.append(m))
        return 200, {"message": " ".join(out)}
    if path == "/api/zpa-template":
        from . import connector_template
        p = current()
        if not lifecycle.ledger(p).find("zpa.provisioning_key"):
            raise KitError("No POV provisioning key yet: apply the change list with ZPA in scope first.")
        cloud = body.get("cloud") or "aws"
        return 200, {"template": connector_template.build_azure(p.id, p.prefix) if cloud == "azure"
                     else connector_template.build(p.id, p.prefix), "cloud": cloud}
    if path == "/api/reveal":   # a secret the SE asks for by name, shown once on their own screen
        p = current()
        what = body.get("what")
        if what == "zpa-key":
            return 200, {"value": secrets.get(p.id, "zpa-provisioning-key")}
        if what == "test-user" and str(body.get("n", "")).isdigit():
            return 200, {"value": secrets.get(p.id, f"zia-test-user-{int(body['n'])}")}
        return 400, {"error": "unknown secret"}
    if path == "/api/ai/consent":
        from . import ai
        ai.record_consent(current(), body.get("by"))
        return 200, {"ok": True}
    if path == "/api/ai/key":
        from . import ai
        k = (body.get("key") or "").strip()
        if len(k) < 16:
            raise KitError("Paste the AI Guard app's proxy key.")
        secrets.put(*ai.OWN_KEY, k)
        return 200, {"ok": True}
    if path == "/api/usecase/propose":
        from . import usecases
        p = current()
        text = (body.get("prompt") or "").strip()
        if not text:
            raise KitError("Describe the use case first.")

        def work(log):
            log("info", "Reading the tenant (read-only) for a fresh snapshot")
            snaps, _ = lifecycle.discover(p, tf)
            log("info", "Asking Claude through AI Guard")
            uc = usecases.propose(p, snaps, text, by=body.get("by") or "SE")
            log("ok", f"{uc['id']}: {len(uc['spec']['changes'])} changes the kit can build, "
                      f"{len(uc['spec']['directions'])} directions")
            return {k: v for k, v in uc.items() if k != "raw"}
        return 200, {"job": start_job("usecase", work)}
    if path == "/api/ai/share":
        from . import ai
        settings.set_value(current(), "ai.share", body.get("share"))
        return 200, {"share": ai.share(current()), "consent": ai.consent(current())}
    if path == "/api/usecase/refine":
        from . import usecases
        p, uid, text = current(), body.get("id"), (body.get("feedback") or "").strip()
        if not text:
            raise KitError("Say what to change.")

        def work(log):
            log("info", "Reading the tenant (read-only) for a fresh snapshot")
            snaps, _ = lifecycle.discover(p, tf)
            log("info", f"Asking Claude through AI Guard to rework {uid}")
            uc = usecases.refine(p, snaps, uid, text, by=body.get("by") or "SE")
            log("ok", f"{uid}: {len(uc['spec']['changes'])} changes the kit can build, "
                      f"{len(uc['spec']['directions'])} directions")
            return {k: v for k, v in uc.items() if k != "raw"}
        return 200, {"job": start_job("usecase", work)}
    if path == "/api/library/save":
        from . import library, usecases
        p = current()
        e = library.save(p, usecases.get(p, body.get("id")), title=body.get("title"))
        return 200, {"entry": e}
    if path == "/api/library/use":
        from . import library
        p, name = current(), body.get("name")

        def work(log):
            log("info", "Reading the tenant (read-only) to check the library entry against it")
            snaps, _ = lifecycle.discover(p, tf)
            uc = library.use(p, snaps, name)
            log("ok", f"{uc['id']} from the library (no AI call): {len(uc['spec']['changes'])} changes the kit can build")
            return {k: v for k, v in uc.items() if k != "raw"}
        return 200, {"job": start_job("usecase", work)}
    if path == "/api/usecase/status":
        from . import usecases
        uc = usecases.set_status(current(), body.get("id"), body.get("status"))
        return 200, {"usecase": {k: v for k, v in uc.items() if k != "raw"}}
    if path == "/api/handover":
        p = current()
        how = body.get("how")
        if how == "teardown":
            if body.get("confirm") != "DELETE":
                raise KitError("Type DELETE to confirm.")

            def work(log):
                checks = lifecycle.teardown(p, tf, log, include_adopted=bool(body.get("include_adopted")))
                if lifecycle.ledger(p).active():
                    log("warn", "Some objects are still in the ledger; secrets and data are kept until they're gone.")
                    return {"checks": checks, "finished": False}
                gone, purged = handover.finish(p)
                log("ok", f"Deleted {len(gone)} secrets and {', '.join(purged) or 'no'} customer data files.")
                return {"checks": checks, "finished": True}
            return 200, {"job": start_job("teardown", work)}
        if how == "terraform":
            def work(log):
                out, exported, skipped = handover.terraform(p, lifecycle.ledger(p))
                log("ok", f"Terraform folder: {out} ({len(exported)} objects; not exportable: "
                          f"{', '.join(e['name'] for e, _ in skipped) or 'none'})")
                gone, purged = handover.finish(p)
                log("ok", f"Deleted {len(gone)} secrets and {', '.join(purged) or 'no'} customer data files.")
                return {"folder": str(out), "finished": True}
            return 200, {"job": start_job("terraform", work)}
        raise KitError("Choose teardown or terraform.")
    return 404, {"error": "not found"}


def page_file(path, q, token):
    """Pages that carry customer data (change list, report) need the run's token too."""
    if q.get("t") != token:
        return None
    p = current()
    f = {"/plan": p.path("plan.html"), "/report": p.path("report.html")}.get(path)
    return f.read_bytes() if f and f.exists() else None


# ---------------------------------------------------------------- server
def serve(port=8790, open_browser=True):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qsl, urlsplit
    import webbrowser

    token = _rand.token_urlsafe(24)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj=None, ctype="application/json", raw=None):
            data = raw if raw is not None else json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _route(self, method):
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
            if host not in ("127.0.0.1", "localhost"):
                return self._send(403, {"error": "bad host"})
            u = urlsplit(self.path)
            q = dict(parse_qsl(u.query))
            if u.path == "/" and method == "GET":
                html = (HERE / "console.html").read_text(encoding="utf-8").replace("__POV_TOKEN__", token)
                return self._send(200, raw=html.encode(), ctype="text/html; charset=utf-8")
            if u.path in ("/plan", "/report") and method == "GET":
                data = page_file(u.path, q, token)
                return self._send(200, raw=data, ctype="text/html; charset=utf-8") if data else \
                    self._send(404, {"error": "not found"})
            if u.path == "/diagnostics" and method == "GET":
                data = diagnostics_zip(q, token)
                return self._send(200, raw=data, ctype="application/zip") if data else self._send(403, {"error": "bad token"})
            if not u.path.startswith("/api/") or self.headers.get("X-POV-Token") != token:
                return self._send(403, {"error": "bad token"})
            body = {}
            if method == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                if n > 20 * 1024 * 1024:
                    return self._send(413, {"error": "too large"})
                try:
                    body = json.loads(self.rfile.read(n) or b"{}")
                except ValueError:
                    return self._send(400, {"error": "bad JSON"})
            try:
                code, out = api(method, u.path, body, q)
            except KitError as e:
                code, out = 400, {"error": str(e)}
            except Exception as e:
                code, out = 500, {"error": f"{type(e).__name__}: {e}"}
            self._send(code, out)

        def do_GET(self):
            self._route("GET")

        def do_POST(self):
            self._route("POST")

    srv = None
    for p in range(port, port + 20):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), H)
            port = p
            break
        except OSError:
            continue
    if not srv:
        raise KitError(f"No free local port between {port} and {port + 19}.")
    url = f"http://127.0.0.1:{port}/"
    print(f"  POV console: {url}   (this computer only; Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    return srv
