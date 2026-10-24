"""The pilot device's own test runner: `pov-probe ui`.

The console's Device tests tab, cut down to what a pilot device needs: run the POV's tests, see each result and what it
means, and walk through the guided demos with Show it (pages open in this computer's browser). No tenant settings, no
API keys, nothing in any tenant changes. It reads the probe pack already on this device (the POV's tests) and serves a
page on this computer only (127.0.0.1), with a one-time token in its address.

Results are saved to a file every run (the SE imports it), and sent to the SE's console too when this device has a
link (`pov-probe link`, or a link code pasted here) and the console can be reached.

Two modes, chosen on the page: Presenter (the talk track: what to say, what to point at) and Plain (just the tests).
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from pathlib import Path

from . import VERSION, demo, device, probe

HERE = Path(__file__).resolve().parent
JOB: dict = {}
LOCK = threading.Lock()


def library(pack):
    crit, have = [], set()
    for c in pack.get("criteria") or []:
        tests = [{"id": demo.spec_id(c["id"], sp), "text": demo.describe_spec(sp), "type": sp.get("type"),
                  "open": demo.open_url(sp), "show": demo.show(sp)} for sp in c.get("probe") or []]
        if tests:
            crit.append({"criterion": c["id"], "title": c.get("title") or c["id"], "tests": tests})
            have.add(c["id"])
    stories = [dict(s, tests=[t["id"] for c in s["criteria"] for g in crit if g["criterion"] == c for t in g["tests"]])
               for s in demo.STORIES if have & set(s["criteria"])]
    return {"criteria": crit, "stories": stories}


def state():
    pack = device.current_pack()
    link = device.saved_link()
    return {"version": VERSION, "pack": {k: pack.get(k) for k in ("pov", "customer", "pack_id", "generated_at")}
            if pack else None, "summary": device.describe(pack), "library": library(pack) if pack else None,
            "link": {"customer": link.get("c"), "pov": link.get("p")} if link else None,
            "last": JOB.get("last"), "running": bool(JOB.get("thread") and JOB["thread"].is_alive()),
            "logs": demo.LOGS}


def _chosen(pack, ids):
    want = set(ids or [])
    crit = []
    for c in pack["criteria"]:
        specs = [sp for sp in c.get("probe") or [] if not want or demo.spec_id(c["id"], sp) in want]
        if specs:
            crit.append({"id": c["id"], "title": c.get("title"), "probe": specs, "hash": c.get("hash")})
    return crit


def start(ids=None, record=True):
    """Runs the chosen tests (all without ids) in the background. -> job id"""
    pack = device.current_pack()
    if not pack:
        raise device.DeviceError("No POV tests on this device yet: the SE's setup command installs them.")
    with LOCK:
        if JOB.get("thread") and JOB["thread"].is_alive():
            raise device.DeviceError("Tests are already running.")
        jid = secrets.token_hex(4)
        JOB.clear()
        JOB.update(id=jid, items=[], done=False, error=None, stop=False, result=None)
    crit = _chosen(pack, ids)
    gate = [c for c in pack["criteria"] if c["id"] == "IS-TEN-01"]

    def landed(r):
        sid = demo.spec_id(r["criterion"], {k: v for k, v in r["spec"].items() if k != "switched"})
        JOB["items"].append(dict(r, id=sid, text=demo.describe_spec(r["spec"]), open=demo.open_url(r["spec"]),
                                 show=demo.show(r["spec"])))

    def work():
        try:
            device.gate(gate or crit)
            res = probe.run(crit, pack=pack, on_result=landed, stop=lambda: JOB.get("stop"))
            ok = sum(1 for r in res["results"] if r["pass"])
            out = {"ok": ok, "total": len(res["results"]), "stopped": bool(res.get("stopped")), "file": None,
                   "sent": False, "run_id": res["run_id"]}
            if record and res["results"]:
                path = device.desktop() / f"pov-probe-results-{pack.get('pov', 'device')}-{res['run_id']}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                probe.save(res, path)
                out["file"] = str(path)
                msgs = []
                out["sent"] = device.send_to_console(res, say=msgs.append)
                out["sent_note"] = " ".join(msgs)
            JOB["result"] = out
            JOB["last"] = dict(out, at=time.strftime("%H:%M"))
        except device.DeviceError as e:
            JOB["error"] = str(e)
        except Exception as e:   # noqa: BLE001
            JOB["error"] = f"{type(e).__name__}: {e}"
        JOB["done"] = True
    JOB["thread"] = threading.Thread(target=work, daemon=True)
    JOB["thread"].start()
    return jid


def open_test(test_id):
    import webbrowser
    pack = device.current_pack() or {"criteria": []}
    for c in pack["criteria"]:
        for sp in c.get("probe") or []:
            if demo.spec_id(c["id"], sp) == test_id and demo.open_url(sp):
                webbrowser.open(demo.open_url(sp))
                return demo.open_url(sp)
    raise device.DeviceError("That test has no page to open.")


def api(method, path, body, q):
    if path == "/api/state":
        return state()
    if path == "/api/run" and method == "POST":
        return {"job": start(body.get("ids") or None, record=body.get("record", True))}
    if path == "/api/job":
        since = int(q.get("since", 0))
        return {"items": [{k: v for k, v in x.items() if k != "thread"} for x in JOB.get("items", [])[since:]],
                "done": JOB.get("done", True), "error": JOB.get("error"), "result": JOB.get("result")}
    if path == "/api/stop" and method == "POST":
        JOB["stop"] = True
        return {"ok": True}
    if path == "/api/open" and method == "POST":
        return {"url": open_test(body.get("id"))}
    if path == "/api/link" and method == "POST":   # a link code pasted on the page
        info = device.link_from_code(body.get("code"))
        lk = device.Link(info, say=lambda *a: None)
        url = lk.hello()
        device.HOME.mkdir(parents=True, exist_ok=True)
        device.LINK.write_text(json.dumps(dict(info, url=url, device=lk.device)), encoding="utf-8")
        return {"linked": True, "customer": lk.customer}
    if path == "/api/unlink" and method == "POST":
        device.LINK.unlink(missing_ok=True)
        return {"linked": False}
    raise device.DeviceError("not found")


def serve(port=8795, open_browser=True):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qsl, urlsplit
    import webbrowser
    token = secrets.token_urlsafe(18)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj=None, raw=None, ctype="application/json"):
            data = raw if raw is not None else json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _go(self, method):
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
            if host not in ("127.0.0.1", "localhost"):
                return self._send(403, {"error": "bad host"})
            u = urlsplit(self.path)
            if u.path == "/" and method == "GET":
                html = (HERE / "runner.html").read_text(encoding="utf-8").replace("__TOKEN__", token)
                return self._send(200, raw=html.encode(), ctype="text/html; charset=utf-8")
            if self.headers.get("X-Token") != token:
                return self._send(403, {"error": "bad token"})
            body = {}
            if method == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                try:
                    body = json.loads(self.rfile.read(n) or b"{}") if n else {}
                except ValueError:
                    return self._send(400, {"error": "bad JSON"})
            try:
                self._send(200, api(method, u.path, body, dict(parse_qsl(u.query))))
            except device.DeviceError as e:
                self._send(400, {"error": str(e)})
            except Exception as e:   # noqa: BLE001
                self._send(500, {"error": f"{type(e).__name__}: {e}"})

        def do_GET(self):
            self._go("GET")

        def do_POST(self):
            self._go("POST")

    srv = None
    for p in range(port, port + 20):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), H)
            port = p
            break
        except OSError:
            continue
    if not srv:
        raise device.DeviceError(f"No free local port between {port} and {port + 19}.")
    url = f"http://127.0.0.1:{port}/"
    print(f"  POV device tests: {url}   (this computer only; Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    return srv
