"""Linked pilot devices: run the POV's device tests on another computer and see the results here, live.

The device runs `pov-probe link CODE` (or the one-line command the console shows). It connects OUT to this
console's device listener and asks for work: the console never reaches into the device, so the device needs no open
port. The listener is separate from the console itself and serves only /agent/* with the POV's link token, so linking a
device never exposes the console.

  same network   the listener on this computer's network address (port 8799 by default)
  anywhere       a Cloudflare quick tunnel (cloudflared, if installed) to the same listener: a public https URL that
                 forwards only /agent/* traffic; it changes each time it starts, so devices relink after a restart

What a linked device does: runs the device tests the console sends (after the same tenant check as always), sends
each result as it lands, and opens a test's page in its own browser for Show it. A run started on the device itself
(`pov-probe test`) is sent here too, once it finishes. Nothing else: no shell, no files.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
import uuid
from collections import deque

from .core import KitError

PORT = 8799
ONLINE = 75          # seconds since a device last asked for work, to call it online
POLL = 25            # how long a device's request for work waits for one

LOCK = threading.Condition()
DEVICES: dict[str, dict] = {}     # device id -> {name, os, user, version, seen, queue}
CMDS: dict[str, dict] = {}        # command id -> {device, on_result, results, done, res, error, stop}
LISTEN: dict = {}                 # srv, port, pov, token, tunnel (process), url


# ---------------------------------------------------------------- state kept with the POV
def _state(pov):
    st = pov.read_json("devlink.json", {}) or {}
    if not st.get("token"):
        st["token"] = secrets.token_urlsafe(24)
        pov.write_json("devlink.json", st)
    return st


def _save(pov, **kw):
    st = _state(pov)
    st.update(kw)
    pov.write_json("devlink.json", st)
    return st


def lan_addresses():
    out = []
    try:   # the address this computer uses on its network (no packet is sent)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ip = s.getsockname()[0]
            if not ip.startswith("127."):
                out.append(ip)
    except OSError:
        pass
    try:
        host = socket.gethostname()
        if host and "." not in host:
            host += ".local"
        if host:
            out.append(host)
    except OSError:
        pass
    return out


def urls():
    if not LISTEN.get("srv"):
        return []
    port = LISTEN["port"]
    out = [f"http://{a}:{port}" for a in lan_addresses()]
    if LISTEN.get("url"):
        out.insert(0, LISTEN["url"])
    return out


def code(pov):
    """The link code a device needs: where to reach this console's listener, and the POV's link token."""
    if not LISTEN.get("srv"):
        raise KitError("Turn on device linking first.")
    blob = {"u": urls(), "t": _state(pov)["token"], "p": pov.id, "c": pov.cfg.get("customer") or pov.id}
    return base64.urlsafe_b64encode(json.dumps(blob, separators=(",", ":")).encode()).decode().rstrip("=")


def commands(pov):
    from .device_setup import base_url
    c = code(pov)
    return {"macos": f"curl -fsSL {base_url()}/install-probe.sh | bash && ~/.zscaler-pov-probe/app/pov-probe link '{c}'",
            "windows": f"& ([scriptblock]::Create((irm {base_url()}/install-probe.ps1))); "
                       f"& \"$env:USERPROFILE\\.zscaler-pov-probe\\app\\pov-probe.cmd\" link '{c}'",
            "code": c}


# ---------------------------------------------------------------- the console side of a run
def devices(pov=None):
    now = time.time()
    with LOCK:
        rows = [{"id": k, "name": v.get("name"), "user": v.get("user"), "os": v.get("os"), "version": v.get("version"),
                 "seen": int(now - v.get("seen", 0)), "online": now - v.get("seen", 0) < ONLINE,
                 "busy": any(c["device"] == k and not c["done"] for c in CMDS.values()),
                 "last": v.get("last")}
                for k, v in DEVICES.items() if not pov or v.get("pov") == pov.id]
    return sorted(rows, key=lambda r: (not r["online"], r["name"] or ""))


def _device(dev_id):
    d = DEVICES.get(dev_id)
    if not d:
        raise KitError("That device isn't linked (any more). Run the link command on it again.")
    if time.time() - d.get("seen", 0) > ONLINE:
        raise KitError(f"{d.get('name') or 'The device'} hasn't been in touch for a while: check it's on, awake and "
                       "still running the link command.")
    return d


def _send(dev_id, cmd):
    with LOCK:
        _device(dev_id)["queue"].append(cmd)
        LOCK.notify_all()


def open_on(dev_id, url):
    if not re.match(r"^https?://", str(url or "")):
        raise KitError("Only web pages can be opened on a device.")
    _send(dev_id, {"id": uuid.uuid4().hex[:8], "op": "open", "url": url})
    return DEVICES[dev_id].get("name")


def run_on(dev_id, criteria, pack, on_result=None, stop=None, timeout=900, gate=None):
    """Runs the tests on a linked device and waits for it. -> the device's probe run (as probe.run returns it)"""
    cid = uuid.uuid4().hex[:8]
    with LOCK:
        _device(dev_id)
        CMDS[cid] = {"device": dev_id, "on_result": on_result, "done": False, "res": None, "error": None,
                     "stop": False, "at": time.time()}
    _send(dev_id, {"id": cid, "op": "run", "criteria": criteria, "pack": pack, "gate": gate or []})
    end = time.time() + timeout
    with LOCK:
        while not CMDS[cid]["done"]:
            if stop and stop():
                CMDS[cid]["stop"] = True
            if time.time() > end:
                CMDS[cid].update(done=True, error="The device stopped answering during the run.")
                break
            seen = DEVICES.get(dev_id, {}).get("seen", 0)
            if time.time() - seen > ONLINE:
                CMDS[cid].update(done=True, error="The device went offline during the run.")
                break
            LOCK.wait(1.0)
        c = CMDS.pop(cid)
    if c["error"]:
        raise KitError(c["error"])
    return c["res"]


# ---------------------------------------------------------------- the device listener (only /agent/*)
def handle(method, path, body, auth, q, current):
    """One request from a device. -> (code, obj). `current` is the POV the console has open now."""
    pov = current()
    tok = _state(pov)["token"]
    if not auth or not hmac.compare_digest(auth, tok):
        return 403, {"error": "This link isn't for the POV the console has open. Ask the SE for the current link "
                              "command."}
    dev = str(body.get("device") or q.get("device") or "")[:64]
    if path == "/agent/hello" and method == "POST":
        dev = dev or uuid.uuid4().hex[:12]
        with LOCK:
            d = DEVICES.setdefault(dev, {"queue": deque()})
            d.update(pov=pov.id, seen=time.time(), **{k: str(body.get(k) or "")[:120]
                                                       for k in ("name", "os", "user", "version")})
        pov.log("probe", f"device linked: {d.get('name')} ({d.get('user') or 'no user'})")
        return 200, {"device": dev, "poll": POLL, "pov": pov.id, "customer": pov.cfg.get("customer") or pov.id}
    if dev not in DEVICES:
        return 404, {"error": "unknown device: link again"}
    if path == "/agent/next" and method == "GET":
        end = time.time() + POLL
        with LOCK:
            d = DEVICES[dev]
            while True:
                d["seen"] = time.time()
                if d["queue"]:
                    return 200, d["queue"].popleft()
                left = end - time.time()
                if left <= 0:
                    return 200, {"op": "none"}
                LOCK.wait(min(left, 5))
    if path == "/agent/result" and method == "POST":
        with LOCK:
            DEVICES[dev]["seen"] = time.time()
            c = CMDS.get(str(body.get("cmd")))
        if not c:
            return 200, {"stop": True}
        r = body.get("result") or {}
        if c["on_result"]:
            try:
                c["on_result"](r)
            except Exception:   # noqa: BLE001
                pass
        return 200, {"stop": c["stop"]}
    if path == "/agent/done" and method == "POST":
        with LOCK:
            DEVICES[dev]["seen"] = time.time()
            c = CMDS.get(str(body.get("cmd")))
            if c:
                c.update(done=True, res=body.get("res"), error=body.get("error"))
                LOCK.notify_all()
        return 200, {"ok": True}
    if path == "/agent/upload" and method == "POST":   # a run started on the device itself
        res = body.get("res") or {}
        if not isinstance(res, dict) or not {"run_id", "results"} <= res.keys():
            return 400, {"error": "not a probe run"}
        if res.get("pov") and res["pov"] != pov.id:
            return 409, {"error": f"these results are for POV {res['pov']}, the console has {pov.id} open"}
        from . import evidence, probe
        path_ = pov.path(f"devlink-{res['run_id']}.json")
        probe.save(dict(res, linked=DEVICES[dev].get("name")), path_)
        try:
            evidence.import_probe(pov, path_)
        finally:
            path_.unlink(missing_ok=True)
        ok = sum(1 for r in res["results"] if r.get("pass"))
        with LOCK:
            DEVICES[dev].update(seen=time.time(), last={"run_id": res["run_id"], "ok": ok, "total": len(res["results"]),
                                                        "at": res.get("at"), "results": res["results"]})
        return 200, {"ok": True, "imported": True}
    return 404, {"error": "not found"}


def start(pov, current, port=None, tunnel=False):
    """Turns on the device listener (and, with tunnel, a Cloudflare quick tunnel to it). -> status"""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qsl, urlsplit
    if not LISTEN.get("srv"):
        class A(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _go(self, method):
                u = urlsplit(self.path)
                body, raw = {}, b""
                if method == "POST":
                    n = int(self.headers.get("Content-Length") or 0)
                    if n > 8 * 1024 * 1024:
                        return self._send(413, {"error": "too large"})
                    raw = self.rfile.read(n) if n else b""
                if u.path.startswith("/nss/") and method == "POST":   # the POV's Cloud NSS web-log feed
                    from . import logfeed
                    try:
                        return self._send(*logfeed.handle(current(), u.path, raw))
                    except Exception as e:   # noqa: BLE001
                        return self._send(500, {"text": f"{type(e).__name__}", "code": 8})
                if method == "POST":
                    try:
                        body = json.loads(raw or b"{}")
                    except ValueError:
                        return self._send(400, {"error": "bad JSON"})
                if not u.path.startswith("/agent/"):
                    return self._send(404, {"error": "not found"})
                auth = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
                try:
                    code_, out = handle(method, u.path, body, auth, dict(parse_qsl(u.query)), current)
                except KitError as e:
                    code_, out = 409, {"error": str(e)}
                except Exception as e:   # noqa: BLE001
                    code_, out = 500, {"error": f"{type(e).__name__}: {e}"}
                self._send(code_, out)

            def _send(self, code_, obj):
                data = json.dumps(obj, default=str).encode()
                self.send_response(code_)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._go("GET")

            def do_POST(self):
                self._go("POST")

        base = int(port or _state(pov).get("port") or PORT)
        for p in range(base, base + 10):
            try:
                srv = ThreadingHTTPServer(("0.0.0.0", p), A)
                break
            except OSError:
                continue
        else:
            raise KitError(f"No free port between {base} and {base + 9} for the device listener.")
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        LISTEN.update(srv=srv, port=p)
    _save(pov, listen=True, port=LISTEN["port"], tunnel=bool(tunnel))
    if tunnel and not (LISTEN.get("tunnel") and LISTEN["tunnel"].poll() is None):
        start_tunnel()
    if not tunnel:
        stop_tunnel()
    return status(pov)


def cloudflared():
    for p in (shutil.which("cloudflared"), "/opt/homebrew/bin/cloudflared", "/usr/local/bin/cloudflared"):
        if p and os.path.exists(p):
            return p
    return None


def start_tunnel(wait=25):
    exe = cloudflared()
    if not exe:
        raise KitError("For devices on other networks the console uses a Cloudflare quick tunnel, and cloudflared "
                       "isn't installed on this computer. Install it (macOS: `brew install cloudflared`; Windows: "
                       "`winget install Cloudflare.cloudflared`), then turn this on again. Devices on this network "
                       "work without it.")
    proc = subprocess.Popen([exe, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{LISTEN['port']}"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    LISTEN.update(tunnel=proc, url=None)
    found = threading.Event()

    def read():
        for line in proc.stdout:
            m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", line)
            if m and not LISTEN.get("url"):
                LISTEN["url"] = m.group(0)
                found.set()
    threading.Thread(target=read, daemon=True).start()
    if not found.wait(wait):
        stop_tunnel()
        raise KitError("The Cloudflare tunnel didn't start (no address after 25 seconds). Devices on this network "
                       "still work; try again, or check this computer can reach trycloudflare.com.")
    return LISTEN["url"]


def stop_tunnel():
    p = LISTEN.pop("tunnel", None)
    LISTEN.pop("url", None)
    if p and p.poll() is None:
        p.terminate()


def stop(pov):
    stop_tunnel()
    srv = LISTEN.pop("srv", None)
    if srv:
        srv.shutdown()
        srv.server_close()
    LISTEN.pop("port", None)
    _save(pov, listen=False, tunnel=False)
    return status(pov)


def status(pov):
    st = _state(pov)
    on = bool(LISTEN.get("srv"))
    out = {"on": on, "port": LISTEN.get("port"), "tunnel": LISTEN.get("url"), "tunnel_wanted": bool(st.get("tunnel")),
           "cloudflared": bool(cloudflared()), "devices": devices(pov), "urls": urls() if on else []}
    if on:
        out["commands"] = commands(pov)
    return out


def resume(pov, current, log=lambda *a: None):
    """At console start: turn the listener back on if it was on (an update restarts the console)."""
    st = pov.read_json("devlink.json", {}) or {}
    if st.get("listen"):
        try:
            start(pov, current, tunnel=st.get("tunnel"))
        except KitError as e:
            log("warn", str(e))
