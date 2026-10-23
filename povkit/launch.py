"""Opening the POV console without a terminal window.

The desktop shortcut runs `pov-kit gui --background`: if a console is already running it just opens the browser on
it; otherwise it starts one as a background process (no window), waits until it answers, and exits. The console
writes where it listens to ~/.zscaler-pov-kit/console.json, and its output to console.log next to it.

A background console stops itself once no console page has been open for a while (the page checks in every minute),
never while a job such as apply is running. The Stop button in the page, or `pov-kit gui --stop`, stops it at once.
`pov-kit gui` on its own still runs in the terminal, as before.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from .core import KitError
from .core.pov import BASE

STATE = BASE / "console.json"
LOG = BASE / "console.log"
ENV = "POVKIT_BACKGROUND"
IDLE_MINUTES = 30          # a background console with no page open this long stops itself
START_TIMEOUT = 180        # the first start can install the kit's libraries
KIT = Path(__file__).resolve().parent.parent / "pov_kit.py"
WINDOWS = os.name == "nt"
CREATE_NO_WINDOW, NEW_GROUP = 0x08000000, 0x00000200


def background():
    """Is this process a console started without a window?"""
    return os.environ.get(ENV) == "1"


def write_state(port, url):
    from . import VERSION
    BASE.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({"pid": os.getpid(), "port": port, "url": url, "version": VERSION,
                                 "background": background(), "started": time.time()}), encoding="utf-8")


def clear_state():
    """Remove console.json, if it's this process's."""
    try:
        if json.loads(STATE.read_text(encoding="utf-8")).get("pid") == os.getpid():
            STATE.unlink()
    except (OSError, ValueError):
        pass


def _alive(pid):
    if not pid:
        return False
    if WINDOWS:
        r = subprocess.run(["tasklist", "/FI", f"PID eq {int(pid)}", "/NH"], capture_output=True, text=True,
                           creationflags=CREATE_NO_WINDOW)
        return str(pid) in r.stdout
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _answers(url):
    """Does a POV console answer at url? (its page carries the kit's title)"""
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.status == 200 and b"POV" in r.read(4096)
    except Exception:   # noqa: BLE001 - anything else means no
        return False


def running():
    """The running console's {pid, port, url, ...}, or None. Clears a stale console.json."""
    try:
        st = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if _alive(st.get("pid")) and _answers(st.get("url", "")):
        return st
    try:
        STATE.unlink()
    except OSError:
        pass
    return None


def _log_file():
    BASE.mkdir(parents=True, exist_ok=True)
    if LOG.exists() and LOG.stat().st_size > 1_000_000:   # keep the last run's output, not every run's
        LOG.replace(LOG.with_suffix(".log.1"))
    return open(LOG, "a", encoding="utf-8")


def log_tail(n=12):
    try:
        return "\n".join(LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-n:])
    except OSError:
        return ""


def spawn(port=8790, open_browser=True):
    """Start a console with no window. -> the Popen."""
    env = {**os.environ, ENV: "1", "PYTHONUNBUFFERED": "1"}
    cmd = [sys.executable, str(KIT), "gui", "--port", str(port)] + ([] if open_browser else ["--no-browser"])
    out = _log_file()
    out.write(f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} starting the console in the background\n")
    out.flush()
    kw = {"stdin": subprocess.DEVNULL, "stdout": out, "stderr": subprocess.STDOUT, "env": env, "cwd": str(Path.home())}
    if WINDOWS:
        kw["creationflags"] = CREATE_NO_WINDOW | NEW_GROUP
    else:
        kw["start_new_session"] = True   # not tied to the launcher, so it outlives it
    return subprocess.Popen(cmd, **kw)


def open_background(port=8790, open_browser=True, wait=START_TIMEOUT):
    """The desktop shortcut: reuse a running console or start one without a window. -> its URL."""
    import webbrowser
    st = running()
    if st:
        if open_browser:
            webbrowser.open(st["url"])
        return st["url"]
    proc = spawn(port, open_browser)
    end = time.time() + wait
    while time.time() < end:
        if proc.poll() is not None:
            raise KitError("The POV console stopped while starting.\n\n" + log_tail())
        st = running()
        if st and st.get("pid") == proc.pid:
            return st["url"]   # the console opens the browser itself
        time.sleep(0.5)
    raise KitError(f"The POV console didn't answer within {wait // 60} minutes. Its log: {LOG}\n\n" + log_tail())


def stop():
    """Stop the running console. -> True if one was running."""
    st = running()
    if not st:
        return False
    pid = int(st["pid"])
    if WINDOWS:
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, creationflags=CREATE_NO_WINDOW)
    else:
        os.kill(pid, signal.SIGTERM)
    for _ in range(20):
        if not _alive(pid):
            break
        time.sleep(0.25)
    try:
        STATE.unlink()
    except OSError:
        pass
    return True


def watchdog(seen, busy, shutdown, idle=IDLE_MINUTES * 60, every=60):
    """In a background console: stop once no page has checked in for `idle` seconds and no job is running."""
    import threading

    def loop():
        while True:
            time.sleep(every)
            if time.time() - seen() > idle and not busy():
                print(f"  No console page open for {idle // 60} minutes: stopping.", flush=True)
                shutdown()
                return
    threading.Thread(target=loop, daemon=True).start()
