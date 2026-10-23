"""The console opens without a terminal window: reuse a running one, start one in the background, stop it."""
import json
import os
import sys
import time

import pytest

from povkit import gui, installer, launch


@pytest.fixture
def base(tmp_path, monkeypatch):
    monkeypatch.setattr(launch, "BASE", tmp_path)
    monkeypatch.setattr(launch, "STATE", tmp_path / "console.json")
    monkeypatch.setattr(launch, "LOG", tmp_path / "console.log")
    return tmp_path


def test_a_stale_state_file_is_cleared(base):
    launch.STATE.write_text(json.dumps({"pid": 999999, "port": 1, "url": "http://127.0.0.1:1/"}))
    assert launch.running() is None and not launch.STATE.exists()


def test_state_file_is_only_cleared_by_its_own_console(base):
    launch.write_state(8790, "http://127.0.0.1:8790/")
    st = json.loads(launch.STATE.read_text())
    assert st["pid"] == os.getpid() and st["port"] == 8790
    launch.STATE.write_text(json.dumps({**st, "pid": st["pid"] + 1}))
    launch.clear_state()
    assert launch.STATE.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")
def test_background_start_reuse_and_stop(base, monkeypatch):
    monkeypatch.setenv("ZPOV_HOME", str(base))   # the child's own BASE
    url = launch.open_background(port=8931, open_browser=False, wait=60)
    try:
        st = launch.running()
        assert st and st["background"] and st["url"] == url
        assert launch.open_background(port=8931, open_browser=False) == url   # reused, not a second console
        assert "in the background" in launch.LOG.read_text()
    finally:
        assert launch.stop()
    assert launch.running() is None


def test_a_console_that_dies_on_start_says_why(base, monkeypatch):
    monkeypatch.setattr(launch, "KIT", base / "missing.py")
    with pytest.raises(Exception, match="stopped while starting"):
        launch.open_background(port=8932, open_browser=False, wait=20)


def test_watchdog_stops_an_idle_console_but_not_during_a_job():
    stopped, busy = [], [True]
    launch.watchdog(lambda: 0, lambda: busy[0], lambda: stopped.append(1), idle=0, every=0.05)
    time.sleep(0.2)
    assert not stopped   # a job is running
    busy[0] = False
    time.sleep(0.3)
    assert stopped


def test_stop_and_ping_endpoints(monkeypatch):
    calls = []
    monkeypatch.setattr(gui, "stop_console", lambda: calls.append("stop"))
    assert gui.api("GET", "/api/ping", {}, {}) == (200, {"ok": True})
    gui.JOBS["x"] = {"kind": "apply", "done": False}
    try:
        with pytest.raises(Exception, match="apply is still running"):
            gui.api("POST", "/api/stop", {}, {})
        assert gui.api("POST", "/api/stop", {"force": True}, {})[0] == 200
    finally:
        gui.JOBS.pop("x")
    time.sleep(0.5)
    assert calls == ["stop"]


def test_shortcuts_open_without_a_terminal(tmp_path, monkeypatch):
    app = tmp_path / "Zscaler POV Console.app"
    installer.mac_app(app, tmp_path / "kit")
    launch_sh = (app / "Contents" / "MacOS" / "launch").read_text()
    assert "gui --background" in launch_sh and "Terminal" not in launch_sh and "display dialog" in launch_sh
    assert b"LSUIElement" in (app / "Contents" / "Info.plist").read_bytes()
    vbs = tmp_path / "open.vbs"
    installer.win_launcher(vbs, tmp_path / "kit")
    text = vbs.read_text()
    assert "gui --background" in text and ", 0, True)" in text and "MsgBox" in text
