"""The desktop app opens the console in the background: no Terminal (or command) window for the end user."""
import subprocess
import threading
import time

from povkit import gui, installer


def test_mac_app_starts_in_the_background(tmp_path):
    app = tmp_path / "Zscaler POV Console.app"
    installer.mac_app(app, tmp_path / "kit")
    launch = (app / "Contents" / "MacOS" / "launch").read_text()
    assert "open -a Terminal" not in launch and "nohup" in launch and str(tmp_path / "kit" / "pov-kit") in launch
    assert "console.log" in launch and "display dialog" in launch
    if not installer.windows():   # Windows' bash (WSL) can't take a Windows path
        assert subprocess.run(["bash", "-n", str(app / "Contents" / "MacOS" / "launch")]).returncode == 0
    assert (app / "Contents" / "Resources" / "console.command").exists()          # still there, for troubleshooting


def test_windows_launcher_hides_the_window():
    v = installer.WIN_LAUNCH
    assert ', 0, False' in v and "console.log" in v and "ZPOV_HIDDEN" in v and "MsgBox" in v


def test_second_open_reuses_the_running_console(home, monkeypatch):
    opened, errors = [], []
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url))

    def run():
        try:
            gui.serve(port=8871, open_browser=False)
        except Exception as e:   # noqa: BLE001
            errors.append(repr(e))
    gui.SERVER.clear()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    for _ in range(300):   # slower to start on some CI machines
        if errors or (gui.SERVER.get("port") and gui._running_console(gui.SERVER["port"])):
            break
        time.sleep(0.1)
    assert not errors, errors
    port = gui.SERVER["port"]
    assert gui._running_console(port)
    assert gui.serve(port=port, open_browser=True) is None and opened == [f"http://127.0.0.1:{port}/"]
    gui.quit_console()
    t.join(10)
    assert not t.is_alive() and not gui._running_console(port)
