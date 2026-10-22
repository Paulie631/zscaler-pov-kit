"""POV end dates and reminders, so no POV ends with its objects still in the customer's tenant.

Every POV has an end date (30 days from the start unless set: `pov-kit set ends 2026-12-15`). Status warns in the
last week and fails once it has passed with POV objects still in the tenant.

`pov-kit remind install` adds a scheduled task on this computer (Windows Task Scheduler, a macOS LaunchAgent or a
cron line on Linux) that runs `pov-kit remind run` every morning. That run reads only the POV folders on this laptop
(no tenant calls, no keys) and shows a desktop notification when something needs doing: a POV ending within a week,
one past its end with objects still in the tenant, or a ledger not backed up. On Mondays it also sums up every
active POV.
"""
from __future__ import annotations

import datetime as dt
import os
import platform
import shlex
import subprocess
from pathlib import Path

from .core import KitError
from .core import pov as povs
from .core.checks import FAIL, INFO, OK, WARN, check
from .core.ledger import Ledger

DEFAULT_DAYS = 30
TASK = "Zscaler POV Kit reminder"
LAUNCH_ID = "com.zscaler.povkit.remind"


def today():
    return dt.date.today()


def ends(pov) -> dt.date:
    v = pov.cfg.get("ends")
    if v:
        return dt.date.fromisoformat(v)
    return dt.date.fromisoformat(pov.cfg.get("created", today().isoformat())[:10]) + dt.timedelta(days=DEFAULT_DAYS)


def parse_date(v: str) -> str:
    try:
        d = dt.date.fromisoformat(str(v).strip())
    except ValueError as e:
        raise KitError("Use a date like 2026-12-15.") from e
    return d.isoformat()


def active_objects(pov) -> int:
    return len(Ledger(pov.path("ledger.json"), pov.id, pov.prefix).active())


def end_check(pov):
    e, n = ends(pov), active_objects(pov)
    left = (e - today()).days
    done = pov.cfg.get("state") in ("handed_over", "torn_down")
    if done:
        return check("pov-end", "POV end date", OK, f"{e.isoformat()}; handed over")
    if left < 0:
        return check("pov-end", "POV end date", FAIL if n else WARN, f"ended {-left} days ago ({e.isoformat()}); "
                     f"{n} POV objects still in the tenant",
                     "Hand over now: `pov-kit handover teardown`, or `handover terraform` if the customer keeps it. "
                     "Or move the date: `pov-kit set ends YYYY-MM-DD`.")
    if left <= 7:
        return check("pov-end", "POV end date", WARN, f"ends in {left} days ({e.isoformat()}); {n} POV objects",
                     "Plan the handover with the customer: teardown, or the Terraform export.")
    return check("pov-end", "POV end date", OK if n else INFO, f"ends {e.isoformat()} ({left} days)")


def due(weekly=None):
    """What needs saying across every POV on this laptop. -> (urgent lines, summary lines)"""
    from . import backup
    weekly = today().weekday() == 0 if weekly is None else weekly
    urgent, summary = [], []
    for pid in povs.all_povs():
        p = povs.Pov(pid)
        if p.cfg.get("state") in ("handed_over", "torn_down"):
            continue
        c, n = end_check(p), active_objects(p)
        name = f"{p.cfg['customer']} ({pid})"
        if c["status"] in (WARN, FAIL):
            urgent.append(f"{name}: {c['detail']}")
        if n and not backup.folder():
            urgent.append(f"{name}: {n} objects and no backup off this laptop")
        if weekly:
            summary.append(f"{name}: {c['detail']}")
    return urgent, summary


def notify(title, text):
    """A desktop notification. Best effort: printing is the fallback."""
    print(f"{title}\n{text}")
    sysname = platform.system()
    try:
        if sysname == "Darwin":
            esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')  # noqa: E731
            subprocess.run(["osascript", "-e", f'display notification "{esc(text[:240])}" with title "{esc(title)}"'],
                           check=False, timeout=10)
        elif sysname == "Windows":
            ps = ("Add-Type -AssemblyName System.Windows.Forms; $n = New-Object System.Windows.Forms.NotifyIcon; "
                  "$n.Icon = [System.Drawing.SystemIcons]::Information; $n.Visible = $true; "
                  "$n.ShowBalloonTip(15000, $env:ZT, $env:ZB, 'Info'); Start-Sleep 16; $n.Dispose()")
            subprocess.run(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps], check=False,
                           timeout=30, env=dict(os.environ, ZT=title, ZB=text[:240]))
        elif sysname == "Linux":
            subprocess.run(["notify-send", title, text[:240]], check=False, timeout=10)
    except Exception:
        pass


def run(weekly=None, send=notify):
    urgent, summary = due(weekly)
    if urgent:
        send("Zscaler POV Kit: action needed", "\n".join(urgent))
    elif summary:
        send("Zscaler POV Kit: this week's POVs", "\n".join(summary))
    return urgent, summary


# ---------------------------------------------------------------- the scheduled task
def launcher() -> Path:
    root = Path(__file__).resolve().parent.parent
    return root / ("pov-kit.cmd" if platform.system() == "Windows" else "pov-kit")


def install(hour=9, minute=7):
    sysname, cmd = platform.system(), launcher()
    if sysname == "Windows":
        subprocess.run(["schtasks", "/Create", "/F", "/SC", "DAILY", "/ST", f"{hour:02d}:{minute:02d}", "/TN", TASK,
                        "/TR", f'"{cmd}" remind run'], check=True)
        return f"Task Scheduler: '{TASK}', daily at {hour:02d}:{minute:02d}"
    if sysname == "Darwin":
        plist = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_ID}.plist"
        plist.parent.mkdir(parents=True, exist_ok=True)
        plist.write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LAUNCH_ID}</string>
  <key>ProgramArguments</key><array><string>{cmd}</string><string>remind</string><string>run</string></array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>{hour}</integer><key>Minute</key><integer>{minute}</integer></dict>
</dict></plist>
""", encoding="utf-8")
        subprocess.run(["launchctl", "unload", str(plist)], check=False, capture_output=True)
        subprocess.run(["launchctl", "load", str(plist)], check=True)
        return f"LaunchAgent {plist}, daily at {hour:02d}:{minute:02d}"
    line = f"{minute} {hour} * * * {shlex.quote(str(cmd))} remind run  # {TASK}"
    old = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
    keep = [x for x in old.splitlines() if TASK not in x]
    subprocess.run(["crontab", "-"], input="\n".join(keep + [line]) + "\n", text=True, check=True)
    return f"cron, daily at {hour:02d}:{minute:02d}"


def uninstall():
    sysname = platform.system()
    if sysname == "Windows":
        subprocess.run(["schtasks", "/Delete", "/F", "/TN", TASK], check=False)
    elif sysname == "Darwin":
        plist = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_ID}.plist"
        subprocess.run(["launchctl", "unload", str(plist)], check=False, capture_output=True)
        plist.unlink(missing_ok=True)
    else:
        old = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
        subprocess.run(["crontab", "-"], input="\n".join(x for x in old.splitlines() if TASK not in x) + "\n",
                       text=True, check=False)

