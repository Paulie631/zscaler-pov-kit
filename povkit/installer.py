"""Installing the kit on an SE's laptop, as the AI Guard SE Demo Kit does.

The double-click installers (Install Zscaler POV Kit.command / .cmd) install uv if needed, then run
`pov-kit install`, which:
  - copies the kit to ~/.zscaler-pov-kit/app (the previous copy is kept as app.previous for rollback)
  - adds a "Zscaler POV Console" shortcut: an app on the Mac desktop, a desktop and Start menu shortcut on Windows
  - lets the SE run `pov-kit` from any terminal (~/.local/bin on Mac and Linux, the user PATH on Windows)
POVs, secrets and the ledger stay where they are (~/.zscaler-pov-kit/povs and the keychain); installing, updating
and uninstalling never touch them or any tenant.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

from . import VERSION
from .core import KitError
from .core.pov import BASE

HERE = Path(__file__).resolve().parent.parent
APP = BASE / "app"
APP_NAME = "Zscaler POV Console"
CLI = "pov-kit"
UNINSTALL_LNK = "Uninstall Zscaler POV Kit.lnk"
FILES = ["pov-kit", "pov-kit.cmd", "pov_kit.py", "povkit", "assets", "docs", "plugin", "README.md", "SECURITY.md",
         "CHANGELOG.md", "TESTPLAN.md", "INSTALL.md", "pyproject.toml", "Uninstall Zscaler POV Kit.command",
         "Uninstall Zscaler POV Kit.cmd"]
EXECUTABLE = ("pov-kit", "Uninstall Zscaler POV Kit.command")


def windows():
    return platform.system() == "Windows"


def installed():
    """Is this copy the installed one?"""
    try:
        return APP.exists() and HERE.resolve() == APP.resolve()
    except OSError:
        return False


def is_git():
    return (HERE / ".git").exists()


def copy_kit(src=None, dest=None):
    """Copy the kit into dest via a staging folder, keeping the previous copy as dest.previous for rollback."""
    src, dest = Path(src or HERE), Path(dest or APP)
    stage, prev = dest.with_name(dest.name + ".new"), dest.with_name(dest.name + ".previous")
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    for f in FILES:
        s = Path(src) / f
        if s.is_dir():
            shutil.copytree(s, stage / f, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        elif s.exists():
            shutil.copy2(s, stage / f)
    for f in EXECUTABLE:
        if (stage / f).exists():
            os.chmod(stage / f, 0o755)
    if dest.exists():
        shutil.rmtree(prev, ignore_errors=True)
        try:
            dest.rename(prev)
        except OSError:   # Windows: a folder in use can't be renamed, so copy over it instead
            shutil.copytree(stage, dest, dirs_exist_ok=True)
            shutil.rmtree(stage, ignore_errors=True)
            return dest
    stage.rename(dest)
    return dest


def shortcut_paths():
    home = Path.home()
    if windows():
        menu = Path(os.getenv("APPDATA", str(home))) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
        return {"desktop": desktop_dir() / f"{APP_NAME}.lnk", "start": menu / f"{APP_NAME}.lnk",
                "start_uninstall": menu / UNINSTALL_LNK}
    if platform.system() == "Darwin":
        return {"desktop": home / "Desktop" / f"{APP_NAME}.app", "wrapper": home / ".local" / "bin" / CLI}
    return {"desktop": home / "Desktop" / f"{APP_NAME}.desktop", "wrapper": home / ".local" / "bin" / CLI}


def desktop_dir():
    """The real desktop folder on Windows (OneDrive can move it)."""
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", "[Environment]::GetFolderPath('Desktop')"],
                           capture_output=True, text=True, timeout=30)
        if r.stdout.strip():
            return Path(r.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        pass
    return Path.home() / "Desktop"


def win_shortcut(path, target, args, workdir, description, icon=None):
    ps = ("$ErrorActionPreference='Stop'; try { "
          "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:ZP_LNK); $s.TargetPath=$env:ZP_TGT; "
          "$s.Arguments=$env:ZP_ARGS; $s.WorkingDirectory=$env:ZP_WD; $s.Description=$env:ZP_DESC; "
          "if ($env:ZP_ICON) { $s.IconLocation=$env:ZP_ICON + ',0' }; $s.Save(); "
          "if (-not (Test-Path -LiteralPath $env:ZP_LNK)) { throw 'the shortcut file was not written' } "
          "} catch { [Console]::Out.WriteLine('ERR: ' + $_.Exception.Message); exit 1 }")
    env = {**os.environ, "ZP_LNK": str(path), "ZP_TGT": str(target), "ZP_ARGS": args, "ZP_WD": str(workdir),
           "ZP_DESC": description, "ZP_ICON": str(icon or "")}
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps],
                       capture_output=True, text=True, env=env, timeout=60)
    if r.returncode:
        raise KitError(f"Couldn't create the shortcut {Path(path).name}: "
                       f"{(r.stdout + r.stderr).strip().replace('ERR: ', '')[:300]}")


def mac_app(app, kit=None):
    """A small app bundle on the desktop: the kit's icon, and it opens the console in a Terminal window (closing
    the window stops the console). Built on the laptop, so Gatekeeper doesn't quarantine it."""
    import plistlib
    kit = Path(kit or APP)
    shutil.rmtree(app, ignore_errors=True)
    (app / "Contents" / "MacOS").mkdir(parents=True)
    (app / "Contents" / "Resources").mkdir(parents=True)
    info = {"CFBundleName": APP_NAME, "CFBundleDisplayName": APP_NAME, "CFBundleExecutable": "launch",
            "CFBundleIdentifier": "com.zscaler-pov-kit.console", "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": VERSION, "LSMinimumSystemVersion": "10.13"}
    icon = kit / "assets" / "pov-icon.icns"
    if icon.exists():
        shutil.copy2(icon, app / "Contents" / "Resources" / "icon.icns")
        info["CFBundleIconFile"] = "icon"
    with open(app / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump(info, f)
    console = app / "Contents" / "Resources" / "console.command"
    console.write_text(f'#!/bin/bash\n# Opens the {APP_NAME}. Close this window to stop it.\nexec "{kit / CLI}" gui\n',
                       encoding="utf-8")
    os.chmod(console, 0o755)
    launch = app / "Contents" / "MacOS" / "launch"
    launch.write_text(f'#!/bin/bash\nexec open -a Terminal "{console}"\n', encoding="utf-8")
    os.chmod(launch, 0o755)
    os.utime(app)


def win_user_path(add=None, remove=None):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
        try:
            val, kind = winreg.QueryValueEx(k, "Path")
        except FileNotFoundError:
            val, kind = "", winreg.REG_EXPAND_SZ
        parts = [p for p in val.split(";") if p]
        norm = lambda p: os.path.normcase(os.path.normpath(os.path.expandvars(p)))  # noqa: E731
        new = parts + ([add] if add and norm(add) not in {norm(p) for p in parts} else [])
        if remove:
            new = [p for p in new if norm(p) != norm(remove)]
        if new != parts:
            winreg.SetValueEx(k, "Path", 0, kind, ";".join(new))
            try:
                import ctypes
                ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 2, 5000, None)
            except Exception:
                pass
        return new


def shortcuts(log, kit=None):
    kit = Path(kit or APP)
    sp = shortcut_paths()
    if windows():
        for key in ("desktop", "start"):
            try:
                sp[key].parent.mkdir(parents=True, exist_ok=True)
                win_shortcut(sp[key], kit / "pov-kit.cmd", "gui", Path.home(), "Open the Zscaler POV console",
                             kit / "assets" / "pov-icon.ico")
                log("ok", f"Shortcut: {sp[key]}")
            except (KitError, OSError, subprocess.TimeoutExpired) as e:
                log("warn", str(e))
        try:
            win_shortcut(sp["start_uninstall"], kit / "Uninstall Zscaler POV Kit.cmd", "", kit,
                         "Remove the Zscaler POV Kit from this computer")
        except (KitError, OSError, subprocess.TimeoutExpired):
            pass
        try:
            win_user_path(add=str(kit))
            log("ok", f"In a new terminal, run  {CLI} gui  from any folder")
        except Exception as e:
            log("warn", f"Couldn't add the kit to your PATH ({e}). Use the desktop shortcut.")
        return
    sp["desktop"].parent.mkdir(parents=True, exist_ok=True)
    if platform.system() == "Darwin":
        mac_app(sp["desktop"], kit)
        log("ok", f"'{APP_NAME}' on your desktop (double-click to open the console)")
    else:
        sp["desktop"].write_text(f"[Desktop Entry]\nType=Application\nName={APP_NAME}\nExec={kit / CLI} gui\n"
                                 f"Icon={kit / 'assets' / 'pov-icon.png'}\nTerminal=true\n", encoding="utf-8")
        os.chmod(sp["desktop"], 0o755)
        log("ok", f"Shortcut: {sp['desktop']}")
    sp["wrapper"].parent.mkdir(parents=True, exist_ok=True)
    sp["wrapper"].write_text(f'#!/bin/bash\nexec "{kit / CLI}" "$@"\n', encoding="utf-8")
    os.chmod(sp["wrapper"], 0o755)
    on_path = str(sp["wrapper"].parent) in os.getenv("PATH", "").split(os.pathsep)
    log("ok", f"Command: {CLI} (from any folder" + (")" if on_path else "; open a new terminal first)"))


def install(log):
    if installed():
        log("ok", f"Kit already in {APP}; refreshing the shortcuts")
    else:
        copy_kit()
        log("ok", f"Kit {VERSION} copied to {APP}")
    shortcuts(log)
    log("info", f"POVs, settings and secrets stay in {BASE / 'povs'} and the keychain, unchanged.")
    log("ok", f"Installed. Open '{APP_NAME}' on your desktop, or run: {CLI} gui")


def uninstall(log):
    """Removes the installed kit, its shortcuts and PATH entry. Keeps POVs, secrets and every tenant object."""
    sp = shortcut_paths()
    for p in sp.values():
        if p.exists():
            shutil.rmtree(p) if p.is_dir() else p.unlink()
            log("ok", f"Removed {p}")
    if windows():
        try:
            win_user_path(remove=str(APP))
        except Exception:
            pass
    for d in (APP.with_name("app.previous"), APP.with_name("app.new")):
        shutil.rmtree(d, ignore_errors=True)
    if APP.exists():
        if windows() and installed():   # this launcher runs from the folder: remove it a moment after exit
            subprocess.Popen(f'cmd /c ping -n 3 127.0.0.1 >nul & rmdir /s /q "{APP}"', shell=True,
                             creationflags=0x00000008 | 0x00000200)
        else:
            shutil.rmtree(APP, ignore_errors=True)
        log("ok", f"Removed {APP}")
    log("ok", "Uninstalled. Your POVs are still in ~/.zscaler-pov-kit/povs; to set the kit up again, run the installer.")
