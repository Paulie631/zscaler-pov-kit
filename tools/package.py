"""Build the release files into dist/, as the AI Guard SE Demo Kit does:

  zscaler-pov-kit-<v>.zip              the kit with the double-click installers (share via Teams, OneDrive, GitHub)
  zscaler-pov-kit-<v>-email.zip        without .cmd/.command files, so mail filters don't block it
  zscaler-pov-kit-<v>.plugin           the Claude plugin
  zscaler-pov-kit-<v>-email.plugin     the plugin without .cmd files
  zscaler-pov-probe-<v>.zip            the probe for pilot devices: tests and traffic only (install-probe.sh/.ps1)
  SHA256SUMS.txt
  latest.json                          what the kit's update check reads (version, notes, zip link, SHA-256)

Run: python tools/package.py           (uses the committed files at HEAD)
     python tools/package.py --check   (CI: every shipped file exists, the CHANGELOG has this version)
     python tools/package.py --notes   (the release notes for this version, for the release page)
"""
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
TOP = "zscaler-pov-kit/"
SHIP = ["Install Zscaler POV Kit.cmd", "Install Zscaler POV Kit.command", "Uninstall Zscaler POV Kit.cmd",
        "Uninstall Zscaler POV Kit.command", "pov-kit", "pov-kit.cmd", "pov_kit.py", "povkit", "assets", "docs", "plugin",
        "tools/build_plugin.py", "README.md", "INSTALL.md", "SECURITY.md", "TESTPLAN.md", "CHANGELOG.md", "pyproject.toml"]
# the probe package: only what a pilot device runs (no console, no tenant API, no secrets handling)
PROBE_TOP = "zscaler-pov-probe/"
PROBE_SHIP = {"pov-probe": "pov-probe", "pov-probe.cmd": "pov-probe.cmd", "pov_probe.py": "pov_probe.py",
              "docs/PROBE.md": "README.md", "povkit/__init__.py": "povkit/__init__.py", "povkit/device.py": "povkit/device.py",
              "povkit/probe.py": "povkit/probe.py", "povkit/traffic.py": "povkit/traffic.py",
              "povkit/demo.py": "povkit/demo.py", "povkit/runner.py": "povkit/runner.py",
              "povkit/runner.html": "povkit/runner.html",
              "povkit/traffic.json": "povkit/traffic.json", "povkit/zscaler_root_ca.crt": "povkit/zscaler_root_ca.crt"}
EMAIL_BLOCKED = re.compile(r"\.(cmd|command|bat|ps1|exe)$", re.I)
EXECUTABLE = re.compile(r"(^|/)(pov-kit|pov-probe|[^/]+\.command)$")


def version():
    return re.search(r'^VERSION = "([^"]+)"', (ROOT / "povkit" / "__init__.py").read_text(encoding="utf-8"), re.M).group(1)


def changelog_notes(v):
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    m = re.search(rf"^## {re.escape(v)}\b.*?\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    return (m.group(1) if m else "").strip()


def archive():
    data = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=zip", f"--prefix={TOP}", "HEAD", *SHIP],
                          capture_output=True, check=True).stdout
    return zipfile.ZipFile(io.BytesIO(data))


def probe_zip(dest):
    """The probe package from the committed files at HEAD, so it matches the kit's zip exactly."""
    data = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=zip", "HEAD", *PROBE_SHIP],
                          capture_output=True, check=True).stdout
    src = zipfile.ZipFile(io.BytesIO(data))
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as out:
        for info in src.infolist():
            if info.is_dir():
                continue
            new = zipfile.ZipInfo(PROBE_TOP + PROBE_SHIP[info.filename], info.date_time)
            new.compress_type = zipfile.ZIP_DEFLATED
            new.external_attr = (0o100755 << 16) if EXECUTABLE.search(new.filename) else (0o100644 << 16)
            out.writestr(new, src.read(info.filename))


def rezip(src, dest, keep=lambda name: True):
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as out:
        for info in src.infolist():
            if not keep(info.filename):
                continue
            if EXECUTABLE.search(info.filename):   # unzipped on a Mac, the launcher and installers stay runnable
                info.external_attr = (0o100755 << 16)
            out.writestr(info, src.read(info.filename))


def check():
    v = version()
    missing = [f for f in [*SHIP, *PROBE_SHIP, "install-probe.sh", "install-probe.ps1"] if not (ROOT / f).exists()]
    assert not missing, f"missing shipped files: {missing}"
    assert changelog_notes(v), f"CHANGELOG.md has no section for {v}"
    print(f"release files ok for {v}")


def notes():
    v = version()
    return (changelog_notes(v) + "\n\n**Download** `zscaler-pov-kit-" + v + ".zip`, extract it, and double-click the "
            "installer inside (see INSTALL.md); already installed? Use the console's Updates button or `pov-kit update`. "
            "The SE deployment guide, the customer overview and the quick start card for this version are attached as "
            "Word and Markdown. The `-email` files leave out the installers so mail filters accept them.\n")


def main():
    v = version()
    DIST.mkdir(exist_ok=True)
    kit = archive()
    files = [DIST / f"zscaler-pov-kit-{v}.zip", DIST / f"zscaler-pov-kit-{v}-email.zip"]
    rezip(kit, files[0])
    rezip(kit, files[1], lambda n: not EMAIL_BLOCKED.search(n))
    subprocess.run([sys.executable, str(ROOT / "tools" / "build_plugin.py")], check=True, capture_output=True)
    plugin = zipfile.ZipFile(DIST / "zscaler-pov-kit.plugin")
    files += [DIST / f"zscaler-pov-kit-{v}.plugin", DIST / f"zscaler-pov-kit-{v}-email.plugin"]
    rezip(plugin, files[2])
    rezip(plugin, files[3], lambda n: not EMAIL_BLOCKED.search(n))
    probe = DIST / f"zscaler-pov-probe-{v}.zip"
    probe_zip(probe)
    files.append(probe)
    (DIST / "SHA256SUMS.txt").write_text("".join(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}\n"
                                                 for f in files))
    repo = os.getenv("GITHUB_REPOSITORY", "Paulie631/zscaler-pov-kit")
    (DIST / "latest.json").write_text(json.dumps({
        "version": v, "tag": f"v{v}", "notes": changelog_notes(v),
        "zip_url": f"https://github.com/{repo}/releases/download/v{v}/{files[0].name}",
        "sha256": hashlib.sha256(files[0].read_bytes()).hexdigest(),
        "probe_zip_url": f"https://github.com/{repo}/releases/download/v{v}/{probe.name}",
        "probe_sha256": hashlib.sha256(probe.read_bytes()).hexdigest()}, indent=2))
    for f in files + [DIST / "SHA256SUMS.txt", DIST / "latest.json"]:
        print(f.relative_to(ROOT))


if __name__ == "__main__":
    if "--check" in sys.argv:
        check()
    elif "--notes" in sys.argv:
        print(notes())
    else:
        main()
