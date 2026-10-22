"""Install, update and roll back, as the demo kit does: verified downloads only, POVs never touched."""
import hashlib
import io
import json
import zipfile

import pytest

from povkit import VERSION, installer, updater
from povkit.core import KitError


@pytest.fixture
def kit(tmp_path, monkeypatch):
    """A fake kit source (not a git checkout), an app folder and a home folder, all under tmp."""
    src = tmp_path / "src"
    (src / "povkit").mkdir(parents=True)
    (src / "povkit" / "__init__.py").write_text(f'VERSION = "{VERSION}"\n')
    for f in ("pov_kit.py", "pov-kit", "pov-kit.cmd", "README.md"):
        (src / f).write_text("x")
    (src / "assets").mkdir()
    (src / "assets" / "pov-icon.icns").write_bytes(b"icns")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(installer, "HERE", src)
    monkeypatch.setattr(installer, "APP", tmp_path / "zpov" / "app")
    monkeypatch.setattr(updater, "CACHE", tmp_path / "zpov" / "update.json")
    monkeypatch.setattr(updater, "BASE", tmp_path / "zpov")
    monkeypatch.setattr(installer.Path, "home", lambda: home)
    monkeypatch.setattr(installer.platform, "system", lambda: "Linux")
    return src, home


def release(version, extra=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("zscaler-pov-kit/pov_kit.py", "x")
        z.writestr("zscaler-pov-kit/pov-kit", "#!/bin/bash\n")
        z.writestr("zscaler-pov-kit/povkit/__init__.py", f'VERSION = "{version}"\n')
        for n, d in (extra or {}).items():
            z.writestr(n, d)
    data = buf.getvalue()
    info = {"version": version, "zip_url": "https://github.com/x/y/releases/download/v/y.zip", "notes": "New things",
            "sha256": hashlib.sha256(data).hexdigest()}

    class R:
        status_code = 200
        content = data

        def json(self):
            return info
    return info, (lambda *a, **k: R())


def test_install_copies_the_kit_and_adds_the_shortcuts(kit):
    src, home = kit
    log = []
    installer.install(lambda lv, m: log.append(m))
    assert (installer.APP / "pov_kit.py").exists() and (installer.APP / "assets" / "pov-icon.icns").exists()
    assert (home / ".local" / "bin" / "pov-kit").exists() and (home / "Desktop" / "Zscaler POV Console.desktop").exists()
    assert oct((installer.APP / "pov-kit").stat().st_mode & 0o777) == "0o755"
    installer.uninstall(lambda lv, m: log.append(m))
    assert not installer.APP.exists() and not (home / ".local" / "bin" / "pov-kit").exists()


def test_update_verifies_installs_and_rolls_back(kit):
    installer.install(lambda *a: None)
    info, get = release("9.9.9")
    st = updater.status(force=True, get=get)
    assert st["available"] and st["latest"] == "9.9.9" and st["notes"] == "New things" and not st["git"]
    assert updater.install(info, get=get) == "9.9.9"
    assert updater.installed_version(installer.APP) == "9.9.9"
    assert updater.status(get=get)["can_rollback"]
    assert updater.rollback() == VERSION
    assert updater.installed_version(installer.APP) == VERSION


def test_update_refuses_bad_downloads(kit):
    info, get = release("9.9.9")
    with pytest.raises(KitError, match="SHA-256"):
        updater.install(dict(info, sha256="0" * 64), get=get)
    with pytest.raises(KitError, match="anywhere but GitHub"):
        updater.install(dict(info, zip_url="https://evil.example/kit.zip"), get=get)
    bad, get2 = release("9.9.9", {"../escape.txt": "x"})
    with pytest.raises(KitError, match="laid out"):
        updater.install(bad, get=get2)
    assert not installer.APP.exists()


def test_a_git_checkout_is_never_overwritten(kit):
    src, _ = kit
    (src / ".git").mkdir()
    info, get = release("9.9.9")
    with pytest.raises(KitError, match="git pull"):
        updater.install(info, get=get)
    assert updater.status(force=True, get=get)["git"]


def test_update_check_is_cached(kit):
    info, get = release("9.9.9")
    updater.fetch_release(force=True, get=get)
    calls = []
    assert updater.fetch_release(get=lambda *a, **k: calls.append(1))["version"] == "9.9.9" and not calls
    assert json.loads(updater.CACHE.read_text())["info"]["version"] == "9.9.9"
