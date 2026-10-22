"""Builds dist/zscaler-pov-kit.plugin: the plugin folder plus a copy of the kit inside the skill.

  python tools/build_plugin.py          build
  python tools/build_plugin.py --check  validate the plugin structure only (used in CI)
"""
import json
import pathlib
import re
import shutil
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "plugin" / "zscaler-pov-kit"
SKILL = "zscaler-pov"
KIT_FILES = ["pov-kit", "pov-kit.cmd", "pov_kit.py", "README.md", "SECURITY.md", "CHANGELOG.md", "TESTPLAN.md",
             "pyproject.toml"]
KIT_DIRS = ["povkit", "docs"]


def check():
    manifest = json.loads((SRC / ".claude-plugin" / "plugin.json").read_text())
    assert re.fullmatch(r"[a-z0-9-]+", manifest["name"]), "plugin name must be kebab-case"
    skills = list((SRC / "skills").glob("*/SKILL.md"))
    assert skills, "no skills found"
    for s in skills:
        text = s.read_text()
        assert text.startswith("---\nname: "), f"{s} needs YAML frontmatter"
        assert "\ndescription: " in text.split("\n---", 2)[0] + "\n", f"{s} needs a description"
    kit_version = re.search(r'VERSION = "([^"]+)"', (ROOT / "povkit" / "__init__.py").read_text()).group(1)
    assert manifest["version"] == kit_version, f"plugin {manifest['version']} != kit {kit_version}"
    return manifest


def build():
    manifest = check()
    out = ROOT / "dist"
    stage = out / "stage"
    shutil.rmtree(stage, ignore_errors=True)
    shutil.copytree(SRC, stage)
    kit = stage / "skills" / SKILL / "kit"
    kit.mkdir(parents=True)
    for f in KIT_FILES:
        shutil.copy2(ROOT / f, kit / f)
    for d in KIT_DIRS:
        shutil.copytree(ROOT / d, kit / d, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    target = out / f"{manifest['name']}.plugin"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(stage.rglob("*")):
            if p.is_file():
                info = zipfile.ZipInfo.from_file(p, p.relative_to(stage).as_posix())
                if p.name == "pov-kit":
                    info.external_attr = 0o755 << 16
                z.writestr(info, p.read_bytes(), zipfile.ZIP_DEFLATED)
    shutil.rmtree(stage)
    print(f"built {target}")
    return target


if __name__ == "__main__":
    if "--check" in sys.argv:
        check()
        print("plugin structure ok")
    else:
        build()
