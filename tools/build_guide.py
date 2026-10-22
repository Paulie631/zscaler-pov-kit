"""Build the guides for a release into dist/, stamped with the kit version, as Markdown and Word:

  Zscaler-POV-Kit-SE-Deployment-Guide-<v>.md / .docx    docs/DEPLOYMENT-GUIDE.md
  Zscaler-POV-Kit-Customer-Overview-<v>.md / .docx      docs/CUSTOMER-OVERVIEW.md (for the customer's security team)
  Zscaler-POV-Kit-Quick-Start-<v>.md / .docx            docs/QUICK-START.md (one page for SEs)

Run: python tools/build_guide.py [--require]   (--require: fail if pandoc is missing, as the release workflow does)
     python tools/build_guide.py --check       (CI: the sources exist and each has a title)
The sources in docs/ are the truth: change them in the same branch as the behavior they describe.
"""
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
GUIDES = [("DEPLOYMENT-GUIDE.md", "Zscaler-POV-Kit-SE-Deployment-Guide"),
          ("CUSTOMER-OVERVIEW.md", "Zscaler-POV-Kit-Customer-Overview"),
          ("QUICK-START.md", "Zscaler-POV-Kit-Quick-Start")]


def version():
    return re.search(r'^VERSION = "([^"]+)"', (ROOT / "povkit" / "__init__.py").read_text(encoding="utf-8"), re.M).group(1)


def stamped(text, v):
    """The title, then a line naming the version this copy describes."""
    title, _, rest = text.partition("\n")
    return f"{title}\n\n**Zscaler POV Kit {v}**\n{rest}"


def check():
    for src, _ in GUIDES:
        text = (ROOT / "docs" / src).read_text(encoding="utf-8")
        assert text.startswith("# "), f"docs/{src} needs a '# ' title on its first line"
    print("guides ok")


def build(require=False):
    v = version()
    DIST.mkdir(exist_ok=True)
    pandoc = shutil.which("pandoc")
    if not pandoc and require:
        sys.exit("pandoc not found: install it to build the Word copies")
    out = []
    for src, name in GUIDES:
        text = (ROOT / "docs" / src).read_text(encoding="utf-8")
        md = DIST / f"{name}-{v}.md"
        md.write_text(stamped(text, v), encoding="utf-8")
        out.append(md)
        if pandoc:
            title = text.partition("\n")[0].lstrip("# ").strip()
            docx = md.with_suffix(".docx")
            subprocess.run([pandoc, str(md), "-f", "gfm", "-o", str(docx), "--metadata", f"title={title} ({v})"],
                           check=True)
            out.append(docx)
    if not pandoc:
        print("pandoc not found: built the Markdown copies only")
    for f in out:
        print(f.relative_to(ROOT))
    return out


if __name__ == "__main__":
    if "--check" in sys.argv:
        check()
    else:
        build("--require" in sys.argv)
