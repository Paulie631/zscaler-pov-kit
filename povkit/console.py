"""Console paths, from console_paths.json (one file to fix when a menu moves)."""
import json
from functools import lru_cache
from pathlib import Path

FILE = Path(__file__).resolve().parent / "console_paths.json"


@lru_cache(maxsize=1)
def paths():
    return json.loads(FILE.read_text(encoding="utf-8"))["paths"]


def path_for(key):
    if not key:
        return ""
    p = paths().get(key)
    if not p:
        return ""
    if p.get("path"):
        return f"Console: {p['path']} ({p['page']})"
    return f"Console: the {p['page']} page (search the console menu for \"{p.get('search') or p['page']}\")"
