"""Product registry. A new product = a module here plus a catalog file; the core does the rest."""
from .later import ZDX, ZPA, AIGuard, CASB
from .zcc import ZCC
from .zia import ZIA

REGISTRY = {p.name: p for p in (ZIA(), ZCC(), ZPA(), AIGuard(), ZDX(), CASB())}
ORDER = ["zia", "zcc", "zpa", "aiguard", "zdx", "casb"]   # zia first: its pilot group scopes the rest


def get(name):
    return REGISTRY[name]


def selected(names):
    return [REGISTRY[n] for n in ORDER if n in names]
