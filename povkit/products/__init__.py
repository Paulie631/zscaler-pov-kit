"""Product registry. A new product = a module here plus a catalog file; the core does the rest."""
from .aiguard import AIGuard
from .casb import CASB
from .zcc import ZCC
from .zdx import ZDX
from .zia import ZIA
from .zpa import ZPA

REGISTRY = {p.name: p for p in (ZIA(), ZCC(), ZPA(), AIGuard(), ZDX(), CASB())}
ORDER = ["zia", "zcc", "zpa", "aiguard", "zdx", "casb"]   # zia first: its pilot group scopes zcc and casb


def get(name):
    return REGISTRY[name]


def selected(names):
    return [REGISTRY[n] for n in ORDER if n in names]
