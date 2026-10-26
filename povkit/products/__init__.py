"""Product registry. A new product = a module here plus a catalog file; the core does the rest."""
from .aidraft import DSPM, AIRedTeam, AISPM
from .aiguard import AIGuard
from .casb import CASB
from .eai import EAI
from .readonly import EASM, BusinessInsights, CloudConnector, Microsegmentation
from .zcc import ZCC
from .zdx import ZDX
from .zia import ZIA
from .zid import ZID
from .zpa import ZPA

REGISTRY = {p.name: p for p in (ZID(), ZIA(), ZCC(), ZPA(), AIGuard(), ZDX(), CASB(), EAI(), EASM(),
                                    BusinessInsights(), Microsegmentation(), CloudConnector(), AISPM(), DSPM(), AIRedTeam())}
# zid first: the POV's own pilot group (when it makes one) scopes everything; then zia, whose pilot group scopes zcc
# and casb. zid isn't chosen like the others: the POV adds it when the Pilot users step asks for a new group.
ORDER = ["zid", "zia", "zcc", "zpa", "aiguard", "zdx", "casb", "eai", "aispm", "dspm", "airt", "easm", "zbi", "zms", "ztw"]
CHOOSABLE = [n for n in ORDER if n != "zid"]


def get(name):
    return REGISTRY[name]


def selected(names):
    return [REGISTRY[n] for n in ORDER if n in names]
