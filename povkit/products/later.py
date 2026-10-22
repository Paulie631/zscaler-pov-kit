"""Modules after v1: their criteria (catalog/later.json) and the role scopes they will need, so the role spec and
catalog already cover every product. The scope names are placeholders until confirmed in a lab tenant."""
from .base import NotReady


class ZPA(NotReady):
    name, title, phase = "zpa", "Private Access (ZPA)", "v2"

    def role_scopes(self):
        return {"discovery": [("ZPA", "view only")],
                "apply": [("ZPA: application segments, segment and server groups, access policy, App Connector "
                           "groups and provisioning keys", "full")]}


class AIGuard(NotReady):
    name, title, phase = "aiguard", "AI Guard", "v2"

    def role_scopes(self):
        return {"discovery": [("ZGUARD (AI Guard)", "view only")],
                "apply": [("ZGUARD (AI Guard): policies, apps, keys, rules", "full")]}


class ZDX(NotReady):
    name, title, phase = "zdx", "Digital Experience (ZDX)", "v3"

    def role_scopes(self):
        return {"discovery": [("ZDX", "view only")], "apply": [("ZDX: probes", "full")]}


class CASB(NotReady):
    name, title, phase = "casb", "CASB and SSPM", "v3"

    def role_scopes(self):
        return {"discovery": [("ZIA: SaaS security", "view only")], "apply": []}
