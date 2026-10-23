"""POV settings, validated in one place for the CLI (`pov-kit set`) and the console."""
from __future__ import annotations

from . import products
from .core import KitError

SETTABLE = {"vanity_domain", "cloud", "client_mode", "pilot_group", "pilot_emails", "placement", "criteria", "products",
            "zpa.app_name", "zpa.domains", "zpa.tcp_ports", "zpa.group", "zpa.location", "zpa.latitude", "zpa.longitude",
            "zpa.scope", "zpa.saml_attribute", "zpa.saml_value", "zdx.app", "casb.tenant", "aiguard.competitor",
            "identity.idp", "identity.bypass_domains", "identity.test_users", "identity.test_domain",
            "identity.pilot", "identity.create_users", "identity.users_in", "ai.model", "ai.share", "ends", "lab",
            "customer_id", "mcp.version", "zcc.cloud", "aiguard.proxy", "aiguard.provider",
            "aiguard.provider_credential", "aiguard.model", "prefix", "manual.mode"}
LISTS = {"criteria", "pilot_emails", "products", "zpa.domains", "zpa.tcp_ports", "identity.bypass_domains"}
CHOICES = {"lab": ("yes", "no"), "manual.mode": ("live", "async"),
           "aiguard.proxy": ("none", "customer", "se"), "aiguard.provider": ("anthropic", "openai"),
           "identity.pilot": ("existing", "create", "test"),
           "identity.users_in": ("auto", "zia", "zidentity"), "identity.create_users": ("yes", "no"), "ai.share": ("full", "names_only"),
           "placement": ("top", "bottom"), "client_mode": ("single", "separate"), "zpa.scope": ("scim", "saml")}


def parse(key, raw):
    if key not in SETTABLE:
        raise KitError(f"Settable: {', '.join(sorted(SETTABLE))}.")
    v = raw
    if key in LISTS:
        v = raw if isinstance(raw, list) else [x.strip() for x in str(raw).split(",") if x.strip()]
        v = [str(x).strip() for x in v if str(x).strip()]
    elif raw is None:
        return None
    else:
        v = str(raw).strip()
    if key in CHOICES and v not in CHOICES[key]:
        raise KitError(f"{key} is one of: {', '.join(CHOICES[key])}.")
    if key == "identity.test_users":
        if not str(v).isdigit() or int(v) > 10:
            raise KitError("identity.test_users is a number from 0 to 10.")
        v = int(v)
    if key == "products":
        bad = [x for x in v if x not in products.CHOOSABLE]
        if bad:
            raise KitError(f"Unknown product(s): {', '.join(bad)}. Choose from {', '.join(products.CHOOSABLE)}.")
        if not v:
            raise KitError("Choose at least one product.")
    if key == "ends":
        from .remind import parse_date
        v = parse_date(v)
    if key == "zcc.cloud" and v and not __import__("re").fullmatch(r"[a-z0-9]+", v):
        raise KitError("zcc.cloud is the Zscaler cloud's name, such as zscalertwo or zscaler.")
    if key == "prefix" and not __import__("re").fullmatch(r"[A-Za-z][A-Za-z0-9-]{1,11}", v or ""):
        raise KitError("The prefix is 2 to 12 letters, digits or dashes, starting with a letter.")
    if key == "pilot_emails":
        bad = [x for x in v if "@" not in x]
        if bad:
            raise KitError(f"Not email addresses: {', '.join(bad)}.")
    return v


def set_value(pov, key, raw, save=True):
    v = parse(key, raw)
    if key == "identity.pilot" and v != (pov.cfg.get("identity") or {}).get("pilot", "existing"):
        from .core.ledger import Ledger
        if Ledger(pov.path("ledger.json"), pov.id, pov.prefix).active("zid"):
            raise KitError("The POV's ZIdentity pilot group is in the tenant, so the pilot group can't change now. "
                           "Remove the POV first (Handover), or keep this group.")
    if key == "prefix" and v != pov.prefix:
        from .core.ledger import Ledger
        if Ledger(pov.path("ledger.json"), pov.id, pov.prefix).active():
            raise KitError("This POV has objects in the tenant under its prefix, so it can't change now. Remove the "
                           "POV first (Handover), or keep the prefix.")
        from .core import pov as povs
        if v in povs.prefixes_in_use(exclude=pov.id):
            raise KitError(f"Another POV on this laptop uses '{v}' in a tenant. Pick another, such as "
                           f"{povs.free_prefix(v, exclude=pov.id)}.")
    if "." in key:
        sect, field = key.split(".", 1)
        pov.cfg.setdefault(sect, {})[field] = v
    else:
        pov.cfg[key] = v
    if save:
        pov.save()
    return v


def get_value(pov, key):
    if "." in key:
        sect, field = key.split(".", 1)
        return (pov.cfg.get(sect) or {}).get(field)
    return pov.cfg.get(key)


def snapshot(pov):
    return {k: get_value(pov, k) for k in sorted(SETTABLE)}
