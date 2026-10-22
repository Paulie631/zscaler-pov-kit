"""The OneAPI connection, through the Zscaler Python SDK. Same call shape as the demo kit's ZiaTenant.call():
resource is a ZIA SDK area ('url_filtering'), ZIdentity ('zid.users'), Client Connector ('zcc.web_policy'),
ZPA ('zpa.application_segment') or Insights ('zins.web_traffic'). Product modules only ever see this wrapped
in a guard (core/guard.py)."""
from __future__ import annotations

import json
import re
import time

from .core import KitError, secrets

OAUTH_FAILED = ("Zscaler rejected the API client's sign-in (401). Check the client ID and secret, the vanity domain, "
                "and that the client hasn't been deleted or its secret rotated.")


def _plain(x):
    if isinstance(x, list):
        return [_plain(i) for i in x]
    return x.as_dict() if hasattr(x, "as_dict") else x


class Tenant:
    def __init__(self, pov, which: str):
        """which: 'discovery' or 'apply' (the two API clients in pov.json, secrets in the keychain)."""
        from zscaler import ZscalerClient
        cl = (pov.cfg.get("clients") or {}).get(which) or {}
        secret = secrets.get(pov.id, f"{which}-client-secret")
        if not (cl.get("client_id") and pov.cfg.get("vanity_domain") and secret):
            raise KitError(f"No {which} API client saved for this POV. Run `pov-kit connect --{which}` with the "
                           f"client ID from the role spec (`pov-kit role-spec`).")
        conf = {"clientId": cl["client_id"], "clientSecret": secret, "vanityDomain": pov.cfg["vanity_domain"]}
        if pov.cfg.get("cloud"):
            conf["cloud"] = pov.cfg["cloud"]
        self.pov, self.which = pov, which
        self.c = ZscalerClient(conf)

    def call(self, resource, method, *a, **kw):
        prefix, _, area = resource.partition(".") if "." in resource else ("zia", "", resource)
        svc = getattr(self.c, prefix if prefix in ("zid", "zcc", "zpa", "zdx", "zins", "aiguard") else "zia")
        api = getattr(svc, area or resource)
        if resource == "zpa.policies" and "conditions" in kw:
            kw = dict(kw, conditions=tuplify(kw["conditions"]))   # the SDK reads rule conditions as tuples
        t0 = time.time()
        try:
            out = getattr(api, method)(*a, **kw)
        except Exception as e:
            self.pov.log("api", f"{resource}.{method} failed", "error", error=str(e)[:500])
            raise KitError(f"{resource}.{method} failed: {e}") from e
        if not (isinstance(out, tuple) and len(out) == 3):
            return _plain(out)
        result, resp, err = out
        write = not re.match(r"(list|get|search|status)", method)
        if err or write:
            self.pov.log("api", f"{self.which} {resource}.{method}", "error" if err else "ok",
                         ms=int((time.time() - t0) * 1000), **({"error": str(err)[:500]} if err else {}))
        if err:
            if re.search(r"\b401\b|invalid_client|unauthori", str(err), re.I):
                raise KitError(OAUTH_FAILED)
            raise KitError(f"{resource}.{method} failed: {err}")
        body = resp.get_body() if resp is not None and hasattr(resp, "get_body") else None
        return body if body is not None else _plain(result)


def tuplify(conditions):
    """JSON has no tuples, so the change list stores ZPA rule conditions as lists. The SDK wants a list of tuples:
    ("app", ["id"]) and ("scim_group", [("idp id", "group id")]), as in its add_access_rule_v2 examples."""
    out = []
    for c in conditions:
        kind, value = c[0], c[1]
        if isinstance(value, list) and value and isinstance(value[0], list):
            value = [tuple(v) for v in value]
        out.append((kind, value))
    return out


def items(body):
    if isinstance(body, list):
        return body
    return next((v for v in (body or {}).values() if isinstance(v, list)), [])


def g(o, key, default=None):
    """Read a field whether the record is camelCase (raw API) or snake_case (SDK models). From the demo kit."""
    if not isinstance(o, dict):
        return default
    if key in o:
        return o[key]
    camel = re.sub(r"_([a-z])", lambda m: m.group(1).upper(), key)
    return o.get(camel, default)


def dump(o) -> str:
    return json.dumps(o, default=str)[:300]
