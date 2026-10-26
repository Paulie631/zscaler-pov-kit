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


# the request never got an answer from Zscaler: this computer's network, not the tenant
NAME_FAILED = re.compile(r"NameResolutionError|Failed to resolve|nodename nor servname|Name or service not known|"
                         r"Temporary failure in name resolution|getaddrinfo failed|No address associated", re.I)
NET_FAILED = re.compile(r"Max retries exceeded|ConnectionError|Connection (?:reset|refused|aborted)|timed out|"
                        r"RemoteDisconnected|ProxyError|SSLError|EOF occurred", re.I)
NET_WAITS = (2, 5)   # seconds before the 2nd and 3rd try


def network_error(e, pov=None):
    """A plain message for a request that never reached Zscaler, or None when it's something else."""
    text = str(e)
    if not (NAME_FAILED.search(text) or NET_FAILED.search(text)):
        return None
    host = (re.search(r"host='([^']+)'", text) or re.search(r"https?://([^/\s:'\"]+)", text) or [None, "Zscaler"])[1]
    if NAME_FAILED.search(text):
        vd = (pov.cfg.get("vanity_domain") if pov else None) or "<vanity>"
        return (f"This computer couldn't look up {host} (a DNS failure), so nothing reached Zscaler and nothing "
                "changed. It's usually brief: a network change, or Wi-Fi, a VPN or Client Connector reconnecting. "
                "Check this computer is online and try again. If it keeps failing, check the vanity domain on "
                f"Setup › Connect: it's the first part of the ZIdentity admin address ({vd}.zslogin.net)"
                + (f", and the cloud ({pov.cfg['cloud']})" if pov and pov.cfg.get("cloud") else "") + ".")
    why = re.search(r"(timed out|Connection (?:reset|refused|aborted)|RemoteDisconnected|ProxyError|SSLError)", text, re.I)
    return (f"Couldn't reach {host}" + (f" ({why[1]})" if why else "") + ", so nothing changed in the tenant. Check "
            "this computer's connection (Wi-Fi, VPN, proxy, Client Connector) and try again. Details are in Logs.")


def _plain(x):
    if isinstance(x, list):
        return [_plain(i) for i in x]
    return x.as_dict() if hasattr(x, "as_dict") else x


def client_slot(pov, which):
    """Which saved client serves a role. Single-client mode (the default): one client, 'main', for both discovery
    and apply. Separate mode: a view-only 'discovery' client and an 'apply' client that exists only from approval to
    handover. Either way the code guard keeps discovery read-only."""
    return "main" if pov.cfg.get("client_mode", "single") == "single" else which


class Tenant:
    def __init__(self, pov, which: str):
        """which: 'discovery' or 'apply'. The client behind it depends on the POV's client mode."""
        from zscaler import ZscalerClient
        slot = client_slot(pov, which)
        cl = (pov.cfg.get("clients") or {}).get(slot) or {}
        secret = secrets.get(pov.id, f"{slot}-client-secret")
        if not (cl.get("client_id") and pov.cfg.get("vanity_domain") and secret):
            how = "`pov-kit connect`" if slot == "main" else f"`pov-kit connect --{slot}`"
            raise KitError(f"No API client saved for this POV ({slot}). Run {how} with the client ID from the role "
                           f"spec (`pov-kit role-spec`), or use the console's Setup tab.")
        conf = {"clientId": cl["client_id"], "clientSecret": secret, "vanityDomain": pov.cfg["vanity_domain"]}
        if pov.cfg.get("cloud"):
            conf["cloud"] = pov.cfg["cloud"]
        if pov.cfg.get("customer_id"):   # ZPA through OneAPI needs the tenant's customer ID
            conf["customerId"] = str(pov.cfg["customer_id"])
        self.pov, self.which = pov, which
        self.c = ZscalerClient(conf)

    def call(self, resource, method, *a, **kw):
        prefix, _, area = resource.partition(".") if "." in resource else ("zia", "", resource)
        svc = getattr(self.c, prefix if prefix in ("zid", "zcc", "zpa", "zdx", "zins", "aiguard", "zwa", "zeasm", "zbi", "zms",
                                                "ztw", "ztb") else "zia")
        api = getattr(svc, area or resource)
        if resource == "zpa.policies" and "conditions" in kw:
            kw = dict(kw, conditions=tuplify(kw["conditions"]))   # the SDK reads rule conditions as tuples
        t0 = time.time()
        from . import recorder
        rec = recorder.enabled(self.pov)
        read = bool(re.match(r"(list|get|search|status|lookup)", method)) or method.endswith("_search")
        for wait in (*NET_WAITS, None):
            try:
                out = getattr(api, method)(*a, **kw)
                break
            except Exception as e:
                # a name that didn't resolve never sent anything, so asking again is safe even for a write;
                # other network errors are retried for reads only
                if wait is not None and (NAME_FAILED.search(str(e)) or (read and NET_FAILED.search(str(e)))):
                    self.pov.log("api", f"{resource}.{method}: network error, trying again in {wait} s", "warn",
                                 error=str(e)[:300])
                    time.sleep(wait)
                    continue
                self.pov.log("api", f"{resource}.{method} failed", "error", error=str(e)[:500])
                if rec:
                    recorder.write(self.pov, resource, method, a, kw, error=e)
                raise KitError(network_error(e, self.pov) or f"{resource}.{method} failed: {e}") from e
        if not (isinstance(out, tuple) and len(out) == 3):
            if rec:
                recorder.write(self.pov, resource, method, a, kw, _plain(out))
            return _plain(out)
        result, resp, err = out
        write = not re.match(r"(list|get|search|status|lookup)", method) and not method.endswith("_search")
        if err or write:
            self.pov.log("api", f"{self.which} {resource}.{method}", "error" if err else "ok",
                         ms=int((time.time() - t0) * 1000), **({"error": str(err)[:500]} if err else {}))
        if err:
            if rec:
                recorder.write(self.pov, resource, method, a, kw, error=err)
            if re.search(r"\b401\b|invalid_client|unauthori", str(err), re.I):
                raise KitError(OAUTH_FAILED)
            raise KitError(network_error(err, self.pov) or f"{resource}.{method} failed: {err}")
        body = resp.get_body() if resp is not None and hasattr(resp, "get_body") else None
        res = body if body is not None else _plain(result)
        if rec:
            recorder.write(self.pov, resource, method, a, kw, res)
        return res


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
