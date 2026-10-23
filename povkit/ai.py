"""Claude for the use-case assistant, criteria mapping and the report summary: through an AI Guard proxy when the SE
has one, otherwise straight to Anthropic's API with the SE's own key.

Through AI Guard (preferred): an AI Guard app key in PROXY mode. The kit looks for one in this order:
  1. the one the SE saved for the POV kit (`pov-kit ai connect`, or the console's Use cases tab)
  2. the AI Guard SE Demo Kit's Anthropic app proxy key on this laptop (keychain service 'aiguard-se-kit',
     entry 'SE-Demo: Anthropic App:proxy'), so an SE who set up the demo kit needs nothing more
The SE's Anthropic API key lives in the SE's own AI Guard tenant as a provider credential; it never goes into the
customer's tenant or this kit. AI Guard scans every request and reply, so the assistant itself demos AI Guard.

Directly (for SEs and partners without an AI Guard tenant): the SE's own Anthropic API key, saved in this laptop's
keychain (`pov-kit ai connect --direct`). Same agreement and the same name replacement; no AI Guard scanning. Used
only when there's no AI Guard proxy key.

Nothing goes to Claude until the customer has agreed to share the discovery snapshot (recorded per POV), in one of
two ways (`pov-kit set ai.share`):
  names_only   the default: the customer's names are swapped for placeholders on the laptop (pseudo.py)
  full         the snapshot as discovery read it
An agreement covers the way it was given for, or a narrower one: agreeing to 'full' covers 'names_only', not the
other way round. It also names the route (through AI Guard, or directly to Anthropic): a new route needs a new
agreement, since the data goes a different way.
"""
from __future__ import annotations

import hashlib
import os
import re
import time

from .core import KitError, secrets

PROXY_HOST = os.getenv("AIGUARD_PROXY", "https://proxy.zseclipse.net").rstrip("/")
ANTHROPIC_HOST = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
DEFAULT_MODEL = "claude-sonnet-5-5"
OWN_KEY = ("_global", "ai-proxy-key")                     # secrets.get(*OWN_KEY)
DEMO_KIT = ("aiguard-se-kit", "SE-Demo: Anthropic App:proxy")
DIRECT_KEY = ("_global", "anthropic-api-key")             # the SE's own Anthropic key, for no AI Guard
ROUTES = {"aiguard": "through AI Guard", "direct": "directly to Anthropic (no AI Guard)"}


def proxy_key():
    """-> (key, where it came from) or (None, why not)."""
    k = secrets.get(*OWN_KEY)
    if k:
        return k, "the POV kit's saved AI Guard proxy key"
    try:
        import keyring
        k = keyring.get_password(*DEMO_KIT)
    except Exception:
        k = None
    if k:
        return k, "the AI Guard demo kit's Anthropic app (proxy key) on this computer"
    return None, ("No AI Guard proxy key. Save one with `pov-kit ai connect` (an AI Guard app key in PROXY mode with "
                  "an Anthropic provider key behind it), or set up the AI Guard SE Demo Kit's Anthropic app on this "
                  "computer.")


def direct_key():
    try:
        return secrets.get(*DIRECT_KEY)
    except Exception:
        return None


def route():
    """-> (route 'aiguard'|'direct', key, where it came from), or (None, None, how to set one up)."""
    k, where = proxy_key()
    if k:
        return "aiguard", k, where
    d = direct_key()
    if d:
        return "direct", d, "your Anthropic API key (directly, no AI Guard)"
    return None, None, ("No way to Claude yet. Save an AI Guard app proxy key (`pov-kit ai connect`), or, without an "
                        "AI Guard tenant, your own Anthropic API key (`pov-kit ai connect --direct`).")


def available():
    return route()[0] is not None


def route_name(pov=None):
    return route()[0] or "aiguard"


SHARES = ("names_only", "full")


def share(pov):
    return (pov.cfg.get("ai") or {}).get("share") or "names_only"


def consent(pov):
    """The recorded agreement, if it covers how this POV shares now."""
    c = (pov.cfg.get("ai") or {}).get("consent")
    if not c:
        return None
    given = c.get("share", "full")   # agreements recorded before 0.6 were for the full snapshot
    if c.get("route", "aiguard") != route_name():   # before 0.9.24 every agreement was for AI Guard
        return None
    return c if SHARES.index(given) >= SHARES.index(share(pov)) else None


def record_consent(pov, by):
    by = (by or "").strip()
    if not by:
        raise KitError("Say who at the customer agreed (name and title).")
    how = share(pov)
    via = route_name()
    pov.cfg.setdefault("ai", {})["consent"] = {"by": by, "share": how, "route": via,
                                                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    pov.save()
    what = "the full discovery snapshot" if how == "full" else "the discovery snapshot with their names replaced"
    pov.log("ai", f"customer agreed to share {what} with Claude {ROUTES[via]} ({by})")


def post(url, json, headers, timeout):
    import requests
    return requests.post(url, json=json, headers=headers, timeout=timeout)


TRANSPORT = post   # tests swap in a fake


def ask(pov, system, user, max_tokens=4000, timeout=180, tool=None, needs_consent=True):
    """One Claude message, through the AI Guard proxy or directly to Anthropic (route()). -> reply text, or with
    `tool` (a tool definition Claude must call) -> (the tool's input or None, reply text)."""
    via, key, where = route()
    if needs_consent and not consent(pov):
        raise KitError(f"The customer hasn't agreed to share the discovery snapshot with Claude ({ROUTES[via or 'aiguard']}) "
                       "yet" + (" in full" if share(pov) == "full" else "") + ". Record their agreement in the Use cases "
                       "tab, or `pov-kit ai consent --by \"Name, title\"`.")
    if not key:
        raise KitError(where)
    label = "the AI Guard proxy" if via == "aiguard" else "Anthropic's API"
    model = (pov.cfg.get("ai") or {}).get("model") or DEFAULT_MODEL
    t0 = time.time()
    try:
        body = {"model": model, "max_tokens": max_tokens, "system": system,
                "messages": [{"role": "user", "content": user}],
                "metadata": {"user_id": "pov-kit-" + hashlib.sha256(pov.id.encode()).hexdigest()[:16]}}   # not the slug
        if tool:
            body.update(tools=[tool], tool_choice={"type": "tool", "name": tool["name"]})
        if via == "aiguard":
            url, headers = f"{PROXY_HOST}/v1/messages", {"X-ApiKey": key, "x-api-key": "unused"}
        else:
            url, headers = f"{ANTHROPIC_HOST}/v1/messages", {"x-api-key": key}
        r = TRANSPORT(url, json=body, headers=dict(headers, **{"anthropic-version": "2023-06-01",
                                                                "content-type": "application/json"}), timeout=timeout)
    except Exception as e:
        raise KitError(f"Couldn't reach {label}: {str(e).replace(key, '<key>')}") from e
    ms = int((time.time() - t0) * 1000)
    text = getattr(r, "text", "") or ""
    if r.status_code >= 400:
        blocked = via == "aiguard" and re.search(r"block|policy|guard|violat", text, re.I)
        pov.log("ai", f"{label}: HTTP {r.status_code}", "warn" if blocked else "error", ms=ms)
        if blocked:
            raise KitError("AI Guard blocked the request or the reply (your AI Guard policy is enforcing). Switch your "
                           "demo policy to Monitor, or rephrase the use case.")
        if via == "direct" and r.status_code in (401, 403):
            raise KitError("Anthropic refused the API key (HTTP %d): check it in the Anthropic Console and save it "
                           "again (`pov-kit ai connect --direct`)." % r.status_code)
        raise KitError(f"{label[0].upper() + label[1:]} answered HTTP {r.status_code}: {text[:200]}".replace(key, "<key>"))
    d = r.json()
    pov.log("ai", f"Claude ({model}) {ROUTES[via]}: reply in {ms} ms", "ok", ms=ms)
    text = " ".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text").strip()
    if tool:
        used = next((b.get("input") for b in d.get("content", []) if b.get("type") == "tool_use"
                     and b.get("name") == tool["name"]), None)
        return (used if isinstance(used, dict) else None), text
    return text
