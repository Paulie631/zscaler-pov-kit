"""Claude, reached through an AI Guard proxy: the use-case assistant's only way to an LLM.

The proxy key is an AI Guard app key in PROXY mode. The kit looks for one in this order:
  1. the one the SE saved for the POV kit (`pov-kit ai connect`, or the console's Use cases tab)
  2. the AI Guard SE Demo Kit's Anthropic app proxy key on this laptop (keychain service 'aiguard-se-kit',
     entry 'SE-Demo: Anthropic App:proxy'), so an SE who set up the demo kit needs nothing more
The SE's Anthropic API key lives in the SE's own AI Guard tenant as a provider credential; it never goes into the
customer's tenant or this kit. AI Guard scans every request and reply, so the assistant itself demos AI Guard.

Nothing goes to Claude until the customer has agreed to share the discovery snapshot (recorded per POV).
"""
from __future__ import annotations

import os
import re
import time

from .core import KitError, secrets

PROXY_HOST = os.getenv("AIGUARD_PROXY", "https://proxy.zseclipse.net").rstrip("/")
DEFAULT_MODEL = "claude-sonnet-5-5"
OWN_KEY = ("_global", "ai-proxy-key")                     # secrets.get(*OWN_KEY)
DEMO_KIT = ("aiguard-se-kit", "SE-Demo: Anthropic App:proxy")


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


def consent(pov):
    return (pov.cfg.get("ai") or {}).get("consent")


def record_consent(pov, by):
    by = (by or "").strip()
    if not by:
        raise KitError("Say who at the customer agreed (name and title).")
    pov.cfg.setdefault("ai", {})["consent"] = {"by": by, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    pov.save()
    pov.log("ai", f"customer agreed to share the discovery snapshot with Claude through AI Guard ({by})")


def post(url, json, headers, timeout):
    import requests
    return requests.post(url, json=json, headers=headers, timeout=timeout)


TRANSPORT = post   # tests swap in a fake


def ask(pov, system, user, max_tokens=4000, timeout=180):
    """One Claude message through the AI Guard proxy. -> reply text."""
    if not consent(pov):
        raise KitError("The customer hasn't agreed to share the discovery snapshot with Claude (through AI Guard) yet. "
                       "Record their agreement in the Use cases tab, or `pov-kit ai consent --by \"Name, title\"`.")
    key, where = proxy_key()
    if not key:
        raise KitError(where)
    model = (pov.cfg.get("ai") or {}).get("model") or DEFAULT_MODEL
    t0 = time.time()
    try:
        r = TRANSPORT(f"{PROXY_HOST}/v1/messages", json={
            "model": model, "max_tokens": max_tokens, "system": system,
            "messages": [{"role": "user", "content": user}],
            "metadata": {"user_id": re.sub(r"[^A-Za-z0-9_-]", "-", f"pov-kit-{pov.id}")}},
            headers={"X-ApiKey": key, "x-api-key": "unused", "anthropic-version": "2023-06-01",
                     "content-type": "application/json"}, timeout=timeout)
    except Exception as e:
        raise KitError(f"Couldn't reach the AI Guard proxy: {e}") from e
    ms = int((time.time() - t0) * 1000)
    text = getattr(r, "text", "") or ""
    if r.status_code >= 400:
        blocked = re.search(r"block|policy|guard|violat", text, re.I)
        pov.log("ai", f"AI Guard proxy: HTTP {r.status_code}", "warn" if blocked else "error", ms=ms)
        if blocked:
            raise KitError("AI Guard blocked the request or the reply (your AI Guard policy is enforcing). Switch your "
                           "demo policy to Monitor, or rephrase the use case.")
        raise KitError(f"The AI Guard proxy answered HTTP {r.status_code}: {text[:200]}".replace(key, "<key>"))
    d = r.json()
    pov.log("ai", f"Claude ({model}) through AI Guard: reply in {ms} ms", "ok", ms=ms)
    return " ".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text").strip()
