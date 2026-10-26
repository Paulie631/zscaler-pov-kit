"""AI Guard: the demo kit's detection policy, applied to one POV app only, with automated API proofs.

Creates a detection policy (the demo kit's template, every detector on, starting in Monitor), a POV app, a
DETECTIONS-mode key for it (the key's secret goes to the keychain) and a rule that sends only that app to the POV
policy. AI Guard rules match by app, so the customer's own apps and rules are untouched. Blocking profiles
(`pov-kit aiguard policy monitor|attacks|data`) change only the POV's own policy.

The API proofs scan test prompts through the Detection API with the POV's key, as the demo kit's tests do; they need
no LLM and send no customer data. Ported from aiguard_kit.py (apps, keys, rules, profiles, das_scan).
"""
from __future__ import annotations

import copy
import json
import os
import re
import time
import uuid
from pathlib import Path

from ..core import GuardError, KitError, naming, secrets
from ..core.changelist import item
from ..core.checks import FAIL, OK, WARN, check
from ..core.ledger import Ledger
from ..tenant import items
from .base import Product

HERE = Path(__file__).resolve().parent
DAS_HOST = os.getenv("AIGUARD_DAS_HOST", "https://api.us1.zseclipse.net").rstrip("/")
DAS_PATH = "/v1/detection/resolve-and-execute-policy"
KEY_SECRET = "aiguard-detection-key"
KINDS = {
    "policy": dict(res="aiguard.policies", get="get_policy", dele="delete_policy", lst="list_policies", title="Policy"),
    "app": dict(res="aiguard.llm_applications", get="get_application", dele="delete_application",
                lst="list_applications", title="App"),
    "key": dict(res="aiguard.llm_application_credentials", get="get_credential", dele="delete_credential",
                lst="list_credentials", title="App key"),
    "rule": dict(res="aiguard.policy_match_rules", get="get_rule", dele="delete_rule", lst="list_rules", title="Rule"),
    "provider_credential": dict(res="aiguard.llm_provider_credentials", get="get_credential", dele="delete_credential",
                                lst="list_credentials", title="Provider key"),
}
# Proxy mode (real prompts to the customer's model through AI Guard): the provider types the kit can drive, with how
# AI Guard stores their key and a small default model. From the demo kit.
PROVIDERS = {"anthropic": ("API_KEY", "key", "claude-haiku-5-5"), "openai": ("BEARER", "token", "gpt-4o-mini")}
PROVIDER_SECRET = "aiguard-provider-key"   # the SE's own provider key (proxy mode 'se'), in the keychain only
SECRET_REF = "{secret:" + PROVIDER_SECRET + "}"   # in the change list instead of the key itself

# Blocking profiles, from the demo kit
REGULATED_PII = {"CREDIT_CARD", "US_SSN", "US_BANK_NUMBER", "IBAN_CODE", "SWIFT_CODE", "US_PASSPORT", "US_ITIN"}
NEVER_BLOCK = {"language", "prompt_tags", "response_tags", "refusal", "url_reachability"}
ATTACKS = {"inputDetectorPolicies": {"prompt_injection", "invisible_text", "toxicity"},
           "outputDetectorPolicies": {"malicious_url", "toxicity"}}
SIDES = ("inputDetectorPolicies", "outputDetectorPolicies")
PROFILES = {"monitor": "Monitor: detect and log everything, block nothing",
            "attacks": "Block attacks: prompt injection, hidden text, toxicity, malicious URLs",
            "data": "Block attacks + data leakage: also secrets and regulated PII",
            "everything": "Block everything risky: every detector except topic and language classification"}
SIDE_NAME = {"inputDetectorPolicies": "prompt", "outputDetectorPolicies": "response"}

# Test prompts for the API proofs, from the demo kit's tests.json. '{_}' is removed at run time; it splits fake keys
# so secret scanning doesn't flag the repository.
TESTS = json.loads((HERE / "aiguard_tests.json").read_text(encoding="utf-8"))
PACKS = {"AI-AIG-P1": "financial-services", "AI-AIG-P2": "healthcare", "AI-AIG-P3": "legal"}
# Detectors that mean "something harmful": an everyday prompt (expect []) must trigger none of them. Topic, language
# and code tags describe a prompt rather than flag it.
HARMFUL = {"prompt_injection", "secrets", "pii", "pii_deepscan", "personal_data", "toxicity", "gibberish",
           "invisible_text", "malicious_url", "brand_and_reputation_risk", "finance_advice", "legal_advice",
           "competition"}


def proof_tests(cid):
    if cid in PACKS:
        return TESTS["packs"][PACKS[cid]]["tests"]
    return TESTS["criteria"].get(cid)


PROOF_TESTS = {cid: proof_tests(cid) for cid in list(TESTS["criteria"]) + list(PACKS)}
AIG_CRITERIA = list(TESTS["criteria"])
BASELINE = "Give me three tips for a strong password policy."


def ledger_of(pov):
    return Ledger(pov.path("ledger.json"), pov.id, pov.prefix)


def template(competitor="Competitor Inc"):
    text = (HERE / "aiguard_policy_template.json").read_text(encoding="utf-8").replace("{COMPETITOR}", competitor)
    return json.loads(text)


def _set_action(det, action, only=None):
    cfg = det.get("configuration")
    if not isinstance(cfg, dict):
        return
    if "action" in cfg:
        cfg["action"] = action
    for key in ("entities", "secretTypes", "languages", "tags", "competitors"):
        for it in cfg.get(key, []) or []:
            if it.get("action") == "DISABLE":
                continue
            kind = it.get("entityType") or it.get("secretType")
            it["action"] = action if only is None or kind in only else "DETECT"
    if "defaultAction" in cfg:   # the API rejects defaultAction BLOCK (the demo kit tested this)
        cfg["defaultAction"] = "DETECT"
    det["severity"] = "HIGH" if action == "BLOCK" else "LOW"


def template_detectors():
    tpl = template()
    return {side: [d["detector"] for d in tpl.get(side, []) if d.get("enabled")] for side in SIDES}


def profile_blocks(profile):
    """{side: {detector: entity filter or None}} that a named profile blocks (the demo kit's profiles)."""
    out = {side: {} for side in SIDES}
    if profile in ("attacks", "data"):
        for side in SIDES:
            out[side].update({d: None for d in ATTACKS[side]})
    if profile == "data":
        for side in SIDES:
            out[side].update({"secrets": None, "pii": REGULATED_PII})
    if profile == "everything":
        names = template_detectors()
        for side in SIDES:
            out[side].update({d: None for d in names[side] if d not in NEVER_BLOCK})
    return out


def apply_profile(body, profile):
    """profile: a name in PROFILES, or a custom one: {"prompt": [detectors], "response": [detectors],
    "pii_regulated_only": True} (Block for those, Detect for the rest)."""
    if isinstance(profile, dict):
        blocks = {side: {d: (REGULATED_PII if d == "pii" and profile.get("pii_regulated_only", True) else None)
                         for d in profile.get(SIDE_NAME[side]) or [] if d not in NEVER_BLOCK} for side in SIDES}
    else:
        blocks = profile_blocks(profile)
    for side in SIDES:
        for d in body.get(side, []):
            if d.get("enabled") and d.get("detector") not in NEVER_BLOCK:
                name = d.get("detector")
                _set_action(d, "BLOCK", blocks[side][name]) if name in blocks[side] else _set_action(d, "DETECT")
    return body


def blocked_map(body):
    """{"prompt": [...], "response": [...]}: detectors with anything set to Block."""
    def blocking(d):
        cfg = d.get("configuration") or {}
        return cfg.get("action") == "BLOCK" or any(
            i.get("action") == "BLOCK" for k in ("entities", "secretTypes", "languages", "tags", "competitors")
            for i in cfg.get(k, []) or [])
    return {SIDE_NAME[side]: sorted(d["detector"] for d in body.get(side, []) if d.get("enabled") and blocking(d))
            for side in SIDES}


def current_profile(body):
    have = blocked_map(body)
    for name in PROFILES:
        want = profile_blocks(name)
        if all(sorted(want[side]) == have[SIDE_NAME[side]] for side in SIDES):
            return name
    return "custom"


# Each provider gets its own proxy key and rule (and, with the SE's key, its own provider key object). Anthropic keeps
# the names POVs had before both were offered, so POVs already applied don't drift.
PKEYS = {"anthropic": ("aiguard.proxy_key", "aiguard.proxy_rule", "aiguard.provider_cred", ""),
         "openai": ("aiguard.proxy_key_openai", "aiguard.proxy_rule_openai", "aiguard.provider_cred_openai", " (OpenAI)")}
LABEL = {"anthropic": "Anthropic", "openai": "OpenAI"}


def provider_secret(ptype):
    """Keychain name of the SE's own model key for a provider."""
    return PROVIDER_SECRET if ptype == "anthropic" else f"{PROVIDER_SECRET}-{ptype}"


def proxy_setup(pov):
    """-> {provider: {"use": "customer"|"se"|"off", "cred": their key's id or None, "model": str}}. POVs set up before
    both providers were offered keep their one provider."""
    ag = pov.cfg.get("aiguard") or {}
    out = {pt: {"use": "off", "cred": None, "model": PROVIDERS[pt][2]} for pt in PROVIDERS}
    if isinstance(ag.get("providers"), dict):
        for pt, v in ag["providers"].items():
            if pt in out and isinstance(v, dict):
                use = v.get("use") if v.get("use") in ("customer", "se", "off") else "off"
                out[pt].update(use=use, cred=v.get("cred"), model=(v.get("model") or PROVIDERS[pt][2]).strip())
        return out
    if (ag.get("proxy") or "none") != "none":
        pt = ag.get("provider") if ag.get("provider") in PROVIDERS else "anthropic"
        out[pt].update(use=ag["proxy"], cred=ag.get("provider_credential"), model=ag.get("model") or PROVIDERS[pt][2])
    return out


def proxy_cfg(pov):
    """-> (mode 'none'|'customer'|'se', provider type, model) of the first provider in use (for older callers)."""
    for pt, v in proxy_setup(pov).items():
        if v["use"] != "off":
            return v["use"], pt, v["model"]
    return "none", "anthropic", PROVIDERS["anthropic"][2]


def das_scan(key, text, direction="IN", timeout=60, user="pov-kit-proof"):
    import requests
    body = {"content": text, "direction": direction, "transactionId": str(uuid.uuid4()), "user": user}
    r = requests.post(DAS_HOST + DAS_PATH, json=body, timeout=timeout,
                      headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    if r.status_code >= 400:
        raise KitError(f"Detection API HTTP {r.status_code}: {r.text[:200]}".replace(key, "<key>"))
    return r.json()


PROXY_HOST = os.getenv("AIGUARD_PROXY", "https://proxy.zseclipse.net").rstrip("/")


def proxy_chat(ptype, key, model, prompt, user=None, max_tokens=300, timeout=90):
    """A real prompt to the customer's model through AI Guard's proxy (from the demo kit). -> (reply, ms, blocked).
    AI Guard answers a blocked prompt or reply with an HTTP error; that's blocked=True with its message."""
    import requests
    t0 = time.time()
    if ptype == "anthropic":
        r = requests.post(f"{PROXY_HOST}/v1/messages", timeout=timeout, json={
            "model": model, "max_tokens": max_tokens, "messages": [{"role": "user", "content": prompt}],
            **({"metadata": {"user_id": re.sub(r"[^A-Za-z0-9_-]", "-", user)}} if user else {})},
            headers={"X-ApiKey": key, "x-api-key": "unused", "anthropic-version": "2023-06-01",
                     "content-type": "application/json"})
    else:
        r = requests.post(f"{PROXY_HOST}/v1/chat/completions", timeout=timeout, json={
            "model": model, "max_tokens": max_tokens, "messages": [{"role": "user", "content": prompt}],
            **({"user": user} if user else {})},
            headers={"X-ApiKey": key, "Authorization": "Bearer unused", "content-type": "application/json"})
    ms = int((time.time() - t0) * 1000)
    if r.status_code >= 400:
        text = (r.text or "")[:600].replace(key, "<key>")
        if re.search(r"block|policy|guard|violat", text, re.I):
            return text, ms, True
        raise KitError(f"The AI Guard proxy answered HTTP {r.status_code}: {text[:300]}")
    d = r.json()
    if ptype == "anthropic":
        reply = " ".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
    else:
        reply = ((d.get("choices") or [{}])[0].get("message") or {}).get("content", "")
    return reply.strip(), ms, False


def hits(d):
    dets = d.get("detectorResponses") or {}
    return sorted(k for k, v in dets.items() if isinstance(v, dict) and v.get("triggered"))


class AIGuard(Product):
    name, title, phase = "aiguard", "AI Guard", "v2"

    def role_scopes(self, pov=None):
        return {"discovery": [("ZGUARD (AI Guard)", "view only")],
                "apply": [("ZGUARD (AI Guard): policies, apps, app keys, rules"
                           + (", provider keys (proxy mode with the SE's key)"
                              if pov and any(v["use"] == "se" for v in proxy_setup(pov).values()) else ""), "full")]}

    def _names(self, P):
        return {"policy": naming.name(P, "AI Guard POV", 60), "app": naming.name(P, "POV app", 60),
                "key": naming.name(P, "POV detection key", 60), "rule": naming.name(P, "POV app rule", 60),
                "proxy_key": naming.name(P, "POV proxy key", 60), "proxy_rule": naming.name(P, "POV proxy rule", 60),
                "provider_cred": naming.name(P, "POV provider key", 60),
                "proxy_key_openai": naming.name(P, "POV proxy key (OpenAI)", 60),
                "proxy_rule_openai": naming.name(P, "POV proxy rule (OpenAI)", 60),
                "provider_cred_openai": naming.name(P, "POV provider key (OpenAI)", 60)}

    def discover(self, t, pov):
        from .. import usecases
        checks, snap = [], {"customer_names": [], "taken": []}
        names, ledger = self._names(pov.prefix), ledger_of(pov)
        planned = set(names.values()) | usecases.planned_names(pov, "aiguard")
        try:
            rows = {k: items(t.call(v["res"], v["lst"])) for k, v in KINDS.items()}
        except KitError as e:
            return {"readable": False}, [check("aiguard-read", "AI Guard readable", FAIL, str(e)[:160],
                                               "Give the discovery client view access to ZGUARD (AI Guard).")]
        snap["readable"] = True
        for kind, rs in rows.items():
            for o in rs:
                n = str(o.get("name") or "")
                mine = ledger.by_id("aiguard", kind, o.get("id")) is not None
                if not naming.has_prefix(n, pov.prefix):
                    snap["customer_names"].append(n)
                elif n in planned and not mine:
                    snap["taken"].append(f"'{n}' ({KINDS[kind]['title']})")
        # proxy mode: what each provider has in the customer's AI Guard, and what the POV uses (read every time, so
        # the console can show both providers even before proxy mode is on)
        setup = proxy_setup(pov)
        provs, readable = [], True
        try:
            provs = [{"id": o.get("id"), "name": o.get("name"), "type": str(o.get("type") or "").lower()}
                     for o in items(t.call("aiguard.llm_providers", "list_providers"))]
        except KitError as e:
            readable = False
            if any(v["use"] != "off" for v in setup.values()):
                checks.append(check("aiguard-proxy", "Proxy mode", WARN, f"providers unreadable: {str(e)[:120]}"))
        snap["proxy"] = {"readable": readable, "providers": {}}
        for pt, v in setup.items():
            # a tenant can have several providers of one type (an OpenAI one and an OpenAI-compatible DeepSeek one):
            # every key of that type is offered, each with its provider, and the provider follows the chosen key
            same = [x for x in provs if x["type"] == pt]
            by_id = {str(x["id"]): x for x in same}
            pcreds = [{"id": o.get("id"), "name": o.get("name"), "provider": by_id[str(o.get("providerId"))]["name"],
                       "provider_id": o.get("providerId")}
                      for o in rows["provider_credential"]
                      if str(o.get("providerId")) in by_id and not naming.has_prefix(o.get("name"), pov.prefix)]
            word = LABEL[pt].lower()
            def native(name, word=word):   # 'Default OpenAI Provider' before 'DeepSeek (OpenAI-compatible)'
                n = str(name).lower()
                return word in n and not re.search(r"compatible|deepseek|azure|bedrock|vertex|groq|mistral", n)
            pcreds.sort(key=lambda c: (not native(c["provider"]), str(c["name"])))
            chosen = next((c for c in pcreds if str(c["id"]) == str(v["cred"])), None) or (
                pcreds[0] if len(pcreds) == 1 and not v["cred"] and v["use"] == "customer" else None)
            prov = (by_id.get(str(chosen["provider_id"])) if chosen else None) or next(
                (x for x in same if native(x["name"])), None) or (same[0] if same else None)
            have = bool(secrets.get(pov.id, provider_secret(pt)))
            snap["proxy"]["providers"][pt] = {"provider": prov, "creds": pcreds, "use": v["use"], "model": v["model"],
                                              "cred": chosen if v["use"] == "customer" else None, "se_key": have}
            label = LABEL[pt]
            if v["use"] == "off" or not readable:
                continue
            if not prov:
                checks.append(check(f"aiguard-proxy-{pt}", f"Proxy mode: {label}", WARN,
                                    f"no {label} provider in this AI Guard tenant",
                                    f"The customer adds an {label} provider in AI Guard (or turn {label} off in AI Guard "
                                    "→ Setup); until then its tests run through the Detection API only."))
            elif v["use"] == "customer":
                checks.append(check(f"aiguard-proxy-{pt}", f"Proxy mode: {label}, the customer's key",
                                    OK if chosen else WARN,
                                    f"'{chosen['name']}'" if chosen else
                                    (f"choose one of: {', '.join(c['name'] for c in pcreds)}" if pcreds else
                                     f"no {label} key in their AI Guard yet"),
                                    "" if chosen else f"AI Guard → Setup: pick the customer's {label} key, or have their "
                                    f"admin add one to AI Guard (or use your own key)."))
            else:
                checks.append(check(f"aiguard-proxy-{pt}", f"Proxy mode: {label}, your own key", OK if have else WARN,
                                    "in this computer's keychain" if have else "not entered yet",
                                    "" if have else f"AI Guard → Setup: enter your {label} key (it goes to the keychain, "
                                    "and the change list adds it to the customer's AI Guard as a POV object)."))
        snap["rule_orders"] = sorted(int(r.get("ruleOrder") or 0) for r in rows["rule"]
                                     if not naming.has_prefix(r.get("name"), pov.prefix))
        # the detectors the POV's policies can switch to block, for use cases
        tpl = template()
        snap["detectors"] = {side: sorted(d["detector"] for d in tpl.get(key, [])
                                          if d.get("enabled") and d.get("detector") not in NEVER_BLOCK)
                             for side, key in (("prompts", SIDES[0]), ("responses", SIDES[1]))}
        snap["detectors"]["all"] = sorted({d["detector"] for key in SIDES for d in tpl.get(key, [])})
        checks.append(check("aiguard-names", "POV names are free", FAIL if snap["taken"] else OK,
                            ", ".join(snap["taken"]) or f"{len(planned)} names checked",
                            "Start the POV with a different prefix." if snap["taken"] else ""))
        checks.append(check("aiguard-tenant", "AI Guard readable", OK,
                            f"{len(rows['policy'])} policies, {len(rows['app'])} apps, {len(rows['rule'])} rules"))
        return snap, checks

    def plan(self, pov, snap):
        if not snap.get("readable"):
            return [], ["No AI Guard items: AI Guard wasn't readable in discovery."]
        pid, n = pov.id, self._names(pov.prefix)
        pol = template((pov.cfg.get("aiguard") or {}).get("competitor", "Competitor Inc"))
        pol = apply_profile(pol, "monitor")
        pol.update(name=n["policy"], description=naming.describe(pid, "AI Guard POV policy, every detector on"))
        order = (snap.get("rule_orders") or [0])[-1] + 1
        affects = "only traffic sent with the POV app's key"
        from .. import usecases   # each accepted use case gets its own policy, app, key and rule
        proxy = self._proxy_items(pov, snap, n, order + 1, affects)
        uc_items, _ = usecases.aiguard_items(pov, snap, order + 1 + sum(1 for i in proxy if i["kind"] == "rule"))
        return [
            item("aiguard", "policy", "aiguard.policy", n["policy"], criteria=AIG_CRITERIA, affects=affects,
                 why=f"Every detector on ({len(pol['inputDetectorPolicies'])} for prompts, "
                     f"{len(pol['outputDetectorPolicies'])} for responses), starting in Monitor.", body=pol),
            item("aiguard", "app", "aiguard.app", n["app"], affects=affects, criteria=AIG_CRITERIA,
                 body={"name": n["app"], "applicationSettings": {"includeEventContents": True,
                                                                 "encryptEventContents": False}}),
            item("aiguard", "key", "aiguard.key", n["key"], affects=affects,
                 why="A Detection API key for the POV app; its secret goes to the SE's keychain.",
                 body={"name": n["key"], "applicationId": "{ref:aiguard.app}", "mode": "DETECTIONS"}),
            item("aiguard", "rule", "aiguard.rule", n["rule"], affects=affects, placement="bottom",
                 why="Matches the POV app only, placed after the customer's rules.",
                 body={"name": n["rule"], "policyId": "{ref:aiguard.policy}", "enabled": True, "ruleOrder": order,
                       "matchCriteria": {"type": "DAS_APPLICATION", "llmApplications": [
                           {"applicationId": "{ref:aiguard.app}", "applicationCredentialsIds": ["{ref:aiguard.key}"]}]}}),
        ] + proxy + uc_items, [f"Starts in Monitor. Switch with `pov-kit aiguard policy {'|'.join(PROFILES)}`; only the POV policy changes."]

    def _proxy_items(self, pov, snap, n, order, affects):
        """Proxy mode, per provider in use: a PROXY key for the POV app (with the customer's model key, or the SE's
        added as a POV object) and a rule sending that key's traffic to the POV policy."""
        out, idx = [], 0
        for pt, px in ((snap.get("proxy") or {}).get("providers") or {}).items():
            if px["use"] == "off" or not px.get("provider") or (px["use"] == "customer" and not px.get("cred")) or \
                    (px["use"] == "se" and not px.get("se_key")):
                continue
            kkey, rkey, ckey, sfx = PKEYS[pt]
            nm = {"key": n["proxy_key" + ("_openai" if pt == "openai" else "")],
                  "rule": n["proxy_rule" + ("_openai" if pt == "openai" else "")],
                  "cred": n["provider_cred" + ("_openai" if pt == "openai" else "")]}
            ctype, field, _ = PROVIDERS[pt]
            if px["use"] == "se":
                out.append(item("aiguard", "provider_credential", ckey, nm["cred"], affects=affects,
                                why=("Your own model key, so the POV can send real prompts; removed at teardown."
                                     if pt == "anthropic" else   # unchanged wording: an approved change list stays approved
                                     f"Your own {LABEL[pt]} key, so the POV can send real prompts; removed at teardown."),
                                body={"name": nm["cred"], "providerId": px["provider"]["id"],
                                      "apiCredentials": {"type": ctype, field: "{secret:" + provider_secret(pt) + "}"}}))
                cred = "{ref:" + ckey + "}"
            else:
                cred = px["cred"]["id"]
            out += [
                item("aiguard", "key", kkey, nm["key"], affects=affects,
                     why=f"A proxy key for the POV app on the {'customer' if px['use'] == 'customer' else 'SE'}'s "
                         f"{pt if pt == 'anthropic' else LABEL[pt]} key: real prompts to {px['model']} through AI Guard. "
                         "Its secret goes to the keychain.",
                     body={"name": nm["key"], "applicationId": "{ref:aiguard.app}", "mode": "PROXY",
                           "providerId": px["provider"]["id"], "providerCredentialsId": cred}),
                item("aiguard", "rule", rkey, nm["rule"], affects=affects, placement="bottom",
                     why=("Sends the POV's proxy traffic to the POV policy, after the customer's rules." if pt == "anthropic"
                          else f"Sends the POV's {LABEL[pt]} proxy traffic to the POV policy, after the customer's rules."),
                     body={"name": nm["rule"], "policyId": "{ref:aiguard.policy}", "enabled": True,
                           "ruleOrder": order + idx,
                           "matchCriteria": {"type": "APPLICATION", "llmApplications": [
                               {"applicationId": "{ref:aiguard.app}",
                                "applicationCredentialsIds": ["{ref:" + kkey + "}"]}]}})]
            idx += 1
        return out

    def apply(self, t, pov, items_, log):
        from ..usecases import aiguard_secret
        verbs = {"policy": "add_policy", "app": "add_application", "key": "add_credential", "rule": "add_rule",
                 "provider_credential": "add_credential"}
        for it in [i for i in items_ if i["product"] == "aiguard" and i["action"] == "create"]:   # in plan order
            kind = it["kind"]
            if not t.ledger.find(it["key"]):
                log("info", f"Creating {it['name']} ({KINDS[kind].get('title', kind.replace('_', ' '))})…")
            if kind == "key":
                secret = aiguard_secret(it["key"])

                def keep(r, pov=pov, name=secret):
                    if r.get("key"):
                        secrets.put(pov.id, name, r["key"])
                        log("info", "  its secret went straight to this computer's keychain")
                    return r.get("id")
                t.create(it["key"], KINDS[kind]["res"], verbs[kind], extract_id=keep, stamped=False, **it["body"])
            elif kind == "provider_credential":   # the SE's model key, from the keychain, never in the change list
                body = copy.deepcopy(it["body"])
                api = body["apiCredentials"]
                for f, v in list(api.items()):
                    if isinstance(v, str) and v.startswith("{secret:") and v.endswith("}"):
                        api[f] = secrets.get(pov.id, v[len("{secret:"):-1]) or ""
                if not all(api.values()):
                    raise KitError("Your model key isn't in this computer's keychain: AI Guard tab → Proxy mode.")
                t.create(it["key"], KINDS[kind]["res"], verbs[kind], stamped=False, **body)
            else:
                t.create(it["key"], KINDS[kind]["res"], verbs[kind], stamped=False, **it["body"])
            log("ok", f"{'Already there:' if getattr(t, 'existed', False) else 'Created'} {it['name']}")

    def live_object(self, t, entry):
        k = KINDS[entry["kind"]]
        try:
            o = t.call(k["res"], k["get"], int(entry["id"]) if str(entry["id"]).isdigit() else entry["id"])
        except Exception as e:
            if re.search(r"\b404\b|not.?found", str(e), re.I):
                return None
            raise
        return o if isinstance(o, dict) and o else None

    def set_profile(self, t, pov, ledger, profile, log):
        if not isinstance(profile, dict) and profile not in PROFILES:
            raise KitError(f"Profiles: {', '.join(PROFILES)}, or a custom one.")
        e = ledger.find("aiguard.policy")
        if not e:
            raise KitError("The POV has no AI Guard policy yet. Run `pov-kit apply` first.")
        live = self.live_object(t, e)
        if not live:
            raise KitError("The POV's AI Guard policy is gone. Status > Fix drift (or `pov-kit status --fix`).")
        body = apply_profile(copy.deepcopy(live), profile)
        body = {k: v for k, v in body.items() if k not in ("id", "createdAt", "updatedAt", "lastModifiedBy")}
        t.update(e, live, KINDS["policy"]["res"], "update_policy", int(e["id"]), **body)
        what = PROFILES[profile] if not isinstance(profile, dict) else (
            "Custom: blocks " + (", ".join(f"{k}: {', '.join(v)}" for k, v in blocked_map(body).items() if v) or "nothing"))
        log("ok", f"POV policy: {what} (takes about 30 seconds)")

    def drift(self, t, pov, ledger, items_):
        mine = [i for i in items_ if i["product"] == "aiguard" and i["action"] == "create"]
        missing = [i["name"] for i in mine if not ledger.find(i["key"])]
        gone = [e["name"] for e in ledger.active("aiguard") if self.live_object(t, e) is None]
        out = [check("aiguard-present", "POV AI Guard objects present", WARN if (missing or gone) else OK,
                     "; ".join(filter(None, [f"not created yet: {', '.join(missing)}" if missing else "",
                                             f"deleted in the console: {', '.join(gone)}" if gone else ""]))
                     or f"all {len(mine)}", "Status > Fix drift (or `pov-kit status --fix`)." if (missing or gone) else "",
                     fixable=bool(missing or gone))]
        if ledger.find("aiguard.key") and not secrets.get(pov.id, KEY_SECRET):
            out.append(check("aiguard-key", "POV detection key in the keychain", WARN, "missing",
                             "The key's secret is shown only when it's created. Delete the key in AI Guard, then run "
                             "Status > Fix drift to make a new one."))
        return out

    def fix_drift(self, t, pov, ledger, items_, log):
        for e in ledger.active("aiguard"):
            if self.live_object(t, e) is None:
                ledger.mark(e, "deleted")
                log("info", f"{e['name']} was deleted in the console; apply will recreate it")
        return False

    def teardown(self, t, pov, ledger, log):
        out = []
        for e in ledger.newest_first("aiguard"):   # rule, key, app, policy
            live = self.live_object(t, e)
            if live is None:
                ledger.mark(e, "deleted")
                continue
            try:
                t.delete(e, live, KINDS[e["kind"]]["res"], KINDS[e["kind"]]["dele"], int(e["id"]))
                log("ok", f"Deleted {e['name']}")
            except GuardError as err:
                out.append(check("aiguard-left", f"Left in place: {e['name']}", WARN, str(err)))
        from ..usecases import aiguard_secret
        for e in ledger.entries:   # use cases' keys: their secrets go with them
            if e["product"] == "aiguard" and e["kind"] == "key" and e["state"] == "deleted" and e["key"] != "aiguard.key":
                secrets.delete(pov.id, aiguard_secret(e["key"]))
        if not ledger.find("aiguard.key"):
            secrets.delete(pov.id, KEY_SECRET)
        return out

    def api_proof(self, t, pov, ledger, criterion, scan=None):
        from ..usecases import aiguard_secret
        live, scan = scan is None, scan or das_scan
        tests, pkey = PROOF_TESTS.get(criterion["id"]), "aiguard.policy"
        if criterion.get("customer_pack"):   # the customer's own prompts, through the POV's main app
            from ..aiguard_runner import customer_packs
            tests = (customer_packs(pov).get(criterion.get("pack")) or {}).get("tests") or []
            key = secrets.get(pov.id, KEY_SECRET)
        elif criterion.get("usecase"):   # a use case's own prompts, through its own app if it has one
            tests = criterion.get("aiguard") or []
            n = int(criterion["id"].split("-")[1])
            own = next((e for e in ledger.active("aiguard") if e["kind"] == "key"
                        and e["key"].startswith(f"aiguard.uc{n:02d}.")), None)
            if own:
                pkey = own["key"].rsplit(".", 1)[0] + ".policy"
            key = secrets.get(pov.id, aiguard_secret(own["key"] if own else "aiguard.key"))
        else:
            key = secrets.get(pov.id, KEY_SECRET)
        from ..aiguard_runner import accepted_drafts
        tests = list(tests or []) + accepted_drafts(pov, criterion["id"])   # tests Claude drafted, once accepted
        if not tests:
            return None
        if not key:
            return {"status": "incomplete", "detail": "no POV detection key in the keychain"}
        e = ledger.find(pkey)
        base = scan(key, BASELINE)
        if e and base.get("policyId") not in (None, int(e["id"]), e["id"]):
            return {"status": "fail", "detail": f"handled by policy '{base.get('policyName')}', not the POV's"}
        rows, ok = [], True
        competitor = (pov.cfg.get("aiguard") or {}).get("competitor") or "Competitor Inc"
        for x in tests:
            text = x["text"].replace("{_}", "").replace("{COMPETITOR}", competitor)
            d = scan(key, text, x.get("direction", "IN"))
            got = hits(d)
            want = x["expect"] if isinstance(x["expect"], list) else [x["expect"]]
            hit = set(want) <= set(got) if want else not (set(got) & HARMFUL)
            ok = ok and hit
            rows.append({"test": x.get("name") or x.get("id"), "expect": want, "detected": got,
                         "action": d.get("action"), "pass": hit})
            if live:
                time.sleep(0.2)   # gentle on the Detection API
        actions = sorted({r["action"] for r in rows if r["action"]})
        missed = [r["test"] for r in rows if not r["pass"]]
        return {"status": "pass" if ok else "fail", "results": rows,
                "detail": f"{len(rows) - len(missed)} of {len(rows)} tests as expected; action "
                          f"{', '.join(actions) or 'none'}" + (f"; not as expected: {', '.join(missed[:5])}"
                                                                 if missed else "")}

    def terraform(self, entry, live):
        return None   # the export covers ZIA and ZPA; AI Guard objects are handed over in the console

    def customer_names(self, snap):
        return set(snap.get("customer_names") or [])
