"""'Names only' sharing: the customer's names leave the laptop as placeholders.

Before a use-case request goes to Claude, every customer-identifying string in the snapshot and in the prompt is
swapped for a stable placeholder (NAME_7, EMAIL_2, DOMAIN_1): the customer's name and vanity domain, their own
policy and object names, the pilot group, user emails, device names, the connected SaaS tenant, IdP names, and the
ZPA app's domains and the customer's segment domains. Claude still sees the policy's shape (kinds, counts, actions,
categories, engines, detectors), which is what it needs to propose a change. Its reply is swapped back on the
laptop, before the kit validates it, so validation always runs on real values.

Zscaler's own values (URL category IDs, DLP engine names, file types, detector names, Cloud App Control names) and
the kit's own object names stay as they are.
"""
from __future__ import annotations

import json
import re

from . import products
from .core.redact import EMAIL

MIN = 3
ENUMISH = re.compile(r"^[A-Z0-9_]+$")   # what Zscaler's own IDs look like (FINANCE, CHATGPT_AI)


def values(pov, snaps, text=""):
    """The strings to hide (from the POV, its snapshot, and any emails in `text`): -> {value: kind}"""
    out = {}

    def add(v, kind="NAME"):
        v = str(v or "").strip()
        if len(v) >= MIN and not v.startswith(pov.prefix + ":") and not v.startswith(pov.prefix + " -"):
            out.setdefault(v, kind)

    add(pov.cfg.get("customer"))
    add(pov.cfg.get("vanity_domain"), "ORG")
    add(pov.cfg.get("pilot_group"))
    for e in pov.cfg.get("pilot_emails") or []:
        add(e, "EMAIL")
    for p in products.selected(pov.products):
        snap = (snaps or {}).get(p.name)
        if snap:
            try:
                for n in p.customer_names(snap):
                    add(n, "DOMAIN" if "." in str(n) and " " not in str(n) else "NAME")
            except Exception:
                pass
    zia = (snaps or {}).get("zia") or {}
    for e in zia.get("custom_engines") or []:   # the customer's own DLP engines; Zscaler's predefined ones stay
        add(e, "ENGINE")
    cbi = zia.get("cbi") or {}
    add(cbi.get("name"))
    add(cbi.get("url"), "DOMAIN")
    zpa = (snaps or {}).get("zpa") or {}
    for d in zpa.get("segment_domains") or []:
        add(d, "DOMAIN")
    for i in zpa.get("idps") or []:
        add(i.get("name"))
    for e in set(EMAIL.findall(json.dumps(snaps or {}, default=str) + " " + str(text or ""))):
        add(e, "EMAIL")
    for e in list(out):   # an email's domain gives the customer away too
        if out[e] == "EMAIL":
            add(e.split("@", 1)[1], "DOMAIN")
    for v, kind in list(out.items()):   # 'ACME CORP' and 'acme corp' too, but never an ID-like 'FINANCE'
        for variant in (v.upper(), v.lower()):
            if variant != v and len(variant) >= 4 and not ENUMISH.match(variant):
                out.setdefault(variant, "~" + kind)   # '~': a variant, unmasked to its original
    return out


class Masker:
    def __init__(self, vals: dict):
        counters, self.fwd, self.back, first = {}, {}, {}, {}
        originals = sorted((v for v, k in vals.items() if not k.startswith("~")), key=lambda x: (-len(x), x))
        for v in originals:
            if v.lower() in first:
                self.fwd[v] = first[v.lower()]
                continue
            k = vals[v]
            counters[k] = counters.get(k, 0) + 1
            tok = f"{k}_{counters[k]}"
            self.fwd[v], self.back[tok] = tok, v
            first[v.lower()] = tok
        for v, k in vals.items():   # case variants share their original's placeholder
            if k.startswith("~") and v not in self.fwd:
                tok = first.get(v.lower())
                if not tok:
                    k = k[1:]
                    counters[k] = counters.get(k, 0) + 1
                    tok = f"{k}_{counters[k]}"
                    self.back[tok], first[v.lower()] = v, tok
                self.fwd[v] = tok
        bound = r"(?<![A-Za-z0-9_@])({})(?![A-Za-z0-9_])"
        alts = sorted(self.fwd, key=len, reverse=True)   # longest first: 'Sales EMEA' before 'Sales'
        self._f = re.compile(bound.format("|".join(re.escape(v) for v in alts))) if alts else None
        self._b = re.compile(r"\b(" + "|".join(re.escape(t) for t in sorted(self.back, key=len, reverse=True)) + r")\b") \
            if self.back else None

    def mask(self, text: str) -> str:
        """Case-sensitive, so a group called 'Finance' doesn't hide the category ID FINANCE."""
        return self._f.sub(lambda m: self.fwd[m.group(1)], text) if self._f else text

    def unmask(self, o):
        if isinstance(o, str):
            return self._b.sub(lambda m: self.back[m.group(1)], o) if self._b else o
        if isinstance(o, list):
            return [self.unmask(x) for x in o]
        if isinstance(o, dict):
            return {self.unmask(k) if isinstance(k, str) else k: self.unmask(v) for k, v in o.items()}
        return o

    def __len__(self):
        return len(self.fwd)


def for_pov(pov, snaps, text=""):
    return Masker(values(pov, snaps, text))
