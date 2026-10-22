"""Redaction for logs and the diagnostics zip.

Two layers, because the zip goes to the kit owner, not the customer:
  secrets         any field that looks like a key, secret, token or password is masked (as in the demo kit)
  customer data   names of the customer's own objects (from discovery) and anything that looks like an email
                  address become placeholders; counts, kinds, error codes and the kit's own objects stay
"""
from __future__ import annotations

import re

SECRET_FIELDS = re.compile(r"^(key|secret|clientsecret|client_secret|token|access_token|apikey|api_key|password|"
                           r"authorization|cookie|privatekey|private_key)$", re.I)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
BEARER = re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.I)
MAX = 2000


def mask(s) -> str:
    s = str(s or "")
    return s[:3] + "…" + s[-2:] if len(s) > 8 else "…"


class Redactor:
    def __init__(self, customer_names=(), prefix="ZPOV"):
        self.prefix = prefix
        # longest first, so 'Sales EMEA' is replaced before 'Sales'
        names = sorted({n for n in customer_names if n and len(n) >= 3 and not n.startswith(prefix)},
                       key=len, reverse=True)
        self._names = re.compile("|".join(re.escape(n) for n in names)) if names else None

    def text(self, s: str) -> str:
        s = BEARER.sub(r"\1…", str(s))
        s = EMAIL.sub("<email>", s)
        if self._names:
            s = self._names.sub("<customer-object>", s)
        return s[:MAX]

    def __call__(self, o, depth=0):
        if depth > 12:
            return "…"
        if isinstance(o, dict):
            return {k: ("…" if SECRET_FIELDS.match(str(k)) and v else self(v, depth + 1)) for k, v in o.items()}
        if isinstance(o, list):
            return [self(v, depth + 1) for v in o[:200]]
        if isinstance(o, str):
            return self.text(o)
        return o
