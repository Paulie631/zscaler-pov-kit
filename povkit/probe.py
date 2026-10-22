"""The POV probe: runs on a pilot device with Client Connector signed in, sends safe test traffic, and writes a
results file the SE imports with `pov-kit import-probe`. It needs no API keys and never sees the tenant's API.

Safe test data only, as in the demo kit's traffic generator (whose classify() this ports): the EICAR test string
(assembled at run time so no kit file contains it), Google Safe Browsing test pages, and generated fake card
numbers from the card networks' published test ranges.
"""
from __future__ import annotations

import base64
import json
import platform
import random
import re
import secrets
import socket
import string
import subprocess
import time

TIMEOUT = 15
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
_EICAR_PARTS = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-", "TEST-FILE!$H+H*")
TEST_BINS = ("411111", "401288", "555555", "510510", "601111")
ZS_PAGE = re.compile(r"zscaler", re.I)
BLOCK_WORDS = re.compile(r"blocked|not allowed|restricted|acceptable use|policy|virus|malware|threat|denied|"
                         r"sorry|prohibited|data loss|sensitive", re.I)


def eicar():
    return "".join(_EICAR_PARTS)


def luhn_ok(num):
    total = 0
    for i, d in enumerate(reversed([int(c) for c in num])):
        total += (d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 else d
    return total % 10 == 0


def fake_card(rnd=random):
    body = rnd.choice(TEST_BINS) + "".join(rnd.choice(string.digits) for _ in range(9))
    return next(body + c for c in string.digits if luhn_ok(body + c))


def classify(resp=None, error=None):
    """-> block | caution | isolate | allow | error:<why>. A Zscaler page or redirect counts as Zscaler acting."""
    if error is not None:
        if re.search(r"reset|refused|aborted|10054|10061", str(error), re.I):
            return "block"
        return "error:" + type(error).__name__
    hops = [h.headers.get("Location", "") for h in getattr(resp, "history", [])] + [str(getattr(resp, "url", ""))]
    trail = " ".join(hops).lower()
    if "zscaler" in trail and re.search(r"isolat|cbi|zsisolation", trail):
        return "isolate"
    ctype = resp.headers.get("Content-Type", "")
    text = ""
    if "html" in ctype or "text" in ctype or not ctype:
        try:
            text = resp.text[:40000]
        except Exception:
            text = ""
    zs = ZS_PAGE.search(text) or "gateway.zscaler" in trail or "zscaler.net" in trail
    if zs and re.search(r"caution|continue to|proceed", text, re.I) and not re.search(r"virus|malware|data loss", text, re.I):
        return "caution"
    if zs and (BLOCK_WORDS.search(text) or resp.status_code in (403, 451)):
        return "block"
    return "allow"


def tls_issuer(host, port=443):
    """'Zscaler' if the certificate this host presents on this device was issued by Zscaler, else 'other'."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True) or b""
    return "Zscaler" if b"Zscaler" in der else "other"


def zcc_running():
    """From the demo kit's traffic generator."""
    try:
        if platform.system() == "Windows":
            out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=15).stdout
            return bool(re.search(r"ZSATray|ZSAService|ZSATunnel", out, re.I))
        out = subprocess.run(["ps", "-A", "-o", "comm="], capture_output=True, text=True, timeout=15).stdout
        return bool(re.search(r"zscaler|zstunnel|ZscalerTunnel", out, re.I))
    except Exception:
        return False


def tag(url, run_id):
    """Adds the run ID so the probe's events can be matched in the customer's logs."""
    return url + ("&" if "?" in url else "?") + f"zpov_run={run_id}"


def run_spec(spec, run_id, s):
    kind = spec["type"]
    t0 = time.time()
    try:
        if kind == "http":
            r = s.get(tag(spec["url"], run_id), timeout=TIMEOUT)
            got = classify(r)
            detail = f"HTTP {r.status_code}"
        elif kind == "eicar":
            b64 = base64.urlsafe_b64encode(eicar().encode()).decode()
            r = s.get(tag(spec["url"].format(b64=b64), run_id), timeout=TIMEOUT)
            got = classify(r)
            detail = f"HTTP {r.status_code}"
        elif kind == "dlp_post":
            rows = "\n".join(f"Card {fake_card()} exp 12/29" for _ in range(6))
            r = s.post(tag(spec["url"], run_id), data={"notes": rows}, timeout=TIMEOUT)
            got = classify(r)
            detail = f"HTTP {r.status_code}, 6 fake card numbers"
        elif kind == "tls_issuer":
            issuer = tls_issuer(spec["host"])
            got = "Zscaler" if issuer == "Zscaler" else "not-Zscaler"
            detail = f"certificate issuer: {issuer}"
        elif kind == "zcc_running":
            got = "running" if zcc_running() else "not running"
            detail = "Client Connector process"
            spec = dict(spec, expect="running")
        elif kind == "via_zscaler":
            # the demo kit's via_zscaler(): ip.zscaler.com says whether the request came through Zscaler
            low = re.sub(r"<[^>]+>", " ", s.get("https://ip.zscaler.com/", timeout=TIMEOUT).text).lower()
            through = (not re.search(r"not (going|accessing|connected)[^.]{0,40}zscaler|not using zscaler", low)
                       and re.search(r"(via|through|using)[^.]{0,30}zscaler", low))
            got = "zscaler" if through else "direct"
            clouds = sorted(set(re.findall(r"\b(zscaler[a-z]*\.net)\b", low)))
            detail = "ip.zscaler.com" + (f": {', '.join(clouds)}" if clouds else "")
            spec = dict(spec, expect="zscaler")
        else:
            got, detail = "error:unknown-type", kind
    except Exception as e:
        got, detail = classify(error=e), str(e)[:160]
    return {"spec": spec, "outcome": got, "expect": spec.get("expect"), "pass": got == spec.get("expect"),
            "detail": detail, "ms": int((time.time() - t0) * 1000)}


def run(criteria, session=None):
    import requests
    s = session or requests.Session()
    s.headers.update({"User-Agent": UA})
    run_id = secrets.token_hex(4)
    out = {"run_id": run_id, "device": socket.gethostname(), "os": platform.platform(),
           "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": []}
    for c in criteria:
        for spec in c.get("probe") or []:
            out["results"].append(dict(run_spec(spec, run_id, s), criterion=c["id"]))
    return out


def save(result, path):
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return path
