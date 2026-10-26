"""Certificates the kit trusts for its own downloads (update checks and installs).

Python's requests trusts only its own list (certifi), not the computer's. On a laptop whose Zscaler Client Connector
inspects TLS (most SE laptops), github.com arrives re-signed by the Zscaler root that Client Connector put in the
computer's trust store, so requests refuses it: "CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate".

bundle() writes one PEM file with certifi's list plus the computer's own trusted roots (the macOS System keychain and
system roots, or Windows' certificate stores), and requests verifies against that. Nothing is turned off: a
certificate nobody on this computer trusts is still refused.
"""
from __future__ import annotations

import hashlib
import platform
import ssl
import subprocess
import time
from pathlib import Path

from .pov import BASE

FILE = BASE / "ca-bundle.pem"
MAX_AGE = 24 * 3600   # rebuilt daily, so a root IT adds (or removes) is picked up


def _system_pems() -> list[str]:
    out = []
    if platform.system() == "Darwin":
        for kc in ("/Library/Keychains/System.keychain",
                   "/System/Library/Keychains/SystemRootCertificates.keychain"):
            try:
                r = subprocess.run(["security", "find-certificate", "-a", "-p", kc], capture_output=True, text=True,
                                   timeout=20)
                out += [c + "-----END CERTIFICATE-----\n" for c in r.stdout.split("-----END CERTIFICATE-----")
                        if "BEGIN CERTIFICATE" in c]
            except Exception:   # noqa: BLE001
                pass
    else:   # Windows (ROOT and CA stores) and Linux (the distribution's bundle)
        try:
            ctx = ssl.create_default_context()
            ctx.load_default_certs()
            out += [ssl.DER_cert_to_PEM_cert(d) for d in ctx.get_ca_certs(binary_form=True)]
        except Exception:   # noqa: BLE001
            pass
    return [c.strip() + "\n" for c in out]


def bundle() -> str | bool:
    """Path of the combined bundle for requests' verify=, or True (requests' own list) if it can't be made."""
    try:
        if FILE.exists() and time.time() - FILE.stat().st_mtime < MAX_AGE:
            return str(FILE)
        import certifi
        pems, seen = [], set()
        for c in [Path(certifi.where()).read_text(encoding="utf-8")] + _system_pems():
            h = hashlib.sha256(c.encode()).hexdigest()
            if h not in seen:
                seen.add(h)
                pems.append(c)
        FILE.parent.mkdir(parents=True, exist_ok=True)
        FILE.write_text("\n".join(pems), encoding="utf-8")
        return str(FILE)
    except Exception:   # noqa: BLE001
        return True


def get(url, **kw):
    """requests.get that trusts this computer's roots too."""
    import requests
    return requests.get(url, verify=bundle(), **kw)
