"""Secrets live in the OS keychain, one namespace per POV, and are deleted at handover. Never in files or logs."""
from __future__ import annotations

SERVICE = "zscaler-pov-kit"
NAMES = ("main-client-secret", "discovery-client-secret", "apply-client-secret", "zpa-provisioning-key",
         "aiguard-detection-key", "mcp-client-secret")


def _kr():
    import keyring
    return keyring


def _k(pov_id, name):
    return f"{pov_id}/{name}"


def get(pov_id, name):
    return _kr().get_password(SERVICE, _k(pov_id, name))


def put(pov_id, name, value):
    _kr().set_password(SERVICE, _k(pov_id, name), value)


def delete(pov_id, name):
    try:
        _kr().delete_password(SERVICE, _k(pov_id, name))
        return True
    except Exception:
        return False


def delete_all(pov_id, extra=()) -> list[str]:
    """Every secret the POV may hold: the fixed names, plus extra ones (use cases' AI Guard keys)."""
    return [n for n in (*NAMES, *extra) if delete(pov_id, n)]


def keychain_works() -> tuple[bool, str]:
    try:
        put("preflight", "probe", "ok")
        good = get("preflight", "probe") == "ok"
        delete("preflight", "probe")
        return good, "" if good else "the keychain didn't return the test value"
    except Exception as e:
        return False, str(e)[:160]
