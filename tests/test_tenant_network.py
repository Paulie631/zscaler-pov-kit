"""A request that never reached Zscaler (DNS, connection): retried, then explained in plain words."""
import types

import pytest

from povkit import tenant as T
from povkit.core import KitError

DNS = ("HTTPSConnectionPool(host='acme.zslogin.net', port=443): Max retries exceeded with url: /oauth2/v1/token "
       "(Caused by NameResolutionError(\"HTTPSConnection(host='acme.zslogin.net', port=443): Failed to resolve "
       "'acme.zslogin.net' ([Errno 8] nodename nor servname provided, or not known)\"))")


def _tenant(pov, fn, monkeypatch):
    monkeypatch.setattr(T, "NET_WAITS", (0, 0))
    t = object.__new__(T.Tenant)
    t.pov, t.which = pov, "discovery"
    t.c = types.SimpleNamespace(zia=types.SimpleNamespace(activate=types.SimpleNamespace(status=fn, activate=fn)))
    return t


def test_dns_failure_is_retried_then_works(pov, monkeypatch):
    calls = []

    def fn():
        calls.append(1)
        if len(calls) < 3:
            raise RuntimeError(DNS)
        return {"status": "ACTIVE"}
    assert _tenant(pov, fn, monkeypatch).call("activate", "status") == {"status": "ACTIVE"} and len(calls) == 3


def test_dns_failure_message(pov, monkeypatch):
    pov.cfg["vanity_domain"] = "acme"
    t = _tenant(pov, lambda: (_ for _ in ()).throw(RuntimeError(DNS)), monkeypatch)
    with pytest.raises(KitError) as e:
        t.call("activate", "status")
    m = str(e.value)
    assert "couldn't look up acme.zslogin.net" in m and "nothing changed" in m and "HTTPSConnectionPool" not in m


def test_write_not_retried_after_a_reset(pov, monkeypatch):
    calls = []

    def fn():
        calls.append(1)
        raise RuntimeError("('Connection aborted.', RemoteDisconnected('Remote end closed connection'))")
    with pytest.raises(KitError, match="Couldn't reach"):
        _tenant(pov, fn, monkeypatch).call("activate", "activate")
    assert len(calls) == 1


def test_other_errors_unchanged(pov, monkeypatch):
    t = _tenant(pov, lambda: (_ for _ in ()).throw(RuntimeError("400 bad rule")), monkeypatch)
    with pytest.raises(KitError, match="activate.status failed: 400 bad rule"):
        t.call("activate", "status")
