from povkit.core import trust

ROOT = "-----BEGIN CERTIFICATE-----\nWlNDQUxFUi1ST09ULUZBS0U=\n-----END CERTIFICATE-----\n"


def test_bundle_adds_the_computers_roots(tmp_path, monkeypatch):
    monkeypatch.setattr(trust, "FILE", tmp_path / "ca-bundle.pem")
    monkeypatch.setattr(trust, "_system_pems", lambda: [ROOT, ROOT])
    path = trust.bundle()
    text = open(path, encoding="utf-8").read()
    assert text.count("WlNDQUxFUi1ST09ULUZBS0U=") == 1          # the computer's root, once
    assert text.count("BEGIN CERTIFICATE") > 100                  # and certifi's own list
    monkeypatch.setattr(trust, "_system_pems", lambda: [])
    assert trust.bundle() == path                                 # cached for a day


def test_updater_uses_it(home, monkeypatch):
    from povkit import updater
    seen = {}

    def fake_get(url, **kw):
        import requests
        seen.update(kw)
        raise requests.exceptions.SSLError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
    monkeypatch.setattr(trust, "get", fake_get)
    st = updater.status(force=True)
    assert "System keychain" in st["error"] and "Terminal" in st["error"]
