import pytest

from povkit.core import KitError, secrets
from povkit.products import zia as Z


class Led:
    def find(self, key):
        return {"key": key, "kind": "user", "id": 7, "name": "ZPOV - pilot user 1"} if key == "zia.user.1" else None


class T:
    def __init__(self):
        self.calls = []

    def update(self, e, live, res, meth, *a, **body):
        self.calls.append((meth, a, body))

    def activate(self):
        self.calls.append(("activate",))


def test_set_generated_and_typed(pov, monkeypatch):
    z = Z.ZIA() if hasattr(Z, "ZIA") else next(v for v in vars(Z).values() if isinstance(v, type) and hasattr(v, "set_test_password"))()
    monkeypatch.setattr(type(z), "live_object", lambda self, t, e: {"id": 7, "name": e["name"], "email": "zpov-pilot-1@x.com",
                                                                    "groups": [{"id": 1}], "department": {"id": 2}})
    t = T()
    pw = z.set_test_password(t, pov, Led(), 1)
    assert len(pw) >= 12 and secrets.get(pov.id, "zia-test-user-1") == pw
    assert t.calls[0][0] == "update_user" and t.calls[0][2]["password"] == pw and t.calls[-1] == ("activate",)
    assert z.set_test_password(T(), pov, Led(), 1, "Pilot-Pass1!") == "Pilot-Pass1!"
    with pytest.raises(KitError):
        z.set_test_password(T(), pov, Led(), 1, "weak")
    with pytest.raises(KitError):
        z.set_test_password(T(), pov, Led(), 2)
