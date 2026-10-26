"""A use case that came back as directions because a product wasn't in the POV, or wasn't readable: the card offers
one click that adds it, reads the tenant again and asks Claude again, so the kit can build it."""
import json

import pytest

from povkit import ai, gui, lifecycle, usecases
from povkit.core import KitError, secrets
from povkit.products import zpa as zpamod

FIRST = {"summary": "Pilot users reach the wiki through ZPA.", "already_covered_by": [], "changes": [],
         "directions": [{"product": "zpa", "console_page": "Application Segments", "steps": ["Add wiki.acme.internal."]},
                        {"product": "zcc", "console_page": "Forwarding Profile", "steps": ["Turn on ZPA."]}],
         "test": {"title": "Wiki", "statement": "The wiki opens.", "probe": [], "attest": "Open it."}}
SECOND = dict(FIRST, changes=[{"kind": "zpa_app", "name": "Wiki", "domains": ["wiki.acme.internal"],
                               "tcp_ports": ["443"], "access": "ALLOW"}],
              directions=[{"product": "zcc", "console_page": "Forwarding Profile", "steps": ["Turn on ZPA."]}])


class Reply:
    def __init__(self, body):
        self.status_code, self._body, self.text = 200, body, json.dumps(body)

    def json(self):
        return self._body


@pytest.fixture
def answers(monkeypatch, pov):
    queue, sent = [FIRST, SECOND], []

    def transport(url, json=None, headers=None, timeout=None):
        sent.append(json)
        ans = queue.pop(0) if len(queue) > 1 else queue[0]
        return Reply({"content": [{"type": "text", "text": __import__("json").dumps(ans)}]})
    monkeypatch.setattr(ai, "TRANSPORT", transport)
    secrets.put(*ai.OWN_KEY, "proxy-key-123")
    ai.record_consent(pov, "Jane Doe, CISO")
    pov.cfg.update(customer_id="7", zpa={"domains": ["pov-app.acme.internal"], "tcp_ports": ["443"]})
    pov.save()
    return sent


def test_gaps_name_what_is_missing(pov):
    d = [{"product": "zpa"}, {"product": "zia"}, {"product": "zcc"}]
    assert usecases.find_gaps(pov, {"zia": {"readable": True}}, {}, d) == {"add": ["zpa"], "read": []}
    assert usecases.find_gaps(pov, {"zia": {"readable": False}}, {}, d) == {"add": ["zpa"], "read": ["zia"]}
    assert usecases.find_gaps(pov, {}, {}, [{"product": "zcc"}]) == {"add": [], "read": []}   # ZCC: directions only


def test_one_click_adds_the_product_reads_and_asks_again(pov, tenant_for, answers):
    snaps, _ = lifecycle.discover(pov, tenant_for)
    uc = usecases.propose(pov, snaps, "Pilot users reach the wiki through ZPA, and nothing else")
    assert uc["spec"]["changes"] == [] and uc["spec"]["gaps"] == {"add": ["zpa"], "read": []}
    uc = usecases.prepare(pov, tenant_for, uc["id"])
    assert "zpa" in pov.products
    assert [c["kind"] for c in uc["spec"]["changes"]] == ["zpa_app"] and uc["status"] == "proposed"
    assert uc["spec"]["gaps"] == {"add": [], "read": []}
    assert "tenant snapshot was just read again" in uc["history"][-1]["feedback"]
    assert [d["product"] for d in uc["spec"]["directions"]] == ["zcc"]          # only what the API can't do


def test_still_unreadable_says_why(pov, tenant_for, answers, monkeypatch):
    from povkit.core.checks import FAIL, check
    snaps, _ = lifecycle.discover(pov, tenant_for)
    uc = usecases.propose(pov, snaps, "Pilot users reach the wiki")
    monkeypatch.setattr(zpamod.ZPA, "discover", lambda self, t, p: ({"readable": False}, [check(
        "zpa-read", "ZPA readable", FAIL, "not found", "Set the ZPA customer ID in Connect.")]))
    with pytest.raises(KitError, match="ZPA still can't be read.*customer ID"):
        usecases.prepare(pov, tenant_for, uc["id"])


def test_directions_can_be_ticked_and_cards_show_gaps(pov, tenant_for, answers):
    snaps, _ = lifecycle.discover(pov, tenant_for)
    uc = usecases.propose(pov, snaps, "Pilot users reach the wiki")
    usecases.mark_done(pov, uc["id"], 1)
    assert usecases.get(pov, uc["id"])["done"] == [1]
    usecases.mark_done(pov, uc["id"], 1, False)
    assert usecases.get(pov, uc["id"])["done"] == []
    cards = gui.api("GET", "/api/usecases", {}, {})[1]["usecases"]
    assert cards[0]["spec"]["gaps"]["add"] == ["zpa"]
