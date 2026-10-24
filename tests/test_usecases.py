"""Use cases from a prompt: Claude proposes, the kit validates, the customer approves, apply builds."""
import json

import pytest

from povkit import ai, evidence, lifecycle, usecases
from povkit.core import KitError, secrets
from povkit.core.changelist import ChangeList

log = lambda *a: None  # noqa: E731

ANSWER = {
    "summary": "Pilot users can open Dropbox but not upload to it, and a test site list is blocked.",
    "already_covered_by": [],
    "changes": [
        {"kind": "url_filtering", "name": "Block test sites", "action": "BLOCK", "urls": ["badsite.example", ".worse.example"],
         "groups": [78], "why": "Shows a custom block list."},                         # 'groups' must be ignored
        {"kind": "cloud_app_control", "name": "No Dropbox uploads", "rule_type": "FILE_SHARE",
         "applications": ["DROPBOX"], "actions": ["BLOCK_FILE_SHARE_UPLOAD"]},
        {"kind": "dlp", "name": "Made-up engine", "action": "BLOCK", "engines": ["Nonexistent engine"]},
        {"kind": "zpa_segment", "name": "Not allowed"},
    ],
    "directions": [{"product": "zia", "console_page": "Advanced Settings", "steps": ["Turn on X for everyone."]}],
    "test": {"title": "Dropbox uploads blocked", "statement": "Uploads to Dropbox are blocked for pilot users.",
             "probe": [{"type": "http", "url": "https://badsite.example/", "expect": "block"},
                       {"type": "http", "url": "http://insecure.example/", "expect": "block"},   # dropped: not https
                       {"type": "shell", "cmd": "rm -rf /"}],                                   # dropped: not a probe type
             "attest": "Upload a file to Dropbox from a pilot device and see the block page."},
}


class Reply:
    def __init__(self, status=200, body=None, text=""):
        self.status_code, self._body, self.text = status, body, text or json.dumps(body)

    def json(self):
        return self._body


@pytest.fixture
def claude(monkeypatch):
    sent = []

    def transport(url, json=None, headers=None, timeout=None):
        sent.append({"url": url, "json": json, "headers": headers})
        return Reply(body={"content": [{"type": "text", "text": "Here you go:\n" + __import__("json").dumps(ANSWER)}]})
    monkeypatch.setattr(ai, "TRANSPORT", transport)
    return sent


@pytest.fixture
def ready(pov, tenant, tenant_for, claude):
    tenant.actions["FILE_SHARE"].append("BLOCK_FILE_SHARE_UPLOAD")
    secrets.put(*ai.OWN_KEY, "proxy-key-123")
    ai.record_consent(pov, "Jane Doe, CISO")
    snaps, _ = lifecycle.discover(pov, tenant_for)
    return snaps


def test_nothing_goes_to_claude_without_consent_and_a_key(pov, tenant_for, claude):
    snaps, _ = lifecycle.discover(pov, tenant_for)
    with pytest.raises(KitError, match="hasn't agreed"):
        usecases.propose(pov, snaps, "block test sites")
    ai.record_consent(pov, "Jane Doe, CISO")
    with pytest.raises(KitError, match="AI Guard app proxy key"):
        usecases.propose(pov, snaps, "block test sites")
    assert claude == []


def test_claude_goes_through_ai_guard_with_names_replaced(pov, ready, claude):
    uc = usecases.propose(pov, ready, "Let POV Pilot open Dropbox but not upload to it, like jane@acme.com does")
    req = claude[0]
    assert req["url"].endswith("/v1/messages") and "proxy.zseclipse.net" in req["url"]
    assert req["headers"]["X-ApiKey"] == "proxy-key-123"
    sent = req["json"]["messages"][0]["content"]
    for name in ("Corp: Block adult", "POV Pilot", "Acme Corp", "jane@acme.com"):   # names only, by default
        assert name not in sent
    assert "Dropbox" in sent and "GAMBLING" in sent                            # Zscaler's own values stay
    assert req["json"]["tool_choice"]["name"] == "propose_use_case"
    assert uc["shared"] == "names_only" and uc["masked"] >= 3


def test_full_sharing_needs_its_own_agreement(pov, ready, claude):
    from povkit import settings
    from povkit.core import KitError
    settings.set_value(pov, "ai.share", "full")
    with pytest.raises(KitError, match="in full"):                           # the agreement was for names only
        usecases.propose(pov, ready, "x")
    ai.record_consent(pov, "Jane Doe, CISO")
    usecases.propose(pov, ready, "Let pilot users open Dropbox but not upload to it")
    assert "Corp: Block adult" in claude[-1]["json"]["messages"][0]["content"]
    settings.set_value(pov, "ai.share", "names_only")
    assert ai.consent(pov)                                                   # full covers names only


def test_the_kit_validates_what_claude_proposes(pov, ready):
    uc = usecases.propose(pov, ready, "Let pilot users open Dropbox but not upload to it")
    spec = uc["spec"]
    assert [c["kind"] for c in spec["changes"]] == ["url_filtering", "cloud_app_control"]
    assert "groups" not in spec["changes"][0]                                 # Claude can't widen scope
    assert {d["why"].split(":")[0] for d in spec["dropped"]} >= {"DLP engines not in this tenant"}
    assert any("doesn't build 'zpa_segment'" in d["why"] for d in spec["dropped"])
    assert len(spec["directions"]) == 1 + len(spec["dropped"])                 # dropped changes become directions
    assert spec["test"]["probe"] == [{"type": "http", "url": "https://badsite.example/", "expect": "block"}]
    assert uc["id"] == "UC-01" and uc["status"] == "proposed"


def test_accepted_use_case_needs_a_fresh_approval_then_applies_scoped(pov, tenant, tenant_for, ready):
    lifecycle.plan(pov, tenant_for)
    ChangeList(pov.dir).approve("Jane Doe")
    lifecycle.apply(pov, tenant_for, log)
    usecases.propose(pov, ready, "Let pilot users open Dropbox but not upload to it")
    usecases.set_status(pov, "UC-01", "accepted")
    st = {c["id"]: c for c in lifecycle.status(pov, tenant_for)}
    assert st["plan-approved"]["status"] == "warn"                            # the plan now differs from the approval
    with pytest.raises(KitError, match="changed since the customer approved"):
        lifecycle.apply(pov, tenant_for, log)
    items, _, _, _ = lifecycle.plan(pov, tenant_for)
    assert {i["key"] for i in items} >= {"zia.uc01.1", "zia.uc01.2", "zia.url_category.uc01-1"}
    assert ChangeList(pov.dir).approval() is None
    ChangeList(pov.dir).approve("Jane Doe")
    lifecycle.apply(pov, tenant_for, log)
    rule = tenant.by_name("url_filtering", "ZPOV: UC1 Block test sites")
    cat = tenant.by_name("url_category", "ZPOV - UC1 Block test sites")
    assert rule["groups"] == [77] and rule["url_categories"] == [cat["id"]] and cat["urls"] == ["badsite.example", ".worse.example"]
    cac = tenant.by_name("cloud_app_control", "ZPOV: UC1 No Dropbox uploads")
    assert cac["actions"] == ["BLOCK_FILE_SHARE_UPLOAD"] and cac["groups"] == [77]
    crit = {c["id"]: c for c in evidence.selected_criteria(pov)}
    assert crit["UC-01"]["proofs"] == ["probe", "attested"]
    assert any(c["id"] == "UC-01" for c in evidence.probe_pack(pov)["criteria"])
    lifecycle.teardown(pov, tenant_for, log)
    assert not tenant.by_name("url_filtering", "ZPOV: UC1 Block test sites")


def test_a_use_case_with_nothing_to_build_stays_directions(pov, ready, monkeypatch):
    monkeypatch.setitem(ANSWER, "changes", [])
    uc = usecases.propose(pov, ready, "Show ZPA access for contractors")
    with pytest.raises(KitError, match="keep it as directions"):
        usecases.set_status(pov, uc["id"], "accepted")
    usecases.set_status(pov, uc["id"], "directions")
    assert "Turn on X for everyone." in usecases.directions_md(usecases.get(pov, uc["id"]))
    assert {c["id"]: c for c in evidence.selected_criteria(pov)}[uc["id"]]["proofs"] == ["probe", "attested"]


def test_ai_guard_blocking_is_explained(pov, ready, monkeypatch):
    monkeypatch.setattr(ai, "TRANSPORT", lambda *a, **k: Reply(403, text='{"error":"blocked by policy"}'))
    with pytest.raises(KitError, match="AI Guard blocked"):
        usecases.propose(pov, ready, "anything")


def test_a_bad_answer_is_reported(pov, ready, monkeypatch):
    monkeypatch.setattr(ai, "TRANSPORT", lambda *a, **k: Reply(body={"content": [{"type": "text", "text": "Sure!"}]}))
    with pytest.raises(KitError, match="expected JSON"):
        usecases.propose(pov, ready, "anything")


def test_make_a_use_case_from_its_card(pov, tenant, tenant_for, ready):
    lifecycle.plan(pov, tenant_for)
    ChangeList(pov.dir).approve("Jane Doe")
    lifecycle.apply(pov, tenant_for, log)
    usecases.propose(pov, ready, "Let pilot users open Dropbox but not upload to it")
    usecases.set_status(pov, "UC-01", "accepted")
    pv = lifecycle.make_preview(pov, tenant_for, "UC-01")
    assert {i["name"] for i in pv["mine"]} >= {"ZPOV: UC1 Block test sites"} and not pv["others"]
    assert pv["mode"] == "se" and not pv["approved"] and not pv["blocked"]
    with pytest.raises(KitError, match="changed since you reviewed"):
        lifecycle.make_now(pov, tenant_for, "UC-01", "stale", "Paul", log)
    with pytest.raises(KitError, match="name"):
        lifecycle.make_now(pov, tenant_for, "UC-01", pv["hash"], "", log)
    lifecycle.make_now(pov, tenant_for, "UC-01", pv["hash"], "Paul", log)
    assert tenant.by_name("url_filtering", "ZPOV: UC1 Block test sites")["groups"] == [77]
    assert "UC-01" in ChangeList(pov.dir).approval()["note"]
    assert lifecycle.make_preview(pov, tenant_for, "UC-01")["mine"] == []
    pov.cfg["approval"] = "customer"
    pov.save()
    usecases.propose(pov, ready, "Block another site")
    usecases.set_status(pov, "UC-02", "accepted")
    pv = lifecycle.make_preview(pov, tenant_for, "UC-02")
    with pytest.raises(KitError, match="customer's approval"):
        lifecycle.make_now(pov, tenant_for, "UC-02", pv["hash"], "Paul", log)
