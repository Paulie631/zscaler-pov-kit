"""Names only, structured replies, refining a proposal, and the use-case library."""
import json

import pytest

from povkit import ai, library, lifecycle, pseudo, usecases
from povkit.core import KitError, secrets

ANSWER = {"summary": "POV Pilot can't upload to Dropbox.", "already_covered_by": [],
          "changes": [{"kind": "cloud_app_control", "name": "No Dropbox uploads", "rule_type": "FILE_SHARE",
                       "applications": ["DROPBOX"], "actions": ["BLOCK_FILE_SHARE_UPLOAD"]}],
          "directions": [{"product": "zia", "console_page": "Users", "steps": ["Tell NAME_1 members first."]}],
          "test": {"title": "Uploads blocked", "statement": "", "probe": [], "aiguard": [], "attest": "Try an upload."}}


class Reply:
    status_code = 200

    def __init__(self, body):
        self._body, self.text = body, json.dumps(body)

    def json(self):
        return self._body


@pytest.fixture
def claude(monkeypatch):
    sent, answers = [], []

    def transport(url, json=None, headers=None, timeout=None):
        sent.append(json)
        a = answers.pop(0) if answers else ANSWER
        return Reply({"content": [{"type": "tool_use", "name": "propose_use_case", "input": a}]})
    monkeypatch.setattr(ai, "TRANSPORT", transport)
    return sent, answers


@pytest.fixture
def snaps(pov, tenant, tenant_for, claude):
    tenant.actions["FILE_SHARE"].append("BLOCK_FILE_SHARE_UPLOAD")
    secrets.put(*ai.OWN_KEY, "proxy-key-123")
    ai.record_consent(pov, "Jane Doe, CISO")
    return lifecycle.discover(pov, tenant_for)[0]


def test_masker_round_trips_and_leaves_zscaler_values(pov, snaps):
    text = "POV Pilot and jane@acme.com at Acme Corp; Corp: Block adult; category FINANCE; Corp: Inspect all"
    m = pseudo.for_pov(pov, snaps, text)
    masked = m.mask(text)
    assert "POV Pilot" not in masked and "acme" not in masked.lower() and "FINANCE" in masked
    assert m.unmask(masked) == text


def test_names_only_covers_accents_case_engines_and_metadata(pov, tenant, snaps, claude):
    sent, _ = claude
    pov.cfg["customer"] = "Zürich Finanz AG"
    pov.save()
    usecases.propose(pov, snaps, "ZÜRICH FINANZ AG wants Acme Project Falcon data blocked for POV PILOT")
    body = json.dumps(sent[-1], ensure_ascii=False)
    for leak in ("Zürich", "ZÜRICH", "Acme Project Falcon", "POV PILOT", pov.id):
        assert leak not in body, leak
    assert "5 or more Credit Card Numbers" in body                            # Zscaler's own engine stays readable


def test_structured_reply_is_unmasked_before_validation(pov, snaps, claude):
    sent, answers = claude
    tok = pseudo.for_pov(pov, snaps).fwd["POV Pilot"]
    answers.append(dict(ANSWER, summary=f"{tok} can't upload to Dropbox."))
    uc = usecases.propose(pov, snaps, "POV Pilot can't upload to Dropbox")
    assert uc["spec"]["summary"] == "POV Pilot can't upload to Dropbox."      # back to the real name, on the laptop
    assert "POV Pilot" not in json.dumps(sent[0])
    assert uc["spec"]["changes"][0]["kind"] == "cloud_app_control"


def test_refine_replaces_the_proposal_and_keeps_history(pov, snaps, claude):
    sent, answers = claude
    uc = usecases.propose(pov, snaps, "No Dropbox uploads")
    usecases.set_status(pov, uc["id"], "accepted")
    answers.append(dict(ANSWER, changes=[dict(ANSWER["changes"][0], name="Caution Dropbox")]))
    uc2 = usecases.refine(pov, snaps, uc["id"], "Name it Caution Dropbox")
    assert uc2["id"] == uc["id"] and uc2["status"] == "proposed"               # out of the change list until accepted
    assert uc2["spec"]["changes"][0]["name"] == "Caution Dropbox"
    assert uc2["history"][0]["status"] == "accepted" and uc2["history"][0]["feedback"] == "Name it Caution Dropbox"
    assert "earlier proposal" in sent[-1]["messages"][0]["content"]
    with pytest.raises(KitError, match="what to change"):
        usecases.refine(pov, snaps, uc["id"], " ")


def test_library_strips_the_customer_and_reuses_without_ai(pov, snaps, claude, tmp_path):
    sent, _ = claude
    uc = usecases.propose(pov, snaps, "POV Pilot at Acme Corp can't upload to Dropbox")
    library.set_folder(str(tmp_path / "lib"))
    e = library.save(pov, uc, title="Block Dropbox uploads for Acme Corp")
    text = (tmp_path / "lib" / f"{e['id']}.json").read_text()
    assert "Acme Corp" not in text and "POV Pilot" not in text and "DROPBOX" in text and "[name]" in text
    n = len(sent)
    uc2 = library.use(pov, snaps, e["id"])
    assert len(sent) == n                                                     # no AI call
    assert uc2["from_library"] == e["id"] and uc2["spec"]["changes"][0]["applications"] == ["DROPBOX"]
    assert [x["id"] for x in library.entries()] == [e["id"]]


def test_direct_route_without_ai_guard(pov, monkeypatch):
    """No AI Guard proxy key: the SE's own Anthropic key, straight to api.anthropic.com, with its own agreement."""
    sent = []

    def transport(url, json=None, headers=None, timeout=None):
        sent.append((url, headers))
        return Reply({"content": [{"type": "text", "text": "hi"}]})
    monkeypatch.setattr(ai, "TRANSPORT", transport)
    monkeypatch.setattr(ai, "proxy_key", lambda: (None, "none"))
    assert ai.route()[0] is None and not ai.available()
    secrets.put(*ai.DIRECT_KEY, "sk-ant-test-0123456789abcdefghij")
    assert ai.route()[0] == "direct"
    with pytest.raises(KitError, match="directly to Anthropic"):
        ai.ask(pov, "s", "u")
    ai.record_consent(pov, "Jane Doe, CISO")
    assert pov.cfg["ai"]["consent"]["route"] == "direct"
    assert ai.ask(pov, "s", "u") == "hi"
    url, headers = sent[-1]
    assert url == "https://api.anthropic.com/v1/messages" and headers["x-api-key"].startswith("sk-ant-")
    assert "X-ApiKey" not in headers
    # an agreement for one route doesn't cover the other
    monkeypatch.setattr(ai, "proxy_key", lambda: ("proxy-key-123", "test"))
    assert ai.route()[0] == "aiguard" and ai.consent(pov) is None


def test_old_agreements_were_for_ai_guard(pov, monkeypatch):
    monkeypatch.setattr(ai, "proxy_key", lambda: ("proxy-key-123", "test"))
    pov.cfg["ai"] = {"consent": {"by": "Jane", "share": "names_only", "at": "2026-01-01T00:00:00Z"}}
    assert ai.consent(pov)


def test_console_saves_a_direct_key(pov, monkeypatch):
    from povkit import gui
    monkeypatch.setattr(ai, "proxy_key", lambda: (None, "none"))
    with pytest.raises(KitError, match="sk-ant-"):
        gui.api("POST", "/api/ai/key", {"key": "nope", "direct": True}, {})
    gui.api("POST", "/api/ai/key", {"key": "sk-ant-test-0123456789abcdefghij", "direct": True}, {})
    r = gui.api("GET", "/api/usecases", {}, {})[1]
    assert r["route"] == "direct" and r["direct"] and not r["proxy"]
    gui.api("POST", "/api/ai/key", {"direct": True, "remove": True}, {})
    assert not ai.direct_key()


def test_console_jobs_can_reach_ai():
    """A job's closure inside gui.api must see the module's `ai` (a local import there broke Ask Claude)."""
    from povkit import gui
    assert "ai" not in gui.api.__code__.co_varnames and gui.ai is ai


def test_a_model_that_refuses_forced_tools_is_asked_again(pov, monkeypatch):
    """The AI Guard proxy said: tool_choice type "tool" and "any" are not supported for this model."""
    calls = []

    class R:
        def __init__(self, code, body):
            self.status_code, self._b, self.text = code, body, json.dumps(body)

        def json(self):
            return self._b

    def transport(url, json=None, headers=None, timeout=None):
        calls.append(json)
        if json["tool_choice"]["type"] == "tool":
            return R(400, {"type": "error", "error": {"type": "invalid_request_error", "message":
                     'tool_choice: type "tool" and "any" are not supported for this model.'}})
        return R(200, {"content": [{"type": "tool_use", "name": "t", "input": {"ok": 1}}]})
    monkeypatch.setattr(ai, "TRANSPORT", transport)
    monkeypatch.setattr(ai, "NO_FORCED_TOOL", set())
    monkeypatch.setattr(ai, "proxy_key", lambda: ("proxy-key-123", "test"))
    tool = {"name": "t", "input_schema": {"type": "object"}}
    used, _ = ai.ask(pov, "s", "u", tool=tool, needs_consent=False)
    assert used == {"ok": 1} and [c["tool_choice"]["type"] for c in calls] == ["tool", "auto"]
    assert "calling the t tool" in calls[1]["system"]
    ai.ask(pov, "s", "u", tool=tool, needs_consent=False)       # remembered: straight to auto
    assert calls[-1]["tool_choice"]["type"] == "auto" and len(calls) == 3


def _resp(code, body):
    class R:
        status_code, text = code, (json.dumps(body) if body is not None else "")

        def json(self):
            return body
    return R()


def test_gateway_errors_are_retried(pov, monkeypatch):
    """The AI Guard proxy answered HTTP 502 with no body (seen live): ask again before giving up."""
    seq = [_resp(502, None), _resp(529, {"type": "error"}), _resp(200, {"content": [{"type": "text", "text": "hi"}]})]
    monkeypatch.setattr(ai, "TRANSPORT", lambda *a, **k: seq.pop(0))
    monkeypatch.setattr(ai, "RETRY_WAITS", (0, 0))
    monkeypatch.setattr(ai, "proxy_key", lambda: ("proxy-key-123", "test"))
    assert ai.ask(pov, "s", "u", needs_consent=False) == "hi" and not seq


def test_gateway_error_message_when_it_persists(pov, monkeypatch):
    calls = []
    monkeypatch.setattr(ai, "TRANSPORT", lambda *a, **k: calls.append(1) or _resp(502, None))
    monkeypatch.setattr(ai, "RETRY_WAITS", (0, 0))
    monkeypatch.setattr(ai, "proxy_key", lambda: ("proxy-key-123", "test"))
    try:
        ai.ask(pov, "s", "u", needs_consent=False)
        raise AssertionError("expected a KitError")
    except ai.KitError as e:
        assert len(calls) == 3 and "Bad Gateway" in str(e) and "no details" in str(e) and "try again" in str(e)
