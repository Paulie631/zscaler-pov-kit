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
