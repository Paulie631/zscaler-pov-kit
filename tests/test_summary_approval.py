"""The executive summary sees results only; the customer's own approval file is bound to the change list."""
import json

import pytest

from povkit import ai, lifecycle, summary
from povkit.core import KitError, secrets
from povkit.core.changelist import ChangeList
from povkit.report import render_plan, render_report


class Reply:
    status_code = 200

    def __init__(self, body):
        self._body, self.text = body, json.dumps(body)

    def json(self):
        return self._body


SUMMARY = {"headline": "The customer's pilot users were protected on day one.", "proved": ["Blocking works [IS-URL-01]"],
           "open": ["Malware proof is still to run [IS-THR-01]"], "value": ["Less risk from risky sites"],
           "next_steps": ["Finish the probe run", "Hand over with the Terraform export"]}


def test_summary_sends_results_only_and_opens_the_report(pov, tenant_for, monkeypatch):
    sent = []
    monkeypatch.setattr(ai, "TRANSPORT", lambda url, json=None, **k: (sent.append(json), Reply(
        {"content": [{"type": "tool_use", "name": "write_summary", "input": SUMMARY}]}))[1])
    lifecycle.discover(pov, tenant_for)
    with pytest.raises(KitError, match="proxy key"):
        summary.write(pov)
    secrets.put(*ai.OWN_KEY, "proxy-key-123")
    s = summary.write(pov)                                                    # no use-case agreement needed
    msg = sent[0]["messages"][0]["content"]
    assert "IS-URL-01" in msg and "Acme Corp" not in msg and "POV Pilot" not in msg and "Corp: Block adult" not in msg
    assert s["headline"].startswith("The customer's")
    html = render_report(pov, __import__("povkit").evidence.evaluate(pov), None)
    assert "Executive summary" in html and "Hand over with the Terraform export" in html
    assert summary.current(pov)[1] is False


def test_customer_approval_file_is_checked_against_the_plan(pov, tenant_for, tmp_path):
    items, notes, h, _ = lifecycle.plan(pov, tenant_for)
    page = render_plan(pov, items, notes, h)
    assert "Approve and save the approval file" in page and h in page        # the full hash is on the page
    rec = {"format": "zpov-approval-1", "pov": pov.id, "hash": h, "by": "Jane Doe", "title": "CISO",
           "email": "jane@acme.com", "note": "", "at": "2026-10-22T12:00:00Z"}
    f = tmp_path / "approval.json"
    f.write_text(json.dumps(dict(rec, hash="0" * 64)))
    with pytest.raises(KitError, match="different change list"):
        ChangeList(pov.dir).approve_file(f)
    f.write_text(json.dumps(dict(rec, title="")))
    with pytest.raises(KitError, match="no name or title"):
        ChangeList(pov.dir).approve_file(f)
    f.write_text(json.dumps(rec))
    a = ChangeList(pov.dir).approve_file(f)
    assert a["by"] == "Jane Doe, CISO" and a["via"] == "customer page" and a["hash"] == h
    lifecycle.apply(pov, tenant_for, lambda *x: None)                         # the approval is good for apply
