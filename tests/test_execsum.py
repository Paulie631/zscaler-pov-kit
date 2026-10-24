import io
import json
import zipfile

import pytest

from povkit import ai, execsum
from povkit.core import KitError

DRAFT = {"customer": {"headline": "{CUSTOMER} saw risky AI prompts blocked.", "situation": "{CUSTOMER} wanted proof.",
                      "results": ["Prompt injection blocked [AI-AIG-01]"], "ai_guard": "40 prompts tested.",
                      "value": ["Less data leakage risk"], "open": ["Secrets [AI-AIG-02]"],
                      "recommendation": "Move to production.", "next_steps": ["{CUSTOMER}: pick a pilot date"]},
         "internal": {"verdict": "Partial technical win.", "win_themes": ["Blocking works"], "risks": ["Secrets miss"],
                      "gaps_to_close": ["Re-run AI-AIG-02"], "competitive": [], "recommendation": "Push to close.",
                      "asks": ["AI Guard PM on the secrets miss"]}}


def _setup(pov, monkeypatch, seen=None):
    monkeypatch.setattr(execsum.evidence, "evaluate", lambda p, ids=None: [
        {"criterion": {"id": "AI-AIG-01", "title": "Prompt injection is blocked", "product": "aiguard"}, "status": "pass",
         "proofs": {"api": {"status": "pass", "detail": "4 of 4"}}},
        {"criterion": {"id": "AI-AIG-02", "title": "Secrets are caught", "product": "aiguard"}, "status": "fail",
         "proofs": {"api": {"status": "fail", "detail": "Stripe key missed"}}}])

    def ask(p, system, msg, **k):
        if seen is not None:
            seen.append(msg)
        return json.loads(json.dumps(DRAFT)), ""
    monkeypatch.setattr(ai, "ask", ask)


def test_write_and_render_both_versions(pov, monkeypatch):
    seen = []
    _setup(pov, monkeypatch, seen)
    s = execsum.write(pov, "lead with AI Guard", f"competitor is Netskope; {pov.cfg['customer']} CISO likes it", "Paul")
    assert pov.cfg["customer"] not in seen[0]           # the name never goes to Claude
    assert s["facts"]["criteria_totals"] == {"total": 2, "pass": 1, "fail": 1, "incomplete": 0}
    assert pov.read_json("summary.json")["headline"].startswith("{CUSTOMER}")   # the report's summary too
    for v in ("customer", "internal"):
        for f in ("docx", "pptx"):
            data = execsum.render(pov, v, f)
            z = zipfile.ZipFile(io.BytesIO(data))
            xml = "".join(z.read(n).decode("utf-8", "ignore") for n in z.namelist() if n.endswith(".xml"))
            assert pov.cfg["customer"] in xml and "{CUSTOMER}" not in xml
            assert ("INTERNAL" in xml) == (v == "internal")


def test_render_needs_a_draft(pov):
    with pytest.raises(KitError):
        execsum.render(pov, "customer", "docx")
    with pytest.raises(KitError):
        execsum.render(pov, "board", "docx")


def test_harmful_count_uses_latest_known_results(pov, monkeypatch):
    from povkit import aiguard_runner
    rows = [{"status": "ok", "id": "a", "provider": "anthropic", "expect": ["prompt_injection"], "pass": False},
            {"status": "ok", "id": "a", "provider": "anthropic", "expect": ["prompt_injection"], "pass": True},
            {"status": "ok", "id": "b", "provider": None, "expect": ["secrets"], "pass": None},      # unknown: skipped
            {"status": "ok", "id": "c", "provider": None, "expect": ["language"], "pass": True},     # not harmful
            {"status": "ok", "id": "d", "provider": "openai", "expect": ["pii"], "pass": False}]
    monkeypatch.setattr(aiguard_runner, "runs", lambda p, limit=500: rows)
    st = execsum.aiguard_stats(pov)
    assert (st["harmful_caught"], st["harmful_tests"], st["scans"]) == (1, 2, 5)
