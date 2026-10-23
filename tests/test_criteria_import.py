"""The customer's success criteria in: read files, split, map (Claude or keywords), build use cases, report."""
import io
import json
import time
import zipfile

from povkit import ai, criteria_import as ci, gui, lifecycle, report, usecases
from povkit.core.changelist import ChangeList


def docx(paras):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        body = "".join(f'<w:p><w:r><w:t>{p}</w:t></w:r></w:p>' for p in paras)
        z.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                   f"<w:body>{body}</w:body></w:document>")
    return b.getvalue()


def xlsx(rows):
    b = io.BytesIO()
    S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    strings = [c for r in rows for c in r]
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("xl/sharedStrings.xml", f'<sst xmlns="{S}">' + "".join(f"<si><t>{x}</t></si>" for x in strings) + "</sst>")
        i, out = 0, []
        for r in rows:
            cells = ""
            for _ in r:
                cells += f'<c t="s"><v>{i}</v></c>'
                i += 1
            out.append(f"<row>{cells}</row>")
        z.writestr("xl/worksheets/sheet1.xml", f'<worksheet xmlns="{S}"><sheetData>{"".join(out)}</sheetData></worksheet>')
    return b.getvalue()


def test_reads_word_excel_csv_and_splits():
    t = ci.read("plan.docx", docx(["Success criteria", "1. Block gambling and anonymizer sites for pilot users",
                                   "2. Inspect TLS traffic for the pilot group"]))
    assert ci.split(t) == ["Block gambling and anonymizer sites for pilot users", "Inspect TLS traffic for the pilot group"]
    t = ci.read("scorecard.xlsx", xlsx([["ID", "Requirement"], ["SC-1", "Detect prompt injection in our chatbot"]]))
    assert ci.split(t) == ["Detect prompt injection in our chatbot"]   # their IDs are dropped
    assert ci.split(ci.read("c.csv", b"Requirement\nPrevent card numbers leaving via webmail\n")) == [
        "Prevent card numbers leaving via webmail"]


def test_keyword_mapping_without_claude(pov_all):
    rows = ci.map_all(pov_all, ["Prompt injection is detected and blocked in our AI apps",
                                "Our CFO gets a weekly PDF of results by courier"], use_ai=False)
    assert rows[0]["catalog"] == ["AI-AIG-01"] and rows[0]["how"] == "keywords"
    assert not rows[1]["catalog"] and rows[1]["usecase"]


def test_claude_mapping_and_build(pov_all, tenant_for, monkeypatch):
    pov_all.cfg["ai"] = {"consent": {"by": "Jane", "share": "full", "at": "x"}, "share": "full"}
    pov_all.save()
    monkeypatch.setattr(ai, "proxy_key", lambda: ("k", "test"))
    calls = []

    def fake_ask(pov, system, user, max_tokens=4000, timeout=180, tool=None, needs_consent=True):
        calls.append(tool["name"])
        if tool["name"] == "map_criteria":
            return {"rows": [{"n": 1, "catalog": ["IS-URL-01", "BOGUS"]},
                             {"n": 2, "usecase": "Block uploads to personal Dropbox for the pilot group"},
                             {"n": 3, "out_of_scope": True, "note": "commercial"}]}, ""
        return {"summary": "Block Dropbox uploads", "changes": [
            {"kind": "url_filtering", "name": "Dropbox uploads", "action": "BLOCK", "urls": ["dropbox.com"]}],
            "directions": [], "test": {"title": "Dropbox upload blocked", "statement": "s",
                                       "probe": [{"type": "http", "url": "https://www.dropbox.com/", "expect": "block"}]}}, ""
    monkeypatch.setattr(ai, "ask", fake_ask)
    rows = ci.map_all(pov_all, ["Block gambling", "No uploads to personal Dropbox", "Price under budget"])
    assert rows[0]["catalog"] == ["IS-URL-01"] and rows[1]["usecase"] and rows[2]["out_of_scope"] and not rows[2]["include"]
    ci.save(pov_all, rows, "plan.docx")
    snaps, _ = lifecycle.discover(pov_all, tenant_for)
    res = ci.build(pov_all, snaps, rows)
    assert pov_all.cfg["criteria"] == ["IS-URL-01"]
    uc = usecases.get(pov_all, res["usecases"][0]) if res["usecases"] else None
    assert uc and uc["status"] == "accepted"
    assert ci.customer_view(pov_all)[uc["id"]] == ["No uploads to personal Dropbox"]
    items, *_ = lifecycle.plan(pov_all, tenant_for)
    assert any("UC" in i["name"] or i["key"].startswith("zia.uc") for i in items)
    html = report.render_report(pov_all, __import__("povkit").evidence.evaluate(pov_all), ChangeList(pov_all.dir).approval())
    assert "Your criterion: Block gambling" in html


def test_gui_flow(pov_all, tenant_for, monkeypatch):
    monkeypatch.setattr(gui, "tf", tenant_for)
    items = gui.api("POST", "/api/criteria/read", {"text": "- Block gambling sites for the pilot group\n- x"}, {})[1]["items"]
    assert items == ["Block gambling sites for the pilot group"]
    jid = gui.api("POST", "/api/criteria/map", {"items": items, "ai": False}, {})[1]["job"]
    for _ in range(200):
        if gui.JOBS[jid]["done"]:
            break
        time.sleep(0.02)
    assert gui.JOBS[jid]["error"] is None and gui.JOBS[jid]["result"]["rows"][0]["catalog"]
    assert gui.api("GET", "/api/criteria/import", {}, {})[1]["rows"]
    json.dumps(gui.api("GET", "/api/criteria/import", {}, {})[1])
