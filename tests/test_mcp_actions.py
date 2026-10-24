"""Claude Desktop making changes through the kit: two agreements, MCP over stdio, changes land in the change list."""
import io
import json

import pytest

from povkit import cli, mcp, mcp_actions, usecases
from povkit.core import KitError


@pytest.fixture
def agreed(pov, tenant, tenant_for, monkeypatch, tmp_path):
    tenant.actions["FILE_SHARE"].append("BLOCK_FILE_SHARE_UPLOAD")
    monkeypatch.setattr(cli, "tenant_for", tenant_for)
    mcp.record_consent(pov, "Jane Doe, CISO")
    mcp_actions.record_actions_consent(pov, "Jane Doe, CISO")
    return pov


def rpc(pov, *msgs):
    inp = io.StringIO("".join(json.dumps(m) + "\n" for m in msgs))
    out = io.StringIO()
    mcp_actions.serve(pov, inp, out)
    return [json.loads(x) for x in out.getvalue().splitlines()]


PROPOSAL = {"summary": "POV Pilot can't upload to Dropbox.", "changes": [
    {"kind": "cloud_app_control", "name": "No Dropbox uploads", "rule_type": "FILE_SHARE", "applications": ["DROPBOX"],
     "actions": ["BLOCK_FILE_SHARE_UPLOAD"]},
    {"kind": "url_filtering", "name": "Bad", "action": "DESTROY", "url_categories": ["GAMBLING"]}],
    "directions": [], "test": {"title": "Uploads blocked", "statement": "", "probe": [], "aiguard": [],
                               "attest": "Try an upload."}}


def test_needs_both_agreements(pov):
    with pytest.raises(KitError, match="reading"):
        mcp_actions.ready(pov)
    mcp.record_consent(pov, "Jane")
    with pytest.raises(KitError, match="making changes"):
        mcp_actions.ready(pov)


def test_protocol_and_tools(agreed):
    r = rpc(agreed, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert len(r) == 2 and r[0]["result"]["capabilities"] == {"tools": {}}
    names = {t["name"] for t in r[1]["result"]["tools"]}
    assert {"propose_change", "set_aiguard_policy", "run_aiguard_tests", "fix_drift", "check_status"} <= names
    assert not {n for n in names if "apply" in n}            # Claude can't apply


def test_propose_change_goes_to_the_change_list(agreed):
    r = rpc(agreed, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "propose_change", "arguments": {
        "use_case": "Pilot users can open Dropbox but not upload", "proposal": PROPOSAL}}})
    res = r[0]["result"]
    assert not res["isError"], res
    body = json.loads(res["content"][0]["text"])
    assert [c["kind"] for c in body["added_to_change_list"]] == ["cloud_app_control"]   # the bad one was refused
    assert any("isn't one of" in " ".join(d["steps"]) for d in body["directions_for_a_person"])
    uc = usecases.load(agreed)[-1]
    assert uc["status"] == "accepted" and uc["by"] == "Claude Desktop"
    r = rpc(agreed, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                     "params": {"name": "withdraw_change", "arguments": {"id": uc["id"]}}})
    assert not r[0]["result"]["isError"] and usecases.load(agreed)[-1]["status"] == "discarded"


def test_errors_come_back_as_tool_errors(agreed):
    r = rpc(agreed, {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "propose_change",
                                                                                   "arguments": {}}},
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "nope"}})
    assert r[0]["result"]["isError"] and "use case" in r[0]["result"]["content"][0]["text"]
    assert r[1]["error"]["code"] == -32602


def test_desktop_entry(agreed, tmp_path):
    cfgf = tmp_path / "claude_desktop_config.json"
    mcp.install_actions(agreed, cfgf)
    cfg = json.loads(cfgf.read_text())
    entry = cfg["mcpServers"][mcp.actions_entry_name(agreed)]
    assert entry["args"][-2:] == ["mcp", "actions"] and "env" not in entry
    agreed.cfg["mcp"]["installed"] = str(cfgf)
    mcp.remove(agreed, cfgf)
    assert mcp.actions_entry_name(agreed) not in json.loads(cfgf.read_text())["mcpServers"]
