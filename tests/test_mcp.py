"""Claude Desktop's read-only access: no secret in the config, writes always off, gone at handover."""
import fnmatch
import json
import os

import pytest

from povkit import handover, mcp
from povkit.core import KitError, secrets


@pytest.fixture
def ready(pov_all):
    pov_all.cfg.update(vanity_domain="acme", customer_id="216199618143191041",
                       clients={"main": {"client_id": "main-id"}})
    pov_all.save()
    secrets.put(pov_all.id, "main-client-secret", "main-secret-value")
    return pov_all


def test_nothing_starts_without_the_customers_agreement(ready):
    with pytest.raises(KitError, match="hasn't agreed"):
        mcp.server_env(ready)
    with pytest.raises(KitError, match="hasn't agreed"):
        mcp.install(ready, "/nonexistent/never-written.json")


def test_the_server_starts_read_only_whatever_the_environment_says(ready, monkeypatch):
    mcp.record_consent(ready, "Jane Doe, CISO")
    monkeypatch.setenv("ZSCALER_MCP_WRITE_ENABLED", "true")
    monkeypatch.setenv("ZSCALER_MCP_WRITE_TOOLS", "*")
    env, why = mcp.server_env(ready)
    assert "ZSCALER_MCP_WRITE_ENABLED" not in env and "ZSCALER_MCP_WRITE_TOOLS" not in env
    assert env["ZSCALER_CLIENT_SECRET"] == "main-secret-value" and env["ZSCALER_CUSTOMER_ID"] == "216199618143191041"
    assert set(env["ZSCALER_MCP_SERVICES"].split(",")) == {"zia", "zins", "zcc", "zpa", "zdx", "zid"}
    assert "*_delete_*" in env["ZSCALER_MCP_DISABLED_TOOLS"] and "main client" in why
    cmd = mcp.command(ready)
    assert "--enable-write-tools" not in cmd and "--write-tools" not in cmd and "zscaler-mcp==0.15.4" in " ".join(cmd)
    ran = {}
    monkeypatch.setattr(os, "execvpe", lambda c, args, e: ran.update(cmd=args, env=e))
    monkeypatch.setattr(mcp.platform, "system", lambda: "Darwin")
    mcp.serve(ready)
    assert ran["cmd"] == cmd and "ZSCALER_MCP_WRITE_ENABLED" not in ran["env"]


def test_the_most_read_only_client_is_used(ready):
    assert mcp.slot(ready)[0] == "main"
    ready.cfg.update(client_mode="separate", clients={"discovery": {"client_id": "d"}, "apply": {"client_id": "a"}})
    assert mcp.slot(ready)[0] == "discovery"
    ready.cfg["clients"]["mcp"] = {"client_id": "m"}
    secrets.put(ready.id, "mcp-client-secret", "m-secret")
    assert mcp.slot(ready)[0] == "mcp"


def test_install_keeps_other_servers_holds_no_secret_and_handover_removes_it(ready, tmp_path, monkeypatch):
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(json.dumps({"mcpServers": {"zscaler": {"command": "uvx", "args": ["zscaler-mcp"]}}, "other": 1}))
    monkeypatch.setattr(mcp, "desktop_config", lambda: cfg)
    mcp.record_consent(ready, "Jane Doe, CISO")
    mcp.install(ready)
    data = json.loads(cfg.read_text())
    entry = data["mcpServers"][mcp.entry_name(ready)]
    assert entry["args"] == ["--pov", ready.id, "mcp", "serve"] and "env" not in entry
    from povkit.cli import parser
    assert parser().parse_args(entry["args"]).pov == ready.id                  # the CLI really accepts it
    assert parser().parse_args(["mcp", "serve", "--pov", ready.id]).pov == ready.id
    assert "main-secret-value" not in cfg.read_text() and "zscaler" in data["mcpServers"] and data["other"] == 1
    assert (tmp_path / "claude_desktop_config.json.zpov-backup").exists()
    assert {c["id"]: c for c in [mcp.status(ready)]}["mcp"]["status"] == "warn"   # main client: ask for a view-only one
    handover.finish(ready)
    data = json.loads(cfg.read_text())
    assert mcp.entry_name(ready) not in data["mcpServers"] and "zscaler" in data["mcpServers"]


def test_a_broken_config_file_is_never_touched(ready, tmp_path):
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text("{not json")
    mcp.record_consent(ready, "Jane Doe, CISO")
    with pytest.raises(KitError, match="isn't valid JSON"):
        mcp.install(ready, cfg)
    assert cfg.read_text() == "{not json"


def test_blocklist_covers_every_write_tool_of_the_pinned_server():
    docgen = pytest.importorskip("zscaler_mcp.common.docgen")
    tools = [t for ts in docgen.build_inventory().by_service().values() for t in ts]
    pats = mcp.NO_WRITES.split(",")
    writes = [t.name for t in tools if t.is_write]
    assert writes and not [w for w in writes if not any(fnmatch.fnmatch(w, p) for p in pats)]
    assert not [t.name for t in tools if not t.is_write and any(fnmatch.fnmatch(t.name, p) for p in pats)]
    blocked = [t.name for t in tools if any(fnmatch.fnmatch(t.name, p) for p in mcp.NO_SECRETS.split(","))]
    assert "zcc_get_device_otp" in blocked and "zpa_get_pra_credential" in blocked
