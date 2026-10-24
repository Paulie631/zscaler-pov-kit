"""Read-only access to the POV tenant from Claude, through Zscaler's own MCP server (PyPI: zscaler-mcp).

During a POV most questions are reads: why a pilot user was blocked, which apps the pilot group used, why a device's
ZDX score dropped. `pov-kit mcp install` adds one entry to Claude Desktop's config, named zscaler-pov-<pov-id>, that
runs `pov-kit --pov <id> mcp serve`. That command:

  - takes the POV's credentials from the keychain at start-up, so the config file holds no secret
  - uses the most read-only client the POV has: a dedicated view-only 'mcp' client (`pov-kit connect --mcp`), else the
    view-only discovery client (two-client mode), else the main client, whose write access the server never uses
  - starts the server with writes off: it never passes --enable-write-tools or a write allowlist, removes the
    ZSCALER_MCP_WRITE_* variables from the environment, and also disables every tool whose name creates, updates,
    deletes or activates, so a future default can't turn writes on, and the reads that return secrets (a device's
    one-time password, PRA and VPN credentials)
  - limits the server to the POV's products
  - refuses to start until the customer has agreed (recorded per POV): these requests go from Claude Desktop to
    Anthropic directly, not through AI Guard, and nothing replaces the customer's names

Writes to the tenant still go only through the approved change list. Handover removes the Claude Desktop entry and
the 'mcp' client's secret with everything else.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .core import KitError, secrets

PACKAGE = "zscaler-mcp"
VERSION = "0.15.4"                      # pinned; `pov-kit set mcp.version` to move it after testing
SERVICES = {"zia": ["zia", "zins"], "zcc": ["zcc"], "zpa": ["zpa"], "zdx": ["zdx"], "casb": ["zia"]}
# every write tool zscaler-mcp 0.15.4 has (148 of 402) matches one of these; tests/test_mcp.py checks it when the
# package is installed
NO_WRITES = ("*_create_*,*_add_*,*_update_*,*_patch_*,*_delete_*,*_remove_*,*activate*,*_bulk_*,*_regenerate_*,"
             "*_start_*")
# reads that return secrets: a device's one-time password (it can turn Client Connector off), PRA and VPN credentials
NO_SECRETS = "*_otp*,*credential*,*_password*,*_secret*"
DISABLED = NO_WRITES + "," + NO_SECRETS
SCRUB = ("ZSCALER_MCP_WRITE_ENABLED", "ZSCALER_MCP_WRITE_TOOLS", "ZSCALER_MCP_DISABLE_OUTPUT_SANITIZATION",
         "ZSCALER_MCP_DISABLE_ENTITLEMENT_FILTER")


def entry_name(pov):
    return f"zscaler-pov-{pov.id}"


def actions_entry_name(pov):
    return f"zscaler-pov-{pov.id}-actions"


def desktop_config() -> Path:
    sysname = platform.system()
    if sysname == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if sysname == "Windows":
        return Path(os.getenv("APPDATA", str(Path.home()))) / "Claude" / "claude_desktop_config.json"
    return Path.home() / ".config" / "Claude" / "claude_desktop_config.json"


def launcher() -> Path:
    root = Path(__file__).resolve().parent.parent
    return root / ("pov-kit.cmd" if platform.system() == "Windows" else "pov-kit")


# ---------------------------------------------------------------- agreement and credentials
def consent(pov):
    return (pov.cfg.get("mcp") or {}).get("consent")


def record_consent(pov, by):
    by = (by or "").strip()
    if not by:
        raise KitError("Say who at the customer agreed (name and title).")
    pov.cfg.setdefault("mcp", {})["consent"] = {"by": by, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    pov.save()
    pov.log("mcp", f"customer agreed to read-only Claude Desktop access to the tenant ({by})")


def slot(pov):
    """The most read-only saved client: (slot, why)."""
    clients = pov.cfg.get("clients") or {}
    if (clients.get("mcp") or {}).get("client_id") and secrets.get(pov.id, "mcp-client-secret"):
        return "mcp", "the POV's view-only MCP client"
    if pov.cfg.get("client_mode") == "separate" and (clients.get("discovery") or {}).get("client_id"):
        return "discovery", "the view-only discovery client"
    return "main", ("the POV's main client (it can write, but the MCP server runs with every write tool off; a "
                    "view-only client is better: `pov-kit connect --mcp`)")


def services(pov):
    out = []
    for p in pov.products:
        out += [s for s in SERVICES.get(p, []) if s not in out]
    if "zia" in out or "zpa" in out:
        out.append("zid")   # ZIdentity: who the pilot users are
    return out


def server_env(pov):
    """The environment the server starts with. -> (env, what it uses)"""
    if not consent(pov):
        raise KitError(f"The customer hasn't agreed to read-only Claude Desktop access to {pov.cfg['customer']}'s "
                       "tenant. Record it first: `pov-kit mcp consent --by \"Name, title\"`.")
    s, why = slot(pov)
    cl = (pov.cfg.get("clients") or {}).get(s) or {}
    secret = secrets.get(pov.id, f"{s}-client-secret")
    if not (cl.get("client_id") and secret and pov.cfg.get("vanity_domain")):
        raise KitError(f"No API client saved for this POV ({s}). Run `pov-kit connect` first.")
    env = {k: v for k, v in os.environ.items() if k not in SCRUB}
    env.update(ZSCALER_CLIENT_ID=cl["client_id"], ZSCALER_CLIENT_SECRET=secret,
               ZSCALER_VANITY_DOMAIN=pov.cfg["vanity_domain"], ZSCALER_MCP_SERVICES=",".join(services(pov)),
               ZSCALER_MCP_DISABLED_TOOLS=DISABLED, ZSCALER_MCP_TRANSPORT="stdio")
    if pov.cfg.get("cloud"):
        env["ZSCALER_CLOUD"] = pov.cfg["cloud"]
    if pov.cfg.get("customer_id"):
        env["ZSCALER_CUSTOMER_ID"] = str(pov.cfg["customer_id"])
    return env, why


def find_uvx():
    """Claude Desktop starts servers with a short PATH, so look where uv installs too (as the launcher does)."""
    name = "uvx.exe" if platform.system() == "Windows" else "uvx"
    for c in (shutil.which("uvx"), Path.home() / ".local" / "bin" / name, Path.home() / ".cargo" / "bin" / name,
              Path("/opt/homebrew/bin/uvx"), Path("/usr/local/bin/uvx")):
        if c and Path(c).exists():
            return str(c)
    raise KitError("uvx (part of uv) isn't installed: `brew install uv`, or see docs.astral.sh/uv.")


def command(pov):
    """The server's command line: never --enable-write-tools or --write-tools."""
    version = (pov.cfg.get("mcp") or {}).get("version") or VERSION
    uvx = find_uvx()
    cmd = [uvx, "--from", f"{PACKAGE}=={version}", "zscaler-mcp", "--services", ",".join(services(pov)),
           "--disabled-tools", DISABLED, "--transport", "stdio"]
    assert not any("write" in c for c in cmd)
    return cmd


def serve(pov):
    """Run the server on this process's stdin and stdout (Claude Desktop talks to it there)."""
    env, why = server_env(pov)
    cmd = command(pov)
    print(f"pov-kit: read-only Zscaler MCP server for {pov.id}, using {why}; services "
          f"{env['ZSCALER_MCP_SERVICES']}", file=sys.stderr)
    pov.log("mcp", f"read-only MCP server started ({env['ZSCALER_MCP_SERVICES']})")
    if platform.system() == "Windows":
        return subprocess.call(cmd, env=env)
    os.execvpe(cmd[0], cmd, env)   # replaces this process: stdin and stdout stay Claude Desktop's


# ---------------------------------------------------------------- Claude Desktop's config
def snippet(pov):
    """The config entry, for Claude Desktop or any MCP client. It carries no secret."""
    return {entry_name(pov): {"command": str(launcher()), "args": ["--pov", pov.id, "mcp", "serve"]}}


def _read(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8") or "{}")
    except ValueError as e:
        raise KitError(f"Claude Desktop's config ({path}) isn't valid JSON, so the kit won't touch it: {e}") from e


def _write(path, cfg):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + ".zpov-backup"))   # one step back, always
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    tmp.replace(path)


def actions_snippet(pov):
    """The changes connector (mcp_actions): the kit's own actions, through the change list. No secret in it."""
    return {actions_entry_name(pov): {"command": str(launcher()), "args": ["--pov", pov.id, "mcp", "actions"]}}


def install_actions(pov, path=None):
    from . import mcp_actions
    mcp_actions.ready(pov)
    path = Path(path) if path else desktop_config()
    cfg = _read(path)
    cfg.setdefault("mcpServers", {}).update(actions_snippet(pov))
    _write(path, cfg)
    pov.cfg.setdefault("mcp", {})["actions_installed"] = str(path)
    pov.save()
    pov.log("mcp", f"Claude Desktop entry {actions_entry_name(pov)} added (changes through the change list)")
    return path


def remove_actions(pov, path=None):
    path = Path(path) if path else Path((pov.cfg.get("mcp") or {}).get("actions_installed") or desktop_config())
    cfg = _read(path)
    servers = cfg.get("mcpServers") or {}
    if actions_entry_name(pov) not in servers:
        return False
    del servers[actions_entry_name(pov)]
    _write(path, cfg)
    (pov.cfg.get("mcp") or {}).pop("actions_installed", None)
    pov.save()
    pov.log("mcp", f"Claude Desktop entry {actions_entry_name(pov)} removed")
    return True


def install(pov, path=None):
    server_env(pov)   # refuses without the customer's agreement and a saved client
    path = Path(path) if path else desktop_config()
    cfg = _read(path)
    cfg.setdefault("mcpServers", {}).update(snippet(pov))
    _write(path, cfg)
    pov.cfg.setdefault("mcp", {})["installed"] = str(path)
    pov.save()
    pov.log("mcp", f"Claude Desktop entry {entry_name(pov)} added")
    return path


def remove(pov, path=None):
    """Removes the read-only entry, and the changes entry with it (it needs the read-only agreement anyway)."""
    try:
        remove_actions(pov, path)
    except KitError:
        pass
    path = Path(path) if path else Path((pov.cfg.get("mcp") or {}).get("installed") or desktop_config())
    cfg = _read(path)
    servers = cfg.get("mcpServers") or {}
    if entry_name(pov) not in servers:
        return False
    del servers[entry_name(pov)]
    _write(path, cfg)
    (pov.cfg.get("mcp") or {}).pop("installed", None)
    pov.save()
    pov.log("mcp", f"Claude Desktop entry {entry_name(pov)} removed")
    return True


def desktop_client():
    """The OneAPI client a Zscaler MCP server in Claude Desktop uses, for `connect --from-claude-desktop`.
    -> {server, client_id, secret, vanity_domain, cloud, customer_id} or None. Read on this laptop only; the secret
    goes to the keychain and is never printed, logged or sent anywhere."""
    try:
        servers = _read(desktop_config()).get("mcpServers") or {}
    except KitError:
        return None
    for name in sorted(servers, key=lambda n: (n != "zscaler", n)):   # the plain 'zscaler' server first
        env = (servers[name] or {}).get("env") or {}
        if name.startswith("zscaler-pov-") or not (env.get("ZSCALER_CLIENT_ID") and env.get("ZSCALER_CLIENT_SECRET")):
            continue
        vanity = str(env.get("ZSCALER_VANITY_DOMAIN") or "").replace("https://", "").split("/")[0].replace(".zslogin.net", "")
        return {"server": name, "client_id": env["ZSCALER_CLIENT_ID"], "secret": env["ZSCALER_CLIENT_SECRET"],
                "vanity_domain": vanity, "cloud": env.get("ZSCALER_CLOUD") or "",
                "customer_id": env.get("ZSCALER_CUSTOMER_ID") or ""}
    return None


def use_desktop_client(pov, slot="main"):
    """Save the Claude Desktop Zscaler MCP client as this POV's client. -> the server it came from."""
    from . import settings
    c = desktop_client()
    if not c:
        raise KitError("No Zscaler MCP server with a OneAPI client (ZSCALER_CLIENT_ID and ZSCALER_CLIENT_SECRET) in "
                       f"Claude Desktop's config ({desktop_config()}).")
    if not c["vanity_domain"]:
        raise KitError(f"The '{c['server']}' MCP server has no ZSCALER_VANITY_DOMAIN; enter the client in Connect instead.")
    secrets.put(pov.id, f"{slot}-client-secret", c["secret"])
    pov.cfg.setdefault("clients", {})[slot] = {"client_id": c["client_id"], "from": f"Claude Desktop ({c['server']})"}
    settings.set_value(pov, "vanity_domain", c["vanity_domain"], save=False)
    if c["cloud"] and c["cloud"].lower() != "production":
        settings.set_value(pov, "cloud", c["cloud"], save=False)
    if c["customer_id"] and not pov.cfg.get("customer_id"):
        settings.set_value(pov, "customer_id", c["customer_id"], save=False)
    pov.save()
    pov.log("connect", f"{slot} client taken from Claude Desktop's '{c['server']}' MCP server")
    return c["server"]


def status(pov):
    from .core.checks import INFO, OK, WARN
    from .core.checks import check as mk
    inst = (pov.cfg.get("mcp") or {}).get("installed")
    if not inst:
        return mk("mcp", "Claude Desktop read-only access", INFO, "not set up",
                  "Optional: Next steps > Ask Claude about this tenant (record the customer's agreement, then Add to "
                  "Claude Desktop).")
    s, why = slot(pov)
    acts = (pov.cfg.get("mcp") or {}).get("actions_installed")
    return mk("mcp", "Claude Desktop read-only access", OK if s != "main" else WARN, f"{entry_name(pov)}, using {why}"
              + (f"; changes through the change list too ({actions_entry_name(pov)})" if acts else ""),
              "" if s != "main" else "Ask the customer for a view-only client for it: `pov-kit connect --mcp`.")
