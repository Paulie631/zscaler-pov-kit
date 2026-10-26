"""zpov-mcp-server: a tiny MCP server (streamable HTTP, JSON responses) with one tool that returns canned, synthetic
answers. It's published on a Lambda function URL with no authentication on purpose, so AI-SPM can find an exposed MCP
server. It reads nothing and can reach nothing: its role only writes its own logs."""
import base64
import json

TOOLS = [{"name": "lookup_order", "description": "Look up an order's status (synthetic POV data).",
          "inputSchema": {"type": "object", "properties": {"order_id": {"type": "string"}}, "required": ["order_id"]}}]


def reply(code, obj=None):
    return {"statusCode": code, "headers": {"Content-Type": "application/json"}, "body": json.dumps(obj) if obj is not None else ""}


def handler(event, ctx):
    if (event.get("requestContext", {}).get("http", {}).get("method") or "POST") != "POST":
        return reply(405, {"error": "POST JSON-RPC to this URL (MCP streamable HTTP)."})
    raw = event.get("body") or "{}"
    try:
        msg = json.loads(base64.b64decode(raw) if event.get("isBase64Encoded") else raw)
    except ValueError:
        return reply(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
    mid, method = msg.get("id"), msg.get("method")
    if mid is None:   # a notification
        return reply(202)
    if method == "initialize":
        res = {"protocolVersion": (msg.get("params") or {}).get("protocolVersion") or "2025-06-18", "capabilities": {"tools": {}},
               "serverInfo": {"name": "zpov-mcp-server", "version": "1.0"}}
    elif method == "tools/list":
        res = {"tools": TOOLS}
    elif method == "tools/call":
        oid = ((msg.get("params") or {}).get("arguments") or {}).get("order_id", "?")
        res = {"content": [{"type": "text", "text": f"Order {oid}: shipped (synthetic POV data)."}]}
    elif method == "ping":
        res = {}
    else:
        return reply(200, {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"no method {method}"}})
    return reply(200, {"jsonrpc": "2.0", "id": mid, "result": res})
