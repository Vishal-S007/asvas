"""PL-08: read-only MCP server — authenticated, tenant-scoped, audited; never creates or changes anything."""

from __future__ import annotations

import asyncio
import json
import os
import sys

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

from asvas.auth import issue_token, lookup_user
from asvas.db import rows, tenant_tx
from asvas.mcp_server import build_server
from tests.test_lifecycle import tid_of


def _tok(email="operator@acme.test"):
    u = lookup_user(email=email)
    return issue_token(u["id"], u["tenant_id"], u["role"])


def _call(server, name, args=None):
    async def go():
        async with Client(server) as c:
            tools = {t.name: t for t in (await c.list_tools()).tools}
            r = await c.call_tool(name, args or {})
            return tools, r
    return asyncio.run(go())


def _data(r):
    if r.structured_content is not None:
        sc = r.structured_content
        return sc.get("result", sc) if isinstance(sc, dict) else sc
    return json.loads(r.content[0].text)


def test_tools_are_read_only_and_catalogues_served(clean):
    tools, r = _call(build_server(_tok()), "list_security_tools")
    assert set(tools) == {"list_security_tools", "list_finding_rules", "get_planning_context", "validate_step"}
    assert all(t.annotations.read_only_hint and not t.annotations.destructive_hint for t in tools.values())
    assert {t["tool_id"] for t in _data(r)} >= {"http.security_headers"}
    _, r = _call(build_server(_tok()), "list_finding_rules")
    assert any(x["rule_id"] == "HDR-CSP" and x["cwe"] == "CWE-693" for x in _data(r))
    with tenant_tx(tid_of()) as conn:
        assert rows(conn, "SELECT count(*) AS n FROM audit_events WHERE event_type = 'mcp.tool_called'")[0]["n"] == 2


def test_unauthenticated_calls_refused(clean):
    _, r = _call(build_server(""), "list_security_tools")
    assert r.is_error and "ASVAS_MCP_TOKEN" in r.content[0].text
    _, r = _call(build_server("not-a-token"), "list_security_tools")
    assert r.is_error and "token rejected" in r.content[0].text


def test_planning_context_is_tenant_scoped(client, make_assessment):
    a = make_assessment()
    _, r = _call(build_server(_tok()), "get_planning_context", {"assessment_id": a["id"]})
    d = _data(r)
    assert not r.is_error and d["assessment_id"] == a["id"] and "untrusted_observations" in d
    _, r = _call(build_server(_tok("operator@globex.test")), "get_planning_context", {"assessment_id": a["id"]})
    assert r.is_error and "not found in your tenant" in r.content[0].text


def test_validate_step_is_dry_run(client, make_assessment):
    a = make_assessment(ports=(18080,))
    ok = {"assessment_id": a["id"], "tool_id": "http.security_headers", "scheme": "http", "host": "127.0.0.1",
          "port": 18080, "params": {"path": "/"}}
    _, r = _call(build_server(_tok()), "validate_step", ok)
    assert _data(r)["valid"] is True
    _, r = _call(build_server(_tok()), "validate_step", {**ok, "host": "8.8.8.8"})
    assert _data(r)["valid"] is False and _data(r)["reasons"]
    _, r = _call(build_server(_tok()), "validate_step", {**ok, "agent": "discovery"})
    assert _data(r)["valid"] is False and any("sub-schema" in x for x in _data(r)["reasons"])
    with tenant_tx(tid_of()) as conn:
        assert rows(conn, "SELECT count(*) AS n FROM jobs")[0]["n"] == 0  # nothing created


def test_stdio_transport_end_to_end(clean):
    env = {**os.environ, "ASVAS_MCP_TOKEN": _tok()}
    params = StdioServerParameters(command=sys.executable, args=["-m", "asvas.cli", "mcp"], env=env,
                                   cwd=os.path.dirname(os.path.dirname(__file__)))
    tools, r = _call(params, "list_finding_rules")
    assert "validate_step" in tools and not r.is_error and len(_data(r)) == 12
