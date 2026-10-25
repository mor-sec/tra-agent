"""The MCP servers over streamable HTTP, with delegation tokens and clearance from the token."""

import socket
import threading
import time

import pytest
import uvicorn

from tests.platform.conftest import ORCHESTRATOR, PORTAL_AUDIENCE
from tra_core.tools import ToolError, ToolSet
from tra_platform.auth import DelegationValidator, TokenValidator
from tra_platform.mcp import McpRoute, RoutedMcpToolClient, build_mcp_app, no_default_clearance


def _serve(app) -> tuple[uvicorn.Server, int]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            return server, port
        time.sleep(0.05)
    raise RuntimeError("server did not start")


@pytest.fixture
def mcp_servers(signer, reference, toolset):
    deployed = ToolSet(reference, toolset.artefacts, no_default_clearance)
    servers, routes = [], {}
    for which in ("reference", "artefacts"):
        aud = f"api://tra-mcp-{which}"
        delegation = DelegationValidator(TokenValidator(signer.issuer, aud, signer.keys), frozenset({ORCHESTRATOR}), which)
        server, port = _serve(build_mcp_app(which, deployed, delegation))
        servers.append(server)
        routes[which] = McpRoute(f"http://127.0.0.1:{port}/mcp", aud)
    yield routes
    for s in servers:
        s.should_exit = True


def _client(signer, routes, roles):
    user = signer.user_token("alice", roles, PORTAL_AUDIENCE)
    return RoutedMcpToolClient(routes, signer.exchanger(ORCHESTRATOR), user)


async def test_tools_over_http(signer, mcp_servers):
    client = _client(signer, mcp_servers, ["TRA.Practitioner", "TRA.Clearance.OfficialSensitive"])
    threats = await client.call("threats_search", {"applies_to": "process"})
    assert threats["threats"]
    artefact = await client.call("artefacts_get", {"source": "git", "locator": "payments-portal-design.md"})
    assert artefact["classification"] == "OFFICIAL_SENSITIVE"


async def test_clearance_comes_from_the_token(signer, mcp_servers):
    client = _client(signer, mcp_servers, ["TRA.Practitioner"])  # no clearance role: OFFICIAL
    with pytest.raises(ToolError, match="clearance"):
        await client.call("artefacts_get", {"source": "git", "locator": "payments-portal-design.md"})


async def test_mcp_refuses_wrong_caller(signer, mcp_servers):
    user = signer.user_token("alice", ["TRA.Practitioner"], PORTAL_AUDIENCE)
    client = RoutedMcpToolClient(mcp_servers, signer.exchanger("not-allowed"), user)
    with pytest.raises(ToolError, match="reference MCP server refused threats_get"):
        await client.call("threats_get", {"threat_id": "TL-001"})
