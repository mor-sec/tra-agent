"""MCP over streamable HTTP for deployed runs: the authenticated server host and the client agents use.

Server side, `build_mcp_app` serves one of the core's MCP servers (reference or
artefacts) at `/mcp`, stateless, with JSON responses. That matches the AgentCore
Runtime MCP contract (port 8000, `/mcp`) and runs as-is in Azure Container Apps.
`DelegationMiddleware` validates the caller's delegation token on every request
and keeps the user Principal on the request, where `artefacts_get` reads the
user's clearance. A caller's clearance never comes from a header it chose.

Client side, `RoutedMcpToolClient` sends each tool to the server that owns it,
exchanging the caller's token for one addressed to that server first.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from starlette.applications import Starlette

from tra_core.identity import Principal
from tra_core.mcp_servers import build_artefacts_server, build_reference_server
from tra_core.schemas import Classification
from tra_core.tools import JSON, McpToolClient, ToolError, ToolSet
from tra_platform.a2a import DelegationMiddleware
from tra_platform.auth import DelegationValidator, TokenExchanger

SERVER_FOR_TOOL = {
    "threats_search": "reference",
    "threats_get": "reference",
    "controls_lookup": "reference",
    "controls_list": "reference",
    "artefacts_get": "artefacts",
    "artefacts_list": "artefacts",
}


def _caller(ctx: Any) -> Principal:
    request = ctx.request_context.request
    return request.scope["state"]["principal"]


def build_mcp_app(which: str, toolset: ToolSet, delegation: DelegationValidator) -> Starlette:
    from mcp.server.transport_security import TransportSecuritySettings

    if which == "reference":
        server = build_reference_server(toolset)
    else:
        server = build_artefacts_server(toolset, lambda ctx: _caller(ctx).clearance)
    app = server.streamable_http_app(
        stateless_http=True,
        json_response=True,
        # Every request carries a validated bearer token, and the platform fronts
        # the container, so Host-header DNS-rebinding checks add nothing here.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    app.add_middleware(DelegationMiddleware, check=delegation.user)
    return app


@dataclass(frozen=True)
class McpRoute:
    url: str  # the server's /mcp endpoint (AgentCore: the runtime invocation URL)
    audience: str


class RoutedMcpToolClient:
    """A `ToolClient` over remote MCP servers, acting for the user behind `subject_token`."""

    def __init__(
        self,
        routes: dict[str, McpRoute],
        exchanger: TokenExchanger,
        subject_token: str,
        http_client_factory: Callable[[dict[str, str]], Any] | None = None,
    ) -> None:
        self.routes = routes
        self.exchanger = exchanger
        self.subject_token = subject_token
        self.http_client_factory = http_client_factory

    async def call(self, name: str, args: dict[str, Any]) -> JSON:
        from mcp.client.streamable_http import streamable_http_client
        from mcp.shared._httpx_utils import create_mcp_http_client

        route = self.routes[SERVER_FOR_TOOL[name]]
        token = await self.exchanger.exchange(self.subject_token, route.audience)
        headers = {"Authorization": f"Bearer {token}"}
        http = self.http_client_factory(headers) if self.http_client_factory else create_mcp_http_client(headers)
        try:
            async with http:
                return await McpToolClient(streamable_http_client(route.url, http_client=http)).call(name, args)
        except BaseExceptionGroup as group:
            # The MCP client reports transport and auth failures as nested task-group errors.
            leaf = _first_leaf(group)
            if isinstance(leaf, ToolError):
                raise leaf from group
            raise ToolError(f"{SERVER_FOR_TOOL[name]} MCP server refused {name}: {leaf!r}") from group


def _first_leaf(exc: BaseException) -> BaseException:
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return exc


def no_default_clearance() -> Classification:
    """`ToolSet.clearance_of` for deployed hosts: the caller's clearance must come from its token."""
    raise PermissionError("no caller clearance on this request")
