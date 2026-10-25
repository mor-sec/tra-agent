"""A2A (v1.0 JSON-RPC) hosting for specialists, and the client transport the orchestrator uses.

Each specialist is its own A2A agent with an agent card. A request is one A2A
message with a single JSON text part (media type `application/json`) holding
the `SpecialistRequest`; the reply is one agent message holding the host's
result the same way. JSON text rather than an A2A data part, because data parts
travel as protobuf `Value`s, which turn integers into floats and would break the
audit event hashes. No tasks
or streaming: every specialist call is short and synchronous, and the
orchestrator owns all state.

The delegation token arrives as the bearer token. On AgentCore the runtime's
inbound JWT authorizer has already checked it; `DelegationMiddleware` checks it
again, so a container started without an authorizer still refuses callers.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from tra_core.identity import Principal
from tra_platform.auth import AuthError, bearer
from tra_platform.host import SpecialistHost

JSON = "application/json"
AGENT_CARD_PATH = "/.well-known/agent-card.json"
UNAUTHENTICATED_PATHS = frozenset({"/ping", AGENT_CARD_PATH})
DESCRIPTIONS = {
    "intake": "Scopes a TRA from design artefacts: system, data, classification, triggers.",
    "system_modeller": "Builds the data flow model: elements, flows, trust zones, assets.",
    "threat_analyst": "Identifies threats per element with STRIDE and MITRE ATLAS.",
    "control_mapper": "Assesses existing and proposed controls against the threats.",
    "risk_assessor": "Proposes likelihood and impact for each risk, with rationale.",
    "quality_critic": "Reviews the draft for gaps, inconsistencies and injected instructions.",
}


class DelegationMiddleware:
    """Rejects requests without a valid delegation token before any protocol parsing starts.

    `check` validates a token and returns the user it acts for. The token and
    that Principal are kept on the request scope for the handler.
    """

    def __init__(self, app: ASGIApp, check: Callable[[str], Principal], header: str = "authorization") -> None:
        self.app = app
        self.check = check
        self.header = header

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in UNAUTHENTICATED_PATHS:
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        try:
            raw = request.headers.get(self.header)
            token = bearer(raw) if self.header == "authorization" else (raw or "")
            principal = self.check(token)
        except AuthError as exc:
            await JSONResponse({"error": "unauthorized", "detail": str(exc)}, status_code=401)(scope, receive, send)
            return
        scope.setdefault("state", {}).update(delegation_token=token, principal=principal)
        await self.app(scope, receive, send)


def agent_card(agent: str, url: str) -> Any:
    from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill

    description = DESCRIPTIONS.get(agent, agent)
    return AgentCard(
        name=f"tra-{agent.replace('_', '-')}",
        description=description,
        version="0.2.0",
        capabilities=AgentCapabilities(streaming=False),
        skills=[AgentSkill(id=agent, name=agent, description=description, tags=["tra"])],
        default_input_modes=["application/json"],
        default_output_modes=["application/json"],
        supported_interfaces=[AgentInterface(protocol_binding="JSONRPC", protocol_version="1.0", url=url)],
    )


def build_a2a_app(host: SpecialistHost, public_url: str, auth_header: str = "authorization") -> Starlette:
    """A Starlette app serving the agent card, JSON-RPC at `/`, and `/ping` for AgentCore health checks."""
    from a2a.helpers.proto_helpers import get_text_parts, new_text_message
    from a2a.server.agent_execution import AgentExecutor, RequestContext
    from a2a.server.events.event_queue_v2 import EventQueue
    from a2a.server.request_handlers import DefaultRequestHandler
    from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
    from a2a.server.routes.common import DefaultServerCallContextBuilder
    from a2a.server.tasks import InMemoryTaskStore

    class ContextBuilder(DefaultServerCallContextBuilder):
        def build(self, request: Request) -> Any:
            context = super().build(request)
            context.state["delegation_token"] = request.scope.get("state", {}).get("delegation_token", "")
            return context

    class SpecialistExecutor(AgentExecutor):
        async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
            parts = get_text_parts(context.message.parts) if context.message else []
            try:
                body = json.loads(parts[0]) if len(parts) == 1 else None
            except json.JSONDecodeError:
                body = None
            if not isinstance(body, dict):
                result: dict[str, Any] = {"status": "failed", "error": "expected one JSON text part", "audit": []}
            else:
                result = await host.handle(body, context.call_context.state["delegation_token"])
            reply = new_text_message(json.dumps(result), media_type=JSON, context_id=context.context_id)
            await event_queue.enqueue_event(reply)

        async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
            raise NotImplementedError("specialist calls are not cancellable")

    card = agent_card(host.agent, public_url)
    handler = DefaultRequestHandler(agent_executor=SpecialistExecutor(), task_store=InMemoryTaskStore(), agent_card=card)
    routes = [
        Route("/ping", lambda _: JSONResponse({"status": "Healthy"}), methods=["GET"]),
        *create_agent_card_routes(card),
        *create_jsonrpc_routes(request_handler=handler, rpc_url="/", context_builder=ContextBuilder()),
    ]
    return Starlette(routes=routes, middleware=[Middleware(DelegationMiddleware, check=host.delegation.user, header=auth_header)])


class A2ATransport:
    """Sends specialist requests as A2A messages.

    `urls` maps each specialist to its A2A endpoint. `headers` adds per-call
    headers (AgentCore wants a runtime session ID); the delegation token always
    goes as the bearer token. `http_client_factory` lets tests call the ASGI apps directly.
    """

    def __init__(
        self,
        urls: dict[str, str],
        headers: Callable[[str, dict[str, Any]], Awaitable[dict[str, str]]] | None = None,
        http_client_factory: Callable[[str], Any] | None = None,
        timeout: float = 300.0,
    ) -> None:
        self.urls = urls
        self.headers = headers
        self.http_client_factory = http_client_factory
        self.timeout = timeout

    async def send(self, agent: str, body: dict[str, Any], delegation_token: str) -> dict[str, Any]:
        import httpx
        from a2a.client import ClientConfig, create_client
        from a2a.helpers.proto_helpers import get_text_parts, new_text_message
        from a2a.types import Role, SendMessageRequest

        extra = await self.headers(agent, body) if self.headers else {}
        http = self.http_client_factory(agent) if self.http_client_factory else httpx.AsyncClient(timeout=self.timeout)
        http.headers.update({"Authorization": f"Bearer {delegation_token}", **extra})
        async with http:
            card = agent_card(agent, self.urls[agent])
            client = await create_client(card, ClientConfig(streaming=False, httpx_client=http))
            message = new_text_message(json.dumps(body), media_type=JSON, context_id=str(uuid.uuid4()), role=Role.ROLE_USER)
            async for event in client.send_message(SendMessageRequest(message=message)):
                if event.HasField("message"):
                    parts = get_text_parts(event.message.parts)
                    if parts:
                        return json.loads(parts[0])
        raise RuntimeError(f"{agent} sent no reply")
