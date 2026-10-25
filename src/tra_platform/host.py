"""Platform-neutral hosting: a specialist behind a network endpoint, and the invoker that calls it.

Both platforms run the same two pieces:

- `SpecialistHost` sits in a specialist's container. It validates the
  delegation token, runs the specialist (`tra_core.orchestrator.run_specialist`)
  and returns the output together with the audit events it recorded.
- `RemoteInvoker` sits in the orchestrator. It exchanges the user's token for
  one addressed to the specialist, sends the request over a `Transport`, and
  folds the returned audit events into the orchestrator's hash chain.

Only the transport differs: A2A JSON-RPC (AgentCore, self-hosted) or Foundry
invocations. The request and response bodies are the same JSON either way.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from tra_core.agents.base import AgentFailure, SpecialistRequest
from tra_core.audit import AuditLog, MemoryAuditSink
from tra_core.identity import Principal
from tra_core.llm import ModelRouter
from tra_core.orchestrator import run_specialist
from tra_core.reference import Reference
from tra_core.tools import ToolClient
from tra_platform.auth import AuthError, DelegationValidator, TokenExchanger


class SpecialistHost:
    """Runs one specialist for authenticated requests.

    `tools_for` builds the tool client for a request from its delegation token,
    so tool calls carry the user's identity on to the MCP servers.
    """

    def __init__(
        self,
        agent: str,
        router: ModelRouter,
        reference: Reference,
        delegation: DelegationValidator,
        tools_for: Callable[[str], ToolClient],
        blob_dir: Path | None = None,
    ) -> None:
        self.agent = agent
        self.router = router
        self.reference = reference
        self.delegation = delegation
        self.tools_for = tools_for
        self.blob_dir = blob_dir

    async def handle(self, body: dict[str, Any], delegation_token: str) -> dict[str, Any]:
        user = self.delegation.user(delegation_token)
        request = SpecialistRequest.model_validate(body)
        if request.agent != self.agent:
            raise AuthError(f"this endpoint hosts {self.agent}, not {request.agent}")
        audit = AuditLog(MemoryAuditSink())
        try:
            output = await run_specialist(
                request, user, self.router, self.tools_for(delegation_token), audit, self.reference, self.blob_dir
            )
            result: dict[str, Any] = {"status": "ok", "output": output}
        except AgentFailure as exc:
            result = {"status": "failed", "error": str(exc)}
        result["audit"] = [e.model_dump(mode="json") for e in audit.sink.read_all()]
        return result


class Transport(Protocol):
    async def send(self, agent: str, body: dict[str, Any], delegation_token: str) -> dict[str, Any]: ...


class RemoteInvoker:
    """`Invoker` for specialists on another host. One per user request.

    It is bound to the caller's validated access token, because that token (not
    the Principal built from it) is what gets exchanged. `audiences` maps each
    specialist to the audience its delegation tokens must carry.
    """

    def __init__(
        self,
        transport: Transport,
        exchanger: TokenExchanger,
        audiences: dict[str, str],
        audit: AuditLog,
        user_token: str,
    ) -> None:
        self.transport = transport
        self.exchanger = exchanger
        self.audiences = audiences
        self.audit = audit
        self.user_token = user_token

    async def invoke(self, request: SpecialistRequest, on_behalf_of: Principal) -> dict[str, Any]:
        token = await self.exchanger.exchange(self.user_token, self.audiences[request.agent])
        reply = await self.transport.send(request.agent, request.model_dump(mode="json"), token)
        self.audit.ingest(reply.get("audit", []), origin=f"agent:{request.agent}")
        if reply.get("status") != "ok":
            raise AgentFailure(reply.get("error", f"{request.agent} returned no output"))
        return reply["output"]
