"""Tools the agents use, and the clients that reach them.

Agents never pick tools themselves: each specialist calls the tools it needs in
code, then hands the results to the model. That keeps agency low (a prompt
injection can't make an agent call a tool it wasn't going to call) and makes
every tool call auditable and repeatable.

The same `ToolSet` backs both paths:
- `LocalToolClient` calls it in-process (tests, local runs).
- `McpToolClient` calls it through an MCP server (see `mcp_servers.py`), which
  is how deployed agents reach it, behind the MCP gateway.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, Protocol

from tra_core.artefacts import ArtefactSource
from tra_core.audit import AuditLog, digest
from tra_core.classification import can_read
from tra_core.identity import Principal
from tra_core.reference import Reference
from tra_core.schemas import Classification

JSON = Any


class ToolError(Exception):
    pass


class ToolSet:
    """Read-only tools over reference data and artefacts."""

    def __init__(
        self,
        reference: Reference,
        artefacts: dict[str, ArtefactSource] | None = None,
        clearance_of: Callable[[], Classification] = lambda: Classification.OFFICIAL_SENSITIVE,
    ) -> None:
        self.reference = reference
        self.artefacts = artefacts or {}
        self.clearance_of = clearance_of

    # -- threats
    def threats_search(self, applies_to: str, tags: list[str] | None = None, include_ai: bool = False) -> JSON:
        hits = self.reference.threats.search(applies_to, tags, include_ai)
        return {"library_version": self.reference.threats.version, "threats": [t.model_dump(mode="json") for t in hits]}

    def threats_get(self, threat_id: str) -> JSON:
        t = self.reference.threats.get(threat_id)
        if t is None:
            raise ToolError(f"unknown threat {threat_id}")
        return t.model_dump(mode="json")

    # -- controls
    def controls_lookup(self, ids: list[str]) -> JSON:
        found = self.reference.controls.lookup(ids)
        unknown = sorted(set(ids) - {c.id for c in found})
        return {
            "catalogue_version": self.reference.controls.version,
            "controls": [c.model_dump(mode="json") for c in found],
            "unknown": unknown,
        }

    def controls_list(self, domain: str | None = None) -> JSON:
        items = [c for c in self.reference.controls.controls if domain is None or c.domain == domain]
        return {
            "catalogue_version": self.reference.controls.version,
            "controls": [{"id": c.id, "title": c.title, "domain": c.domain} for c in items],
        }

    # -- artefacts
    def artefacts_get(self, source: str, locator: str, clearance: Classification | None = None) -> JSON:
        """`clearance` is the caller's, when the transport knows who is calling (the MCP host)."""
        if source not in self.artefacts:
            raise ToolError(f"unknown artefact source {source}")
        artefact = self.artefacts[source].get(locator)
        if not can_read(clearance or self.clearance_of(), artefact.classification):
            raise ToolError("caller's clearance is below the artefact's classification")
        return artefact.model_dump(mode="json")

    def artefacts_list(self, source: str, prefix: str = "") -> JSON:
        if source not in self.artefacts:
            raise ToolError(f"unknown artefact source {source}")
        return {"items": self.artefacts[source].list(prefix)}

    def call(self, name: str, args: dict[str, Any]) -> JSON:
        fn = getattr(self, name, None)
        if name not in TOOL_NAMES or fn is None:
            raise ToolError(f"unknown tool {name}")
        return fn(**args)


TOOL_NAMES = ("threats_search", "threats_get", "controls_lookup", "controls_list", "artefacts_get", "artefacts_list")


class ToolClient(Protocol):
    async def call(self, name: str, args: dict[str, Any]) -> JSON: ...


class LocalToolClient:
    def __init__(self, toolset: ToolSet) -> None:
        self.toolset = toolset

    async def call(self, name: str, args: dict[str, Any]) -> JSON:
        return self.toolset.call(name, args)


class McpToolClient:
    """Calls tools on an MCP server. `server` is a URL, stdio parameters, or an in-process MCPServer."""

    def __init__(self, server: Any) -> None:
        self.server = server

    async def call(self, name: str, args: dict[str, Any]) -> JSON:
        from mcp.client import Client

        async with Client(self.server) as client:
            result = await client.call_tool(name, args)
        if result.is_error:
            text = " ".join(getattr(c, "text", "") for c in result.content)
            raise ToolError(f"{name} failed: {text}")
        if result.structured_content is not None:
            sc = result.structured_content
            # MCP wraps non-object results as {"result": ...}
            return sc["result"] if set(sc) == {"result"} else sc
        text = "".join(getattr(c, "text", "") for c in result.content)
        return json.loads(text)


class AuditedToolClient:
    """Records every tool call (arguments and a hash of the result) in the audit log."""

    def __init__(self, inner: ToolClient, audit: AuditLog, actor: Principal, tra_id: str, tra_version: int) -> None:
        self.inner = inner
        self.audit = audit
        self.actor = actor
        self.tra_id = tra_id
        self.tra_version = tra_version
        self.stage: str | None = None

    async def call(self, name: str, args: dict[str, Any]) -> JSON:
        result = await self.inner.call(name, args)
        self.audit.record(
            tra_id=self.tra_id,
            tra_version=self.tra_version,
            stage=self.stage,
            event_type="tool_call",
            actor=self.actor,
            detail={"tool": name, "args": args, "result_sha256": digest(json.dumps(result, sort_keys=True, default=str))},
        )
        return result
