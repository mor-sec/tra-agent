"""Builds the deployed services from `Settings`. The platform modules add transport and credentials."""

from __future__ import annotations

from typing import Any

from starlette.applications import Starlette

from tra_core.audit import AuditLog
from tra_core.llm import ModelRouter
from tra_core.mcp_servers import _artefact_sources_from_env
from tra_core.reference import Reference
from tra_core.tools import ToolSet
from tra_platform.auth import TokenExchanger
from tra_platform.config import Settings, object_store
from tra_platform.host import SpecialistHost, Transport
from tra_platform.mcp import McpRoute, RoutedMcpToolClient, build_mcp_app, no_default_clearance
from tra_platform.service import OrchestratorService
from tra_platform.storage import ObjectAuditSink, ObjectRegisterWriter, ObjectTraStore


def mcp_routes(settings: Settings) -> dict[str, McpRoute]:
    return {k: McpRoute(v.endpoint, v.audience) for k, v in settings.mcp.items()}


def specialist_host(settings: Settings, exchanger: TokenExchanger, router: ModelRouter | None = None) -> SpecialistHost:
    routes = mcp_routes(settings)
    return SpecialistHost(
        settings.role,
        router or ModelRouter.from_file(settings.models_file),
        Reference(),
        settings.delegation(),
        tools_for=lambda token: RoutedMcpToolClient(routes, exchanger, token),
    )


def mcp_app(settings: Settings) -> Starlette:
    which = settings.role.removeprefix("mcp-")
    toolset = ToolSet(Reference(), _artefact_sources_from_env() if which == "artefacts" else {}, no_default_clearance)
    return build_mcp_app(which, toolset, settings.delegation())


def orchestrator_service(settings: Settings, transport: Transport, exchanger: TokenExchanger, **kwargs: Any) -> OrchestratorService:
    state = object_store(settings.state_uri, settings.kms_key_id)
    audit = object_store(settings.audit_uri, settings.kms_key_id)
    routes = mcp_routes(settings)
    return OrchestratorService(
        validator=settings.validator(),
        store=ObjectTraStore(state),
        audit=AuditLog(ObjectAuditSink(audit)),
        reference=Reference(),
        transport=transport,
        exchanger=exchanger,
        audiences={k: v.audience for k, v in settings.specialists.items()},
        tools_for=lambda token: RoutedMcpToolClient(routes, exchanger, token),
        register=ObjectRegisterWriter(state),
        **kwargs,
    )
