"""Amazon Bedrock AgentCore Runtime entrypoints.

One image, four roles, each a separate AgentCore runtime:

| Role | AgentCore protocol | Container port | Paths |
|---|---|---|---|
| orchestrator | HTTP | 8080 | POST /invocations, GET /ping |
| each specialist | A2A | 9000 | POST / (JSON-RPC), GET /.well-known/agent-card.json, GET /ping |
| mcp-reference, mcp-artefacts | MCP | 8000 | POST /mcp |

Every runtime has the inbound JWT authorizer on (discovery URL of the IdP,
allowed audience = the runtime's own audience) and `Authorization` in its
request header allowlist, so the token reaches the container, which checks it
again. Runtimes run in VPC mode in ap-southeast-2. See `infra/aws`.

Run: `python -m tra_platform.agentcore` (the image's CMD); TRA_ROLE picks the role.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

from tra_platform.a2a import A2ATransport, build_a2a_app
from tra_platform.config import Endpoint, Settings
from tra_platform.federation import entra_assertion_from_aws, entra_credential_from_aws
from tra_platform.wiring import mcp_app, orchestrator_service, specialist_host

SESSION_HEADER = "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id"
PORTS = {"orchestrator": 8080, "mcp": 8000, "a2a": 9000}


def runtime_url(arn: str) -> str:
    """The invocation URL for a runtime ARN. Settings may give an ARN or a URL."""
    if not arn.startswith("arn:"):
        return arn
    from bedrock_agentcore.runtime.a2a import build_runtime_url

    return build_runtime_url(arn)


def session_id(tra_id: str, agent: str) -> str:
    """One runtime session per TRA and agent: warm across that TRA's stages, never shared between TRAs."""
    return hashlib.sha256(f"{tra_id}:{agent}".encode()).hexdigest()  # 64 chars; AgentCore needs at least 33


async def _session_headers(agent: str, body: dict[str, Any]) -> dict[str, str]:
    return {SESSION_HEADER: session_id(body["tra_id"], agent)}


def _exchanger(settings: Settings) -> Any:
    if settings.exchange == "entra-obo":
        return settings.exchanger(client_assertion=entra_assertion_from_aws())
    return settings.exchanger(client_secret=_secret(os.environ["TRA_CLIENT_SECRET_ARN"]))


def _secret(arn: str) -> Any:
    """For IdPs without workload federation: the client secret, read from Secrets Manager when needed."""

    async def read() -> str:
        import asyncio

        import boto3

        client = boto3.client("secretsmanager")
        return (await asyncio.to_thread(client.get_secret_value, SecretId=arn))["SecretString"]

    return read


def _router(settings: Settings) -> Any:
    from tra_core.llm import ModelRouter

    azure = None
    if os.environ.get("TRA_AZURE_CLIENT_ID"):  # only when a specialist routes to GPT in Australia East
        azure = entra_credential_from_aws(settings.tenant_id, os.environ["TRA_AZURE_CLIENT_ID"])
    return ModelRouter.from_file(settings.models_file, azure_credential=azure)


def build_app(settings: Settings) -> tuple[Any, int]:
    # Settings may name other runtimes by ARN; callers need their invocation URLs.
    settings.mcp = {k: Endpoint(runtime_url(v.endpoint), v.audience) for k, v in settings.mcp.items()}
    exchanger = _exchanger(settings)
    if settings.role == "orchestrator":
        from bedrock_agentcore.runtime import BedrockAgentCoreApp
        from starlette.responses import JSONResponse

        transport = A2ATransport(
            {k: runtime_url(v.endpoint) for k, v in settings.specialists.items()}, headers=_session_headers
        )
        service = orchestrator_service(settings, transport, exchanger)
        app = BedrockAgentCoreApp()

        @app.entrypoint
        async def invoke(payload: dict[str, Any], context: Any) -> Any:
            headers = getattr(context, "request_headers", None) or {}
            token = (headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            status, body = await service.handle(payload, token)
            return body if status == 200 else JSONResponse(body, status_code=status)

        return app, PORTS["orchestrator"]
    if settings.role.startswith("mcp-"):
        return mcp_app(settings), PORTS["mcp"]
    host = specialist_host(settings, exchanger, _router(settings))
    public_url = os.environ.get("AGENTCORE_RUNTIME_URL", "http://localhost:9000/")
    return build_a2a_app(host, public_url), PORTS["a2a"]


def main() -> None:
    import uvicorn

    app, port = build_app(Settings.from_env())
    if hasattr(app, "entrypoint"):  # BedrockAgentCoreApp keeps /ping responsive with its own worker loop
        app.run(port=port, host="0.0.0.0")  # noqa: S104 - container listener
    else:
        uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")  # noqa: S104


if __name__ == "__main__":
    main()
