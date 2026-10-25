"""Microsoft Foundry hosted-agent entrypoints (Australia East).

Specialists and the orchestrator run as hosted agents using the Invocations
protocol (`azure-ai-agentserver-invocations`): POST /invocations on port 8088,
with /readiness served by the library. Foundry's front door authenticates the
caller with Entra ID before the container sees the request, and forwards
headers starting with `x-client-`. Our tokens travel in those:

| Header | Carries | Checked by |
|---|---|---|
| `x-client-tra-user` | The user's access token (audience: the orchestrator) | Orchestrator |
| `x-client-tra-delegation` | The delegation token (audience: the specialist) | Specialist |

Why not A2A here: Foundry lists an A2A endpoint for hosted agents, but its
container-side protocol libraries document Responses and Invocations only.
The JSON bodies are the same as over A2A, so switching is a transport change
(`A2ATransport` instead of `FoundryTransport`) once A2A hosting is documented.

The MCP servers do not run as hosted agents. They run in Azure Container Apps
with internal ingress in the same VNet (see `infra/azure`), using
`python -m tra_platform.foundry` with TRA_ROLE=mcp-*.

Claude is not Australia-resident on Foundry, so Foundry specialists that route
to Claude call Bedrock in Sydney through Entra-to-AWS federation
(`TRA_BEDROCK_ROLE_ARN`); GPT deployments in Australia East use the agent's
own Entra identity.
"""

from __future__ import annotations

import hashlib
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from tra_platform.auth import AuthError
from tra_platform.config import Settings
from tra_platform.federation import bedrock_client_from_entra, entra_assertion_from_managed_identity
from tra_platform.wiring import mcp_app, orchestrator_service, specialist_host

USER_HEADER = "x-client-tra-user"
DELEGATION_HEADER = "x-client-tra-delegation"
FOUNDRY_SCOPE = "https://ai.azure.com/.default"


class FoundryTransport:
    """Calls specialists' Invocations endpoints as the orchestrator's agent identity."""

    def __init__(self, project_endpoint: str, agent_names: dict[str, str], credential: Any = None, http: Any = None) -> None:
        self.project_endpoint = project_endpoint.rstrip("/")
        self.agent_names = agent_names
        self.credential = credential
        self.http = http

    def url(self, agent: str) -> str:
        return f"{self.project_endpoint}/agents/{self.agent_names[agent]}/endpoint/protocols/invocations"

    async def send(self, agent: str, body: dict[str, Any], delegation_token: str) -> dict[str, Any]:
        import httpx

        if self.credential is None:
            from azure.identity import DefaultAzureCredential

            self.credential = DefaultAzureCredential()
        session = hashlib.sha256(f"{body['tra_id']}:{agent}".encode()).hexdigest()[:32]
        headers = {
            "Authorization": f"Bearer {self.credential.get_token(FOUNDRY_SCOPE).token}",
            DELEGATION_HEADER: delegation_token,
        }
        client = self.http or httpx.AsyncClient(timeout=300)
        resp = await client.post(
            self.url(agent), params={"api-version": "v1", "agent_session_id": session}, json=body, headers=headers
        )
        if resp.status_code != 200:
            raise RuntimeError(f"{agent} returned {resp.status_code}: {resp.text[:300]}")
        return resp.json()


def _router(settings: Settings) -> Any:
    from tra_core.llm import ModelRouter

    bedrock = bedrock_client_from_entra(settings.bedrock_role_arn) if settings.bedrock_role_arn else None
    return ModelRouter.from_file(settings.models_file, bedrock_client=bedrock)


def build_app(settings: Settings, project_endpoint: str = "") -> Any:
    if settings.role.startswith("mcp-"):
        return mcp_app(settings)

    from azure.ai.agentserver.invocations import InvocationAgentServerHost

    exchanger = settings.exchanger(client_assertion=entra_assertion_from_managed_identity())
    app = InvocationAgentServerHost()

    if settings.role == "orchestrator":
        names = {k: v.endpoint for k, v in settings.specialists.items()}  # endpoint = hosted agent name here
        service = orchestrator_service(settings, FoundryTransport(project_endpoint, names), exchanger)

        @app.invoke_handler
        async def orchestrate(request: Request) -> Response:
            status, body = await service.handle(await request.json(), request.headers.get(USER_HEADER, ""))
            return JSONResponse(body, status_code=status)

        return app

    host = specialist_host(settings, exchanger, _router(settings))

    @app.invoke_handler
    async def specialist(request: Request) -> Response:
        try:
            result = await host.handle(await request.json(), request.headers.get(DELEGATION_HEADER, ""))
        except AuthError as exc:
            return JSONResponse({"error": "unauthorized", "detail": str(exc)}, status_code=401)
        return JSONResponse(result)

    return app


def main() -> None:
    import os

    settings = Settings.from_env()
    app = build_app(settings, os.environ.get("FOUNDRY_PROJECT_ENDPOINT", ""))
    if hasattr(app, "invoke_handler"):
        app.run()  # port 8088, or PORT
    else:
        import uvicorn

        uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))  # noqa: S104


if __name__ == "__main__":
    main()
