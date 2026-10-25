"""Platform glue: AgentCore session IDs and URLs, Foundry invocations host and transport."""

import json

import httpx

from tests.conftest import REPLAY
from tests.platform.conftest import ORCHESTRATOR, PORTAL_AUDIENCE, audience
from tra_core.llm import ReplayModelClient
from tra_platform.agentcore import runtime_url, session_id
from tra_platform.foundry import DELEGATION_HEADER, FoundryTransport


def test_agentcore_session_and_url():
    sid = session_id("TRA-2026-001", "threat_analyst")
    assert len(sid) >= 33 and sid == session_id("TRA-2026-001", "threat_analyst") != session_id("TRA-2026-002", "threat_analyst")
    url = runtime_url("arn:aws:bedrock-agentcore:ap-southeast-2:123456789012:runtime/tra_intake-abc123")
    assert url.startswith("https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/arn%3Aaws")
    assert runtime_url("http://localhost:9000/") == "http://localhost:9000/"


def _foundry_specialist_app(make_host):
    from azure.ai.agentserver.invocations import InvocationAgentServerHost
    from starlette.responses import JSONResponse

    from tra_platform.auth import AuthError

    host = make_host("intake", ReplayModelClient(json.loads(REPLAY.read_text())))
    app = InvocationAgentServerHost()

    @app.invoke_handler
    async def specialist(request):  # mirrors tra_platform.foundry.build_app
        try:
            return JSONResponse(await host.handle(await request.json(), request.headers.get(DELEGATION_HEADER, "")))
        except AuthError as exc:
            return JSONResponse({"error": "unauthorized", "detail": str(exc)}, status_code=401)

    return app


class _Credential:
    def get_token(self, scope):
        assert scope == "https://ai.azure.com/.default"
        return type("T", (), {"token": "entra-token"})()


async def test_foundry_transport_round_trip(make_host, signer, store_artefact):
    app = _foundry_specialist_app(make_host)
    seen = {}

    async def record(request):
        seen["url"], seen["auth"] = str(request.url), request.headers["authorization"]

    async def front_door(scope, receive, send):  # Foundry routes the project URL to the container's /invocations
        if scope["type"] == "http" and scope["path"].endswith("/endpoint/protocols/invocations"):
            scope = {**scope, "path": "/invocations", "raw_path": b"/invocations"}
        await app(scope, receive, send)

    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=front_door), event_hooks={"request": [record]})
    transport = FoundryTransport("http://foundry.test/api/projects/tra", {"intake": "tra-intake"}, _Credential(), http)
    user = signer.user_token("alice", ["TRA.Practitioner", "TRA.Clearance.OfficialSensitive"], PORTAL_AUDIENCE)
    delegation = await signer.exchanger(ORCHESTRATOR).exchange(user, audience("intake"))
    body = {"agent": "intake", "tra_id": "TRA-2026-001", "tra_version": 1, "stage": "intake",
            "payload": {"title": "Customer payments portal", "work_type": "new_system", "artefacts": [store_artefact]}}
    reply = await transport.send("intake", body, delegation)
    assert reply["status"] == "ok" and reply["audit"]
    assert "/agents/tra-intake/endpoint/protocols/invocations" in seen["url"] and "api-version=v1" in seen["url"]
    assert seen["auth"] == "Bearer entra-token"


async def test_foundry_specialist_refuses_missing_delegation(make_host):
    app = _foundry_specialist_app(make_host)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        resp = await c.post("/invocations", json={"agent": "intake"})
    assert resp.status_code == 401


def _env(role, tmp_path):
    return {
        "TRA_ROLE": role,
        "TRA_IDP_ISSUER": "https://login.microsoftonline.com/t/v2.0",
        "TRA_IDP_JWKS_URL": "https://login.microsoftonline.com/t/discovery/v2.0/keys",
        "TRA_AUDIENCE": f"api://tra-{role}",
        "TRA_ALLOWED_CALLERS": "orch-app-id",
        "TRA_TENANT_ID": "t",
        "TRA_CLIENT_ID": "c",
        "TRA_MODELS_FILE": str(REPLAY.parents[2] / "config" / "models.yaml"),
        "TRA_MCP": json.dumps({"reference": {"endpoint": "arn:aws:bedrock-agentcore:ap-southeast-2:1:runtime/r", "audience": "a"}}),
        "TRA_SPECIALISTS": json.dumps({"intake": {"endpoint": "arn:aws:bedrock-agentcore:ap-southeast-2:1:runtime/i", "audience": "b"}}),
        "TRA_STATE_URI": f"file://{tmp_path}/state",
        "TRA_AUDIT_URI": f"file://{tmp_path}/audit",
    }


def _paths(app):
    return {getattr(r, "path", None) for r in app.routes}


def test_agentcore_builds_every_role(tmp_path):
    from tra_platform.agentcore import build_app
    from tra_platform.config import Settings

    app, port = build_app(Settings.from_env(_env("threat_analyst", tmp_path)))
    assert port == 9000 and {"/", "/ping", "/.well-known/agent-card.json"} <= _paths(app)
    app, port = build_app(Settings.from_env(_env("mcp-reference", tmp_path)))
    assert port == 8000
    app, port = build_app(Settings.from_env(_env("orchestrator", tmp_path)))
    assert port == 8080 and {"/invocations", "/ping"} <= _paths(app)


def test_foundry_builds_every_role(tmp_path):
    from tra_platform.config import Settings
    from tra_platform.foundry import build_app

    for role in ("intake", "orchestrator"):
        app = build_app(Settings.from_env(_env(role, tmp_path)), "https://x.services.ai.azure.com/api/projects/p")
        assert {"/invocations", "/readiness"} <= _paths(app)
