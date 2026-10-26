"""Specialists behind A2A endpoints, called by the orchestrator with delegation tokens."""

import httpx
import pytest

from tests.conftest import PAYMENTS_TIER
from tests.platform.conftest import ORCHESTRATOR, PORTAL_AUDIENCE, audience
from tra_core.audit import verify
from tra_core.orchestrator import Orchestrator
from tra_core.schemas import Gate, WorkType
from tra_core.store import FileTraStore
from tra_core.tools import LocalToolClient
from tra_platform.host import RemoteInvoker


def _orchestrator(tmp_path, transport, signer, audit, reference, toolset, user_token):
    invoker = RemoteInvoker(
        transport,
        signer.exchanger(ORCHESTRATOR),
        {a: audience(a) for a in transport.urls},
        audit,
        user_token,
    )
    return Orchestrator(FileTraStore(tmp_path / "tras"), invoker, LocalToolClient(toolset), audit, reference)


async def test_lifecycle_over_a2a(tmp_path, a2a_transport, signer, audit, reference, toolset, alice):
    token = signer.user_token("alice", ["TRA.Practitioner"], PORTAL_AUDIENCE)
    orch = _orchestrator(tmp_path, a2a_transport, signer, audit, reference, toolset, token)
    tra = await orch.create(
        title="Customer payments portal",
        work_type=WorkType.NEW_SYSTEM,
        artefacts=[("git", "payments-portal-design.md")],
        user=alice,
    )
    tra, _ = await orch.decide(tra.id, Gate.G1, alice, "approve", "scope confirmed", PAYMENTS_TIER)
    assert len(tra.threats) == 11 and len(tra.risks) == 6 and tra.awaiting_gate is Gate.G2

    events = audit.sink.read_all()
    assert verify(events) == []
    remote = [e for e in events if e.detail.get("origin")]
    assert {e.detail["origin"] for e in remote} >= {"agent:threat_analyst", "agent:risk_assessor"}
    assert all(e.on_behalf_of == "alice" for e in remote if e.event_type == "model_call")
    assert any(e.event_type == "validation_failed" for e in remote)  # the retry happened remotely


def _rpc(text: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "SendMessage",
        "params": {"message": {"messageId": "m1", "role": "ROLE_USER", "parts": [{"text": text}]}},
    }


async def _post(app, headers):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x") as c:
        return await c.post("/", json=_rpc("{}"), headers=headers)


async def test_specialist_refuses_without_token(a2a_apps):
    assert (await _post(a2a_apps["intake"], {})).status_code == 401


async def test_specialist_refuses_token_for_another_agent(a2a_apps, signer):
    user = signer.user_token("alice", ["TRA.Practitioner"], PORTAL_AUDIENCE)
    token = await signer.exchanger(ORCHESTRATOR).exchange(user, audience("threat_analyst"))
    resp = await _post(a2a_apps["intake"], {"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401 and "audience" in resp.json()["detail"].lower()


async def test_specialist_refuses_unknown_caller(a2a_apps, signer):
    user = signer.user_token("alice", ["TRA.Practitioner"], PORTAL_AUDIENCE)
    token = await signer.exchanger("someone-else").exchange(user, audience("intake"))
    resp = await _post(a2a_apps["intake"], {"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401 and "may not invoke" in resp.json()["detail"]


async def test_user_token_cannot_be_replayed_at_a_specialist(a2a_apps, signer):
    # The user's own token has the portal audience and no actor.
    user = signer.user_token("alice", ["TRA.Practitioner"], audience("intake"))
    resp = await _post(a2a_apps["intake"], {"Authorization": f"Bearer {user}"})
    assert resp.status_code == 401


async def test_agent_card_is_served(a2a_apps):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=a2a_apps["threat_analyst"]), base_url="http://x") as c:
        card = (await c.get("/.well-known/agent-card.json")).json()
    assert card["name"] == "tra-threat-analyst"
    assert card["supportedInterfaces"][0]["protocolBinding"] == "JSONRPC"


async def test_tampered_audit_from_specialist_is_rejected(audit):
    from tra_core.agents.base import SpecialistRequest

    class Liar:
        urls = {"intake": "x"}

        async def send(self, agent, body, token):
            return {"status": "ok", "output": {}, "audit": [{"seq": 1, "tra_id": "T", "tra_version": 1, "stage": None,
                                                              "event_type": "model_call", "actor": "a", "prev_hash": "0" * 64,
                                                              "hash": "f" * 64}]}

    class NoExchange:
        async def exchange(self, token, aud):
            return "t"

    invoker = RemoteInvoker(Liar(), NoExchange(), {"intake": "aud"}, audit, "u")
    req = SpecialistRequest(agent="intake", tra_id="T", tra_version=1, stage="intake", payload={})
    with pytest.raises(ValueError, match="failed verification"):
        await invoker.invoke(req, None)  # type: ignore[arg-type]
