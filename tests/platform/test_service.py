"""The orchestrator service end to end: tokens in, specialists over A2A, durable storage."""

import time

import pytest

from tests.conftest import PAYMENTS_TIER
from tests.platform.conftest import ORCHESTRATOR, PORTAL_AUDIENCE, audience
from tra_core.audit import AuditLog, verify
from tra_core.tools import LocalToolClient
from tra_platform.auth import TokenValidator
from tra_platform.service import OrchestratorService
from tra_platform.storage import LocalObjectStore, ObjectAuditSink, ObjectRegisterWriter, ObjectTraStore

PRACTITIONER = ["TRA.Practitioner", "TRA.Clearance.OfficialSensitive"]


@pytest.fixture
def service(tmp_path, signer, a2a_transport, reference, toolset):
    state = LocalObjectStore(tmp_path / "state")
    return OrchestratorService(
        validator=TokenValidator(signer.issuer, PORTAL_AUDIENCE, signer.keys),
        store=ObjectTraStore(state),
        audit=AuditLog(ObjectAuditSink(LocalObjectStore(tmp_path / "audit"))),
        reference=reference,
        transport=a2a_transport,
        exchanger=signer.exchanger(ORCHESTRATOR),
        audiences={a: audience(a) for a in a2a_transport.urls},
        tools_for=lambda _token: LocalToolClient(toolset),
        register=ObjectRegisterWriter(state),
    )


def token(signer, sub, roles, **extra):
    return signer.user_token(sub, roles, PORTAL_AUDIENCE, **extra)


CREATE = {
    "action": "create",
    "title": "Customer payments portal",
    "work_type": "new_system",
    "artefacts": [{"source": "git", "locator": "payments-portal-design.md"}],
}


async def test_full_lifecycle(service, signer, tmp_path):
    alice, bob = token(signer, "alice", PRACTITIONER), token(signer, "bob", PRACTITIONER)
    status, body = await service.handle(CREATE, alice)
    assert status == 200 and body["tra"]["awaiting_gate"] == "G1" and body["tra"]["classification"] == "OFFICIAL: Sensitive"
    tra_id = body["tra"]["id"]

    def decide(gate, who, rationale="ok", decision="approve", tier_factors=None):
        return service.handle({"action": "decide", "tra_id": tra_id, "gate": gate, "decision": decision, "rationale": rationale, "tier_factors": tier_factors}, who)

    status, body = await decide("G1", alice, tier_factors=PAYMENTS_TIER.model_dump())
    assert status == 200 and body["tra"]["awaiting_gate"] == "G2" and body["tra"]["threats"] == 11
    status, body = await decide("G2", alice, decision="approve_with_changes")  # the critique has open majors
    assert body["outcome"]["waiting_for"]  # Tier 1: a second practitioner
    await decide("G2", bob, decision="approve_with_changes")

    # G3 needs a risk owner who stepped up within ten minutes.
    stale = token(signer, "carol", ["TRA.RiskOwner", "TRA.Clearance.OfficialSensitive"], acrs=["c1"], iat=int(time.time()) - 3600)
    status, body = await decide("G3", stale)
    assert status == 409
    fresh = token(signer, "carol", ["TRA.RiskOwner", "TRA.Clearance.OfficialSensitive"], acrs=["c1"])
    status, body = await decide("G3", fresh, "accept the treatment plan")
    assert status == 200 and "ciso" in body["outcome"]["waiting_for"]  # R-01 is Critical
    ciso = token(signer, "dana", ["TRA.CISO", "TRA.Clearance.OfficialSensitive"], acrs=["c1"])
    status, body = await decide("G3", ciso, "concur")
    assert status == 200 and body["tra"]["stage"] == "monitor"

    status, body = await service.handle({"action": "report", "tra_id": tra_id}, alice)
    assert status == 200 and "```mermaid" in body["markdown"] and body["register_csv"].startswith("risk_id")
    assert (tmp_path / "state" / "register" / f"{tra_id}-risk-register.csv").exists()

    events = service.audit.sink.read_all()
    assert verify(events) == []
    assert len(list((tmp_path / "audit" / "audit").iterdir())) == len(events)


async def test_rejects_bad_tokens_and_low_clearance(service, signer):
    assert (await service.handle(CREATE, "not-a-jwt"))[0] == 401
    other_audience = signer.user_token("alice", PRACTITIONER, "api://something-else")
    assert (await service.handle(CREATE, other_audience))[0] == 401
    viewer = token(signer, "vic", ["TRA.Viewer", "TRA.Clearance.OfficialSensitive"])
    assert (await service.handle(CREATE, viewer))[0] == 403  # practitioners only

    status, body = await service.handle(CREATE, token(signer, "alice", PRACTITIONER))
    official_only = token(signer, "olly", ["TRA.Practitioner"])
    status, _ = await service.handle({"action": "get", "tra_id": body["tra"]["id"]}, official_only)
    assert status == 403
    assert (await service.handle({"action": "get", "tra_id": "TRA-1999-001"}, official_only))[0] == 404
    assert (await service.handle({"action": "nope"}, official_only))[0] == 400
