"""Tampering with the audit trail, locally and through specialist replies.

ISO 27001 A.8.15 (logging); ISM logging controls; PCI DSS 10.3.
"""

import pytest

from tra_core.audit import AuditLog, MemoryAuditSink, verify
from tra_core.identity import Principal, Role
from tra_core.schemas import Gate


@pytest.fixture
async def trail(rig, alice):
    r = rig()
    tra = await r.create(alice)
    await r.orch.decide(tra.id, Gate.G1, alice, "approve", "ok")
    events = r.audit.sink.read_all()
    assert verify(events) == [] and len(events) > 10
    return events


def test_deleting_an_event_is_detected(trail):
    assert verify(trail[:5] + trail[6:])


def test_deleting_the_first_event_is_detected(trail):
    assert verify(trail[1:])


def test_reordering_is_detected(trail):
    swapped = [*trail[:3], trail[4], trail[3], *trail[5:]]
    assert verify(swapped)


def test_editing_a_gate_decision_is_detected(trail):
    i = next(i for i, e in enumerate(trail) if e.event_type == "gate_decision")
    forged = trail[i].model_copy(update={"detail": {**trail[i].detail, "by": "carol"}})
    assert any("content does not match" in p for p in verify([*trail[:i], forged, *trail[i + 1:]]))


def test_rehashing_an_edit_still_breaks_the_next_link(trail):
    i = next(i for i, e in enumerate(trail) if e.event_type == "gate_decision")
    forged = trail[i].model_copy(update={"actor": "carol"})
    forged = forged.model_copy(update={"hash": forged.compute_hash()})
    if i + 1 < len(trail):
        assert verify([*trail[:i], forged, *trail[i + 1:]])


def test_truncating_the_tail_is_not_detectable_by_the_chain_alone(trail):
    # Known limit of any hash chain: dropping the newest events leaves a valid
    # prefix. The control is storage: Object Lock (compliance mode) or an
    # immutable Blob policy, plus the orchestrator role having no delete.
    assert verify(trail[:-3]) == []


def _remote_chain(event_type: str, actor: Principal) -> list[dict]:
    log = AuditLog(MemoryAuditSink())
    log.record(tra_id="TRA-1", tra_version=1, stage="evaluation", event_type=event_type, actor=actor, detail={})
    return [e.model_dump(mode="json") for e in log.sink.read_all()]


def test_specialist_cannot_inject_a_gate_decision():
    log = AuditLog(MemoryAuditSink())
    carol = Principal.human("carol", Role.RISK_OWNER)
    with pytest.raises(ValueError, match="may not record"):
        log.ingest(_remote_chain("gate_decision", carol), origin="agent:risk_assessor")
    assert log.sink.read_all() == []


def test_specialist_cannot_record_as_another_agent():
    log = AuditLog(MemoryAuditSink())
    other = Principal.workload("agent:quality_critic")
    with pytest.raises(ValueError, match="may not record"):
        log.ingest(_remote_chain("agent_output", other), origin="agent:risk_assessor")


def test_specialist_events_with_a_broken_chain_are_refused():
    log = AuditLog(MemoryAuditSink())
    me = Principal.workload("agent:risk_assessor")
    events = _remote_chain("model_call", me)
    events[0]["detail"] = {"model": "something else"}
    with pytest.raises(ValueError, match="failed verification"):
        log.ingest(events, origin="agent:risk_assessor")


def test_specialist_own_events_are_ingested_and_rechained():
    log = AuditLog(MemoryAuditSink())
    log.record(tra_id="TRA-1", tra_version=1, stage="evaluation", event_type="tra_created",
               actor=Principal.human("alice", Role.PRACTITIONER), detail={})
    log.ingest(_remote_chain("model_call", Principal.workload("agent:risk_assessor")), origin="agent:risk_assessor")
    events = log.sink.read_all()
    assert verify(events) == [] and events[-1].detail["origin"] == "agent:risk_assessor"
