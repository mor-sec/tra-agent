from datetime import UTC, datetime, timedelta

import pytest

from tra_core.audit import AuditLog, JsonlAuditSink, MemoryAuditSink, verify
from tra_core.gates import GateError, GateService
from tra_core.identity import Principal, Role
from tra_core.schemas import TRA, Classification, Gate, Stage, WorkType


def _tra(**kw) -> TRA:
    base = dict(id="TRA-2026-900", title="t", work_type=WorkType.NEW_SYSTEM,
                classification=Classification.OFFICIAL_SENSITIVE, requested_by="alice", tier=2,
                stage=Stage.EVALUATION, awaiting_gate=Gate.G2)
    base.update(kw)
    return TRA(**base)


def test_hash_chain_detects_tampering(tmp_path):
    log = AuditLog(JsonlAuditSink(tmp_path / "events.jsonl"))
    me = Principal.human("alice", Role.PRACTITIONER)
    for i in range(3):
        log.record(tra_id="x", tra_version=1, stage=None, event_type="tool_call", actor=me, detail={"i": i})
    events = log.sink.read_all()
    assert verify(events) == []
    events[1].detail["i"] = 99
    assert any("does not match its hash" in p for p in verify(events))
    del events[1]
    assert verify(events)


def test_chain_resumes_across_restarts(tmp_path):
    path = tmp_path / "events.jsonl"
    me = Principal.human("alice")
    AuditLog(JsonlAuditSink(path)).record(tra_id="x", tra_version=1, stage=None, event_type="export", actor=me)
    AuditLog(JsonlAuditSink(path)).record(tra_id="x", tra_version=1, stage=None, event_type="export", actor=me)
    assert verify(JsonlAuditSink(path).read_all()) == []


def test_workload_cannot_decide_a_gate():
    gates = GateService(AuditLog(MemoryAuditSink()))
    agent = Principal.workload("agent:risk_assessor", acting_for="alice")
    with pytest.raises(GateError, match="human"):
        gates.decide(_tra(), Gate.G2, agent, "approve", "looks fine")


def test_role_and_clearance_enforced():
    gates = GateService(AuditLog(MemoryAuditSink()))
    with pytest.raises(GateError, match="practitioner"):
        gates.decide(_tra(), Gate.G2, Principal.human("v", Role.VIEWER), "approve", "x")
    low = Principal.human("p", Role.PRACTITIONER, clearance=Classification.OFFICIAL)
    with pytest.raises(GateError, match="clearance"):
        gates.decide(_tra(), Gate.G2, low, "approve", "x")


def test_gate_must_be_the_one_waiting():
    gates = GateService(AuditLog(MemoryAuditSink()))
    with pytest.raises(GateError, match="not waiting"):
        gates.decide(_tra(), Gate.G1, Principal.human("p", Role.PRACTITIONER), "approve", "x")


def test_tier1_needs_two_distinct_practitioners():
    gates = GateService(AuditLog(MemoryAuditSink()))
    tra = _tra(tier=1)
    alice = Principal.human("alice", Role.PRACTITIONER)
    assert not gates.decide(tra, Gate.G2, alice, "approve", "ok").passed
    assert not gates.decide(tra, Gate.G2, alice, "approve", "ok again").passed
    assert gates.decide(tra, Gate.G2, Principal.human("bob", Role.PRACTITIONER), "approve", "ok").passed


def test_g3_needs_fresh_strong_auth():
    gates = GateService(AuditLog(MemoryAuditSink()))
    tra = _tra(stage=Stage.ACCEPTANCE, awaiting_gate=Gate.G3)
    stale = Principal.human("carol", Role.RISK_OWNER, strong_auth=True,
                            auth_time=datetime.now(UTC) - timedelta(minutes=30))
    with pytest.raises(GateError, match="MFA"):
        gates.decide(tra, Gate.G3, stale, "approve", "accept")
    fresh = Principal.human("carol", Role.RISK_OWNER, strong_auth=True, auth_time=datetime.now(UTC))
    assert gates.decide(tra, Gate.G3, fresh, "approve", "accept").passed


def test_refusals_are_audited():
    log = AuditLog(MemoryAuditSink())
    with pytest.raises(GateError):
        GateService(log).decide(_tra(), Gate.G2, Principal.workload("agent:x"), "approve", "x")
    assert log.sink.read_all()[-1].event_type == "gate_refused"
