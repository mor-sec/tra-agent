from datetime import UTC, datetime, timedelta

import pytest

from tra_core.audit import AuditLog, JsonlAuditSink, MemoryAuditSink, verify
from tra_core.gates import GateError, GateService
from tra_core.identity import Principal, Role
from tra_core.schemas import TRA, Classification, CritiqueIssue, Gate, Risk, Stage, TierFactors, Treatment, WorkType


def _tra(**kw) -> TRA:
    base = dict(id="TRA-2026-900", title="t", work_type=WorkType.NEW_SYSTEM,
                classification=Classification.OFFICIAL_SENSITIVE, requested_by="alice", tier=2,
                stage=Stage.EVALUATION, awaiting_gate=Gate.G2)
    base.update(kw)
    return TRA(**base)


def _no_issues(tra: TRA) -> list[CritiqueIssue]:
    return []


def _issues(severity: str):
    return lambda tra: [CritiqueIssue(severity=severity, where="F01", issue="x", source="check")]


def _risk(residual_likelihood: int, residual_impact: int) -> Risk:
    return Risk(id="R-01", threat_ids=["T-01"], statement="s", category="APP.1", inherent_likelihood=5,
                inherent_impact=5, residual_likelihood=residual_likelihood, residual_impact=residual_impact,
                rationale="r", citations=["T-01"], treatment=Treatment.MITIGATE)


def _owner(sub: str, *roles: Role) -> Principal:
    return Principal.human(sub, *roles, strong_auth=True, auth_time=datetime.now(UTC))


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
    gates = GateService(AuditLog(MemoryAuditSink()), _no_issues)
    agent = Principal.workload("agent:risk_assessor", acting_for="alice")
    with pytest.raises(GateError, match="human"):
        gates.decide(_tra(), Gate.G2, agent, "approve", "looks fine")


def test_role_and_clearance_enforced():
    gates = GateService(AuditLog(MemoryAuditSink()), _no_issues)
    with pytest.raises(GateError, match="practitioner"):
        gates.decide(_tra(), Gate.G2, Principal.human("v", Role.VIEWER), "approve", "x")
    low = Principal.human("p", Role.PRACTITIONER, clearance=Classification.OFFICIAL)
    with pytest.raises(GateError, match="clearance"):
        gates.decide(_tra(), Gate.G2, low, "approve", "x")


def test_gate_must_be_the_one_waiting():
    gates = GateService(AuditLog(MemoryAuditSink()), _no_issues)
    with pytest.raises(GateError, match="not waiting"):
        gates.decide(_tra(), Gate.G1, Principal.human("p", Role.PRACTITIONER), "approve", "x")


def test_tier1_needs_two_distinct_practitioners():
    gates = GateService(AuditLog(MemoryAuditSink()), _no_issues)
    tra = _tra(tier=1)
    alice = Principal.human("alice", Role.PRACTITIONER)
    assert not gates.decide(tra, Gate.G2, alice, "approve", "ok").passed
    assert not gates.decide(tra, Gate.G2, alice, "approve", "ok again").passed
    assert gates.decide(tra, Gate.G2, Principal.human("bob", Role.PRACTITIONER), "approve", "ok").passed


def test_g3_needs_fresh_strong_auth():
    gates = GateService(AuditLog(MemoryAuditSink()), _no_issues)
    tra = _tra(stage=Stage.ACCEPTANCE, awaiting_gate=Gate.G3)
    stale = Principal.human("carol", Role.RISK_OWNER, strong_auth=True,
                            auth_time=datetime.now(UTC) - timedelta(minutes=30))
    with pytest.raises(GateError, match="MFA"):
        gates.decide(tra, Gate.G3, stale, "approve", "accept")
    fresh = Principal.human("carol", Role.RISK_OWNER, strong_auth=True, auth_time=datetime.now(UTC))
    assert gates.decide(tra, Gate.G3, fresh, "approve", "accept").passed


def test_g2_refuses_blockers_and_needs_changes_for_majors():
    alice = Principal.human("alice", Role.PRACTITIONER)
    with pytest.raises(GateError, match="blocker"):
        GateService(AuditLog(MemoryAuditSink()), _issues("blocker")).decide(_tra(), Gate.G2, alice, "approve_with_changes", "x")
    majors = GateService(AuditLog(MemoryAuditSink()), _issues("major"))
    with pytest.raises(GateError, match="approve_with_changes"):
        majors.decide(_tra(), Gate.G2, alice, "approve", "x")
    assert majors.decide(_tra(), Gate.G2, alice, "approve_with_changes", "F01 covered in treatment").passed
    assert majors.decide(_tra(), Gate.G2, alice, "return", "fix F01").returned


@pytest.mark.parametrize("residual,needs_ciso", [((4, 4), True), ((5, 5), True), ((2, 2), False)])
def test_g3_accepters_follow_the_worst_residual_rating(residual, needs_ciso):
    gates = GateService(AuditLog(MemoryAuditSink()), _no_issues)
    tra = _tra(stage=Stage.ACCEPTANCE, awaiting_gate=Gate.G3, risks=[_risk(*residual)])
    first = gates.decide(tra, Gate.G3, _owner("carol", Role.RISK_OWNER), "approve", "accept")
    assert first.passed is not needs_ciso
    if needs_ciso:
        assert "ciso" in first.waiting_for
        assert gates.decide(tra, Gate.G3, _owner("dana", Role.CISO), "approve", "concur").passed


def test_g3_one_person_cannot_fill_both_accepter_roles():
    gates = GateService(AuditLog(MemoryAuditSink()), _no_issues)
    tra = _tra(stage=Stage.ACCEPTANCE, awaiting_gate=Gate.G3, risks=[_risk(4, 4)])
    both = _owner("pat", Role.RISK_OWNER, Role.CISO)
    assert not gates.decide(tra, Gate.G3, both, "approve", "accept").passed
    assert not gates.decide(tra, Gate.G3, both, "approve", "accept again").passed
    assert gates.decide(tra, Gate.G3, _owner("carol", Role.RISK_OWNER), "approve", "accept").passed


def test_g1_approval_must_confirm_the_tier_factors():
    gates = GateService(AuditLog(MemoryAuditSink()), _no_issues)
    tra = _tra(stage=Stage.INTAKE, awaiting_gate=Gate.G1)
    alice = Principal.human("alice", Role.PRACTITIONER)
    with pytest.raises(GateError, match="tier factors"):
        gates.decide(tra, Gate.G1, alice, "approve", "scope ok")
    assert gates.decide(tra, Gate.G1, alice, "return", "missing the network diagram").returned
    factors = TierFactors(internet_facing=False, handles_cardholder_data=False, shared_platform=True)
    assert gates.decide(tra, Gate.G1, alice, "approve", "scope ok", factors).passed
    assert tra.gates[-1].tier_factors == factors
    with pytest.raises(GateError, match="G1 only"):
        gates.decide(_tra(), Gate.G2, alice, "approve", "x", factors)


def test_refusals_are_audited():
    log = AuditLog(MemoryAuditSink())
    with pytest.raises(GateError):
        GateService(log, _no_issues).decide(_tra(), Gate.G2, Principal.workload("agent:x"), "approve", "x")
    assert log.sink.read_all()[-1].event_type == "gate_refused"
