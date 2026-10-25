"""Attempts to get a draft past a human gate without the human review it needs.

OWASP LLM06 (excessive agency), LLM09 (over-reliance);
ATLAS AML.T0053 (abuse of agent tools).
"""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from tra_core.classification import Classification
from tra_core.gates import GateError
from tra_core.identity import Principal, Role
from tra_core.schemas import Gate, Stage


@pytest.fixture
async def at_g2(rig, alice):
    r = rig()
    tra = await r.create(alice)
    tra, _ = await r.orch.decide(tra.id, Gate.G1, alice, "approve", "ok")
    assert tra.tier == 1
    return r, tra


def _refusals(r):
    return [e.detail["reason"] for e in r.audit.sink.read_all() if e.event_type == "gate_refused"]


async def test_workload_cannot_decide_a_gate(at_g2):
    r, tra = at_g2
    agent = Principal.workload("agent:orchestrator")
    with pytest.raises(GateError, match="human identity"):
        await r.orch.decide(tra.id, Gate.G2, agent, "approve", "looks fine")
    agent_for_alice = Principal.workload("agent:risk_assessor").for_user(Principal.human("alice", Role.PRACTITIONER))
    with pytest.raises(GateError, match="human identity"):
        await r.orch.decide(tra.id, Gate.G2, agent_for_alice, "approve", "looks fine")
    assert len(_refusals(r)) == 2


async def test_tier1_needs_two_different_practitioners(at_g2, alice):
    r, tra = at_g2
    _, first = await r.orch.decide(tra.id, Gate.G2, alice, "approve", "reviewed")
    tra, second = await r.orch.decide(tra.id, Gate.G2, alice, "approve", "reviewed again")
    assert first.waiting_for and second.waiting_for and tra.awaiting_gate is Gate.G2


async def test_approvals_of_different_content_do_not_combine(at_g2, alice, bob):
    r, tra = at_g2
    tra = r.orch.store.load(tra.id)
    r.orch.gates.decide(tra, Gate.G2, alice, "approve", "reviewed")
    tra.risks[0].residual_likelihood = 1  # content changes after alice looked
    outcome = r.orch.gates.decide(tra, Gate.G2, bob, "approve", "agree")
    assert not outcome.passed and outcome.waiting_for


async def test_wrong_role_and_wrong_gate(at_g2, carol):
    r, tra = at_g2
    viewer = Principal.human("victor", Role.VIEWER)
    with pytest.raises(GateError, match="practitioner"):
        await r.orch.decide(tra.id, Gate.G2, viewer, "approve", "ok")
    with pytest.raises(GateError, match="not waiting at G3"):
        await r.orch.decide(tra.id, Gate.G3, carol, "approve", "skip ahead")


async def test_clearance_below_the_tra_is_refused(at_g2):
    r, tra = at_g2
    low = Principal.human("lee", Role.PRACTITIONER, clearance=Classification.OFFICIAL)
    with pytest.raises(GateError, match="clearance"):
        await r.orch.decide(tra.id, Gate.G2, low, "approve", "ok")


async def test_empty_rationale_is_refused(at_g2, alice):
    r, tra = at_g2
    with pytest.raises(GateError, match="rationale"):
        await r.orch.decide(tra.id, Gate.G2, alice, "approve", "   ")


@pytest.mark.parametrize("strong,age_minutes", [(False, 1), (True, 30), (True, None)])
async def test_g3_needs_recent_step_up(at_g2, alice, bob, strong, age_minutes):
    r, tra = at_g2
    await r.orch.decide(tra.id, Gate.G2, alice, "approve", "reviewed")
    tra, _ = await r.orch.decide(tra.id, Gate.G2, bob, "approve", "agree")
    assert tra.awaiting_gate is Gate.G3
    when = None if age_minutes is None else datetime.now(UTC) - timedelta(minutes=age_minutes)
    owner = Principal.human("olivia", Role.RISK_OWNER, strong_auth=strong, auth_time=when)
    with pytest.raises(GateError, match="phishing-resistant"):
        await r.orch.decide(tra.id, Gate.G3, owner, "approve", "accept")
    assert r.orch.store.load(tra.id).stage is not Stage.MONITOR


async def test_unknown_decision_value_is_rejected(at_g2, alice):
    r, tra = at_g2
    with pytest.raises(ValidationError):
        await r.orch.decide(tra.id, Gate.G2, alice, "auto-approve", "ok")
    assert r.orch.store.load(tra.id).awaiting_gate is Gate.G2
