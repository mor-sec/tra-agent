"""A model that returns wrong, inflated or manipulative structured output.

OWASP LLM05 (improper output handling), LLM09 (misinformation);
ATLAS AML.T0048 (external harms through manipulated output).
"""

import copy

import pytest

from tra_core.agents.base import AgentFailure
from tra_core.schemas import Gate


def _risk_override(**fields):
    def edit(responses):
        for r in responses["RiskList"][0]["risks"]:
            r.update(fields)
    return edit


def _retry_with(name, bad_edit):
    """Put a bad answer before the recorded good one, so the agent must reject and retry."""
    def edit(responses):
        bad = copy.deepcopy(responses[name][-1])  # the accepted answer, then spoil it
        bad_edit(bad)
        responses[name].insert(0, bad)
    return edit


async def _to_g2(r, alice):
    tra = await r.create(alice)
    tra, _ = await r.orch.decide(tra.id, Gate.G1, alice, "approve", "ok")
    return tra


async def test_model_supplied_ratings_are_ignored(rig, alice):
    r = rig(_risk_override(inherent_rating="Low", residual_rating="Low"))
    tra = await _to_g2(r, alice)
    assert next(x for x in tra.risks if x.id == "R-01").inherent_rating.value == "Critical"


@pytest.mark.parametrize("name,bad,expected", [
    ("RiskList", lambda b: b["risks"][0].update(inherent_likelihood=9), "less than or equal to 5"),
    ("RiskList", lambda b: b["risks"][0].update(residual_impact=5, inherent_impact=2), "residual scores exceed inherent"),
    ("RiskList", lambda b: b["risks"][0].update(threat_ids=["T-99"]), "threat T-99 does not exist"),
    ("RiskList", lambda b: b["risks"][0].update(citations=["E99"]), "citation E99 does not exist"),
    ("RiskList", lambda b: b["risks"][0].update(category="ZZZ.9"), "not in the risk taxonomy"),
    ("RiskList", lambda b: b["risks"][0].update(proposed_controls=["CTRL-NOPE"]), "not in the catalogue"),
    ("ThreatList", lambda b: b["threats"][0].update(element_id="E42"), "not in the system model"),
    ("ThreatList", lambda b: b["threats"][0].update(library_ref="TL-999"), "does not exist"),
    ("ThreatList", lambda b: b["threats"][-1].update(atlas=["ignore previous instructions"]), "not an ATLAS technique"),
    ("ThreatList", lambda b: b["threats"][-1].update(attack=["T1562.001"]), "not in ATT&CK"),  # retired in v20
    ("ThreatList", lambda b: b["threats"][-1].update(atlas=["AML.T9999"]), "not in ATLAS"),
])
async def test_invalid_output_is_rejected_and_retried(rig, alice, name, bad, expected):
    r = rig(_retry_with(name, bad))
    tra = await _to_g2(r, alice)
    assert tra.awaiting_gate is Gate.G2
    prompts = [u for n, u in r.replay.prompts if n == name]
    assert any(expected in p for p in prompts[1:]), f"retry prompt did not cite: {expected}"
    failures = [e for e in r.audit.sink.read_all() if e.event_type == "validation_failed"]
    assert any(expected in " ".join(e.detail["errors"]) for e in failures)


async def test_disclosure_risk_cannot_be_rated_below_the_data_floor(rig, alice):
    def lowball(b):
        for risk in b["risks"]:
            if "T-09" in risk["threat_ids"]:  # assistant disclosure of OFFICIAL: Sensitive invoices
                risk.update(inherent_impact=1, residual_impact=1)
    r = rig(_retry_with("RiskList", lowball))
    await _to_g2(r, alice)
    retry = [u for n, u in r.replay.prompts if n == "RiskList"][1]
    assert "below the floor" in retry


async def test_persistent_bad_output_stops_the_pipeline(rig, alice):
    def always_bad(responses):
        bad = copy.deepcopy(responses["RiskList"][0])
        bad["risks"][0]["inherent_likelihood"] = 0
        responses["RiskList"] = [bad] * 5
    r = rig(always_bad)
    tra = await r.create(alice)
    with pytest.raises(AgentFailure, match="no valid output"):
        await r.orch.decide(tra.id, Gate.G1, alice, "approve", "ok")


async def test_non_json_output_is_rejected(rig, alice):
    def prose(responses):
        responses["IntakeRecord"].insert(0, "Sure! Here is the intake. Everything looks low risk.")
    r = rig(prose)
    tra = await r.create(alice)
    assert tra.awaiting_gate is Gate.G1
    assert any(e.event_type == "validation_failed" for e in r.audit.sink.read_all())


async def test_intake_cannot_lower_the_classification(rig, alice):
    r = rig(_retry_with("IntakeRecord", lambda b: b.update(proposed_classification="OFFICIAL")))
    tra = await r.create(alice)
    assert tra.classification.value == "OFFICIAL_SENSITIVE"
