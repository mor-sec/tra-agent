"""Human review gates. The only path by which a TRA moves past G1, G2 or G3.

Policy is enforced here, in code, so it holds however the agents behave:
workloads can never decide a gate, roles and clearance are checked, Tier 1
needs two practitioners at G2, and G3 needs a fresh phishing-resistant sign-in.
"""

from __future__ import annotations

from dataclasses import dataclass

from tra_core.audit import AuditLog
from tra_core.classification import can_read
from tra_core.identity import Principal, PrincipalKind, Role
from tra_core.schemas import TRA, Gate, GateDecision

GATE_ROLE = {Gate.G1: Role.PRACTITIONER, Gate.G2: Role.PRACTITIONER, Gate.G3: Role.RISK_OWNER}
STEP_UP_MAX_AGE_SECONDS = 600


class GateError(Exception):
    pass


@dataclass
class GateOutcome:
    passed: bool
    returned: bool
    waiting_for: str | None = None


class GateService:
    def __init__(self, audit: AuditLog) -> None:
        self.audit = audit

    def _refuse(self, tra: TRA, gate: Gate, principal: Principal, reason: str) -> GateError:
        self.audit.record(
            tra_id=tra.id,
            tra_version=tra.version,
            stage=tra.stage.value,
            event_type="gate_refused",
            actor=principal,
            detail={"gate": gate.value, "reason": reason},
        )
        return GateError(reason)

    def decide(
        self,
        tra: TRA,
        gate: Gate,
        principal: Principal,
        decision: str,
        rationale: str,
    ) -> GateOutcome:
        if principal.kind is not PrincipalKind.HUMAN:
            raise self._refuse(tra, gate, principal, "gate decisions require a human identity")
        if tra.awaiting_gate is not gate:
            raise self._refuse(tra, gate, principal, f"TRA is not waiting at {gate.value}")
        role = GATE_ROLE[gate]
        if not principal.has(role):
            raise self._refuse(tra, gate, principal, f"{gate.value} needs the {role.value} role")
        if not can_read(principal.clearance, tra.classification):
            raise self._refuse(tra, gate, principal, "clearance is below the TRA's classification")
        if gate is Gate.G3:
            age = principal.auth_age_seconds()
            if not principal.strong_auth or age is None or age > STEP_UP_MAX_AGE_SECONDS:
                raise self._refuse(tra, gate, principal, "G3 needs phishing-resistant MFA within the last 10 minutes")
        if not rationale.strip():
            raise self._refuse(tra, gate, principal, "a rationale is required")

        record = GateDecision(
            gate=gate,
            decision=decision,  # type: ignore[arg-type]
            by=principal.subject,
            role=role.value,
            rationale=rationale,
            tra_hash=tra.content_hash(),
        )
        tra.gates.append(record)
        self.audit.record(
            tra_id=tra.id,
            tra_version=tra.version,
            stage=tra.stage.value,
            event_type="gate_decision",
            actor=principal,
            detail=record.model_dump(mode="json"),
        )

        if decision == "return":
            return GateOutcome(passed=False, returned=True)

        if gate is Gate.G2 and tra.tier == 1:
            approvers = {
                g.by
                for g in tra.gates
                if g.gate is Gate.G2 and g.decision != "return" and g.tra_hash == record.tra_hash
            }
            if len(approvers) < 2:
                return GateOutcome(passed=False, returned=False, waiting_for="a second practitioner (Tier 1)")
        return GateOutcome(passed=True, returned=False)
