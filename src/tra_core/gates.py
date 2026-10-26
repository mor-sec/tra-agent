"""Human review gates. The only path by which a TRA moves past G1, G2 or G3.

Policy is enforced here, in code, so it holds however the agents behave:
workloads can never decide a gate, roles and clearance are checked, Tier 1
needs two practitioners at G2, G2 cannot pass blocker issues and needs
approve_with_changes over major ones, G3 needs a fresh phishing-resistant
sign-in and the accepters `risk.AUTHORITY` names for the worst residual risk.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from tra_core.audit import AuditLog
from tra_core.classification import can_read
from tra_core.identity import Principal, PrincipalKind, Role
from tra_core.risk import Rating
from tra_core.schemas import TRA, CritiqueIssue, Gate, GateDecision, TierFactors

GATE_ROLES = {Gate.G1: (Role.PRACTITIONER,), Gate.G2: (Role.PRACTITIONER,), Gate.G3: (Role.RISK_OWNER, Role.CISO)}
# Who must accept at G3, by the worst residual rating (risk.AUTHORITY who_may_accept).
# shortcut: the risk committee (Critical) and security architect concurrence (Medium)
# are not modelled as roles; add them when the IdP carries them.
ACCEPTERS = {Rating.CRITICAL: (Role.RISK_OWNER, Role.CISO), Rating.HIGH: (Role.RISK_OWNER, Role.CISO)}
STEP_UP_MAX_AGE_SECONDS = 600


class GateError(Exception):
    pass


@dataclass
class GateOutcome:
    passed: bool
    returned: bool
    waiting_for: str | None = None


def accepters(tra: TRA) -> tuple[Role, ...]:
    worst = max((r.residual_rating for r in tra.risks), key=list(Rating).index, default=Rating.LOW)
    return ACCEPTERS.get(worst, (Role.RISK_OWNER,))


class GateService:
    """`checks` returns the deterministic issues for a draft (checks.automated_checks), rerun at G2."""

    def __init__(self, audit: AuditLog, checks: Callable[[TRA], list[CritiqueIssue]]) -> None:
        self.audit = audit
        self.checks = checks

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
        tier_factors: TierFactors | None = None,
    ) -> GateOutcome:
        if principal.kind is not PrincipalKind.HUMAN:
            raise self._refuse(tra, gate, principal, "gate decisions require a human identity")
        if tra.awaiting_gate is not gate:
            raise self._refuse(tra, gate, principal, f"TRA is not waiting at {gate.value}")
        held = [r for r in GATE_ROLES[gate] if principal.has(r)]
        if not held:
            names = " or ".join(r.value for r in GATE_ROLES[gate])
            raise self._refuse(tra, gate, principal, f"{gate.value} needs the {names} role")
        if not can_read(principal.clearance, tra.classification):
            raise self._refuse(tra, gate, principal, "clearance is below the TRA's classification")
        if gate is Gate.G3:
            age = principal.auth_age_seconds()
            if not principal.strong_auth or age is None or age > STEP_UP_MAX_AGE_SECONDS:
                raise self._refuse(tra, gate, principal, "G3 needs phishing-resistant MFA within the last 10 minutes")
        if not rationale.strip():
            raise self._refuse(tra, gate, principal, "a rationale is required")
        # The tier sets G2's two-person rule, so a human states its facts rather than the intake model.
        if gate is Gate.G1 and decision != "return" and tier_factors is None:
            raise self._refuse(tra, gate, principal, "G1 approval must confirm the tier factors")
        if gate is not Gate.G1 and tier_factors is not None:
            raise self._refuse(tra, gate, principal, "tier factors are confirmed at G1 only")
        if gate is Gate.G2 and decision != "return":
            # Rerun the checks rather than trust the stored critique; model issues come from the critic.
            model_issues = [i for i in tra.critique.issues if i.source == "model"] if tra.critique else []
            issues = self.checks(tra) + model_issues
            if blockers := [i for i in issues if i.severity == "blocker"]:
                where = ", ".join(i.where for i in blockers[:5])
                raise self._refuse(tra, gate, principal, f"G2 cannot pass with blocker issues ({where}); return it")
            if decision == "approve" and any(i.severity == "major" for i in issues):
                raise self._refuse(
                    tra, gate, principal, "major issues are open; use approve_with_changes and address them in the rationale"
                )

        tra_hash = tra.content_hash()
        prior = [g for g in tra.gates if g.gate is gate and g.decision != "return" and g.tra_hash == tra_hash]
        # Someone holding both G3 roles fills the one not yet recorded.
        role = next((r for r in held if r.value not in {g.role for g in prior}), held[0])
        record = GateDecision(
            gate=gate,
            decision=decision,  # type: ignore[arg-type]
            by=principal.subject,
            role=role.value,
            rationale=rationale,
            tra_hash=tra_hash,
            tier_factors=tier_factors if decision != "return" else None,
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

        approvals = [*prior, record]
        people = {g.by for g in approvals}
        if gate is Gate.G2 and tra.tier == 1 and len(people) < 2:
            return GateOutcome(passed=False, returned=False, waiting_for="a second practitioner (Tier 1)")
        if gate is Gate.G3:
            needed = accepters(tra)
            missing = [r.value for r in needed if r.value not in {g.role for g in approvals}]
            if missing or len(people) < len(needed):
                waiting = " and ".join(missing) or "a different person"
                return GateOutcome(passed=False, returned=False, waiting_for=f"{waiting} to co-accept (worst residual risk)")
        return GateOutcome(passed=True, returned=False)
