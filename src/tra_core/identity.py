"""Who is acting. Adapters build a Principal from a validated token; core code never parses tokens.

A Principal is either a human (from the user's Entra ID token) or a workload
acting for a human (from an exchanged token whose `act` claim names the agent).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from tra_core.schemas import Classification


class PrincipalKind(str, Enum):
    HUMAN = "human"
    WORKLOAD = "workload"


class Role(str, Enum):
    VIEWER = "viewer"
    PRACTITIONER = "practitioner"
    RISK_OWNER = "risk_owner"
    CISO = "ciso"
    ADMIN = "admin"


@dataclass(frozen=True)
class Principal:
    subject: str
    kind: PrincipalKind
    roles: frozenset[Role] = field(default_factory=frozenset)
    clearance: Classification = Classification.OFFICIAL
    acting_for: str | None = None  # for workloads: the user subject from the token
    strong_auth: bool = False  # phishing-resistant MFA asserted by the IdP (acr/amr)
    auth_time: datetime | None = None

    @classmethod
    def human(
        cls,
        subject: str,
        *roles: Role,
        clearance: Classification = Classification.OFFICIAL_SENSITIVE,
        strong_auth: bool = False,
        auth_time: datetime | None = None,
    ) -> Principal:
        return cls(subject, PrincipalKind.HUMAN, frozenset(roles), clearance, None, strong_auth, auth_time)

    @classmethod
    def workload(cls, subject: str, acting_for: str | None = None) -> Principal:
        return cls(subject, PrincipalKind.WORKLOAD, frozenset(), Classification.OFFICIAL, acting_for)

    def for_user(self, user: Principal) -> Principal:
        """This workload acting on behalf of `user`, inheriting the user's clearance."""
        return Principal(self.subject, PrincipalKind.WORKLOAD, frozenset(), user.clearance, user.subject)

    def has(self, role: Role) -> bool:
        return role in self.roles

    def auth_age_seconds(self, now: datetime | None = None) -> float | None:
        if self.auth_time is None:
            return None
        return ((now or datetime.now(UTC)) - self.auth_time).total_seconds()
