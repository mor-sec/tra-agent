"""The orchestrator as a service: one JSON request in, one JSON response out.

The portal (or any client) sends the user's access token and an action:

    {"action": "create", "title": "...", "work_type": "new_system",
     "artefacts": [{"source": "git", "locator": "design.md"}]}
    {"action": "decide", "tra_id": "TRA-2026-001", "gate": "G1",
     "decision": "approve", "rationale": "...",
     "tier_factors": {"internet_facing": true, "handles_cardholder_data": true, "shared_platform": false}}
    {"action": "get", "tra_id": "TRA-2026-001"}
    {"action": "report", "tra_id": "TRA-2026-001"}

Each request validates the token, builds the user's Principal, and runs the
core orchestrator with a `RemoteInvoker` bound to that token. Errors map to
HTTP-style status codes so both platform hosts can return them as they are.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from typing import Any

from tra_core.agents.base import AgentFailure
from tra_core.audit import AuditLog
from tra_core.classification import can_read
from tra_core.gates import GateError
from tra_core.orchestrator import Orchestrator
from tra_core.reference import Reference
from tra_core.register import RegisterWriter, to_csv
from tra_core.report import render
from tra_core.schemas import TRA, Gate, TierFactors, WorkType
from tra_core.store import TraStore
from tra_core.tools import ToolClient, ToolError
from tra_platform.auth import AuthError, ClaimsMapper, TokenExchanger, TokenValidator
from tra_platform.host import RemoteInvoker, Transport


def summary(tra: TRA) -> dict[str, Any]:
    return {
        "id": tra.id,
        "version": tra.version,
        "title": tra.title,
        "stage": tra.stage.value,
        "awaiting_gate": tra.awaiting_gate.value if tra.awaiting_gate else None,
        "classification": tra.classification.label,
        "tier": tra.tier,
        "threats": len(tra.threats),
        "risks": len(tra.risks),
    }


class OrchestratorService:
    def __init__(
        self,
        *,
        validator: TokenValidator,
        store: TraStore,
        audit: AuditLog,
        reference: Reference,
        transport: Transport,
        exchanger: TokenExchanger,
        audiences: dict[str, str],
        tools_for: Callable[[str], ToolClient],
        register: RegisterWriter | None = None,
        mapper: ClaimsMapper | None = None,
    ) -> None:
        self.validator = validator
        self.store = store
        self.audit = audit
        self.reference = reference
        self.transport = transport
        self.exchanger = exchanger
        self.audiences = audiences
        self.tools_for = tools_for
        self.register = register
        self.mapper = mapper or ClaimsMapper()

    async def handle(self, body: dict[str, Any], user_token: str) -> tuple[int, dict[str, Any]]:
        try:
            return 200, await self._dispatch(body, user_token)
        except AuthError as exc:
            return 401, {"error": "unauthorized", "detail": str(exc)}
        except (PermissionError, ToolError) as exc:
            return 403, {"error": "forbidden", "detail": str(exc)}
        except GateError as exc:
            return 409, {"error": "gate_refused", "detail": str(exc)}
        except KeyError as exc:
            return 404, {"error": "not_found", "detail": str(exc)}
        except AgentFailure as exc:
            return 502, {"error": "agent_failed", "detail": str(exc)}
        except ValueError as exc:
            return 400, {"error": "bad_request", "detail": str(exc)}

    def _readable(self, tra_id: str, user: Any) -> TRA:
        tra = self.store.load(tra_id)
        if not can_read(user.clearance, tra.classification):
            raise PermissionError(f"{tra.id} is {tra.classification.label}; your clearance is {user.clearance.label}")
        return tra

    async def _dispatch(self, body: dict[str, Any], user_token: str) -> dict[str, Any]:
        user = self.mapper.human(self.validator.validate(user_token))
        action = body.get("action")
        if action == "get":
            return {"tra": self._readable(body["tra_id"], user).model_dump(mode="json")}
        if action == "report":
            tra = self._readable(body["tra_id"], user)
            return {"tra": summary(tra), "markdown": render(tra, self.reference), "register_csv": to_csv(tra)}

        invoker = RemoteInvoker(self.transport, self.exchanger, self.audiences, self.audit, user_token)
        orch = Orchestrator(self.store, invoker, self.tools_for(user_token), self.audit, self.reference, self.register)
        if action == "create":
            tra = await orch.create(
                title=str(body["title"]),
                work_type=WorkType(body["work_type"]),
                artefacts=[(a["source"], a["locator"]) for a in body["artefacts"]],
                user=user,
            )
            return {"tra": summary(tra)}
        if action == "decide":
            factors = TierFactors.model_validate(body["tier_factors"]) if body.get("tier_factors") is not None else None
            tra, outcome = await orch.decide(
                body["tra_id"], Gate(body["gate"]), user, str(body["decision"]), str(body["rationale"]), factors
            )
            return {"tra": summary(tra), "outcome": asdict(outcome)}
        raise ValueError(f"unknown action {action!r}")
