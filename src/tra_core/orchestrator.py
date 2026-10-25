"""The TRA orchestrator: runs the stage machine, calls specialists, stops at gates.

Specialists are reached through an `Invoker`, so the orchestrator neither knows
nor cares whether they run in-process (`LocalInvoker`) or behind A2A endpoints
on AgentCore or Foundry (the platform adapters provide those invokers).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from tra_core.agents.base import AgentDeps, SpecialistRequest, prompt_version
from tra_core.agents.specialists import NEEDS_REFERENCE, SPECIALISTS
from tra_core.audit import AuditLog
from tra_core.classification import check_accepted, derived_label
from tra_core.gates import GateOutcome, GateService
from tra_core.identity import Principal, PrincipalKind, Role
from tra_core.llm import AuditedModelClient, ModelRouter
from tra_core.reference import Reference
from tra_core.register import RegisterWriter
from tra_core.risk import tier as compute_tier
from tra_core.schemas import (
    TRA,
    Artefact,
    ArtefactRef,
    ControlAssessment,
    Critique,
    Gate,
    IntakeRecord,
    Risk,
    Stage,
    SystemModel,
    Threat,
    WorkType,
)
from tra_core.store import TraStore
from tra_core.tools import AuditedToolClient, ToolClient
from tra_core.workflow import RETURN_TO, gate_after, next_stage


class Invoker(Protocol):
    async def invoke(self, request: SpecialistRequest, on_behalf_of: Principal) -> dict[str, Any]: ...


class LocalInvoker:
    """Runs specialists in-process, each with its own audited model and tool clients."""

    def __init__(
        self,
        router: ModelRouter,
        tools: ToolClient,
        audit: AuditLog,
        reference: Reference,
        blob_dir: Path | None = None,
    ) -> None:
        self.router = router
        self.tools = tools
        self.audit = audit
        self.reference = reference
        self.blob_dir = blob_dir

    async def invoke(self, request: SpecialistRequest, on_behalf_of: Principal) -> dict[str, Any]:
        return await run_specialist(
            request, on_behalf_of, self.router, self.tools, self.audit, self.reference, self.blob_dir
        )


async def run_specialist(
    request: SpecialistRequest,
    on_behalf_of: Principal,
    router: ModelRouter,
    tools: ToolClient,
    audit: AuditLog,
    reference: Reference,
    blob_dir: Path | None = None,
) -> dict[str, Any]:
    """Run one specialist for one request. Shared by the local invoker and the platform hosts."""
    cls = SPECIALISTS[request.agent]
    actor = Principal.workload(f"agent:{request.agent}").for_user(on_behalf_of)
    model = AuditedModelClient(
        router.client_for(request.agent),
        audit,
        actor,
        lambda: (request.tra_id, request.tra_version, request.stage),
        prompt_version(request.agent),
        blob_dir,
    )
    audited_tools = AuditedToolClient(tools, audit, actor, request.tra_id, request.tra_version)
    audited_tools.stage = request.stage
    deps = AgentDeps(model=model, tools=audited_tools, audit=audit, actor=actor)
    agent = cls(deps, reference) if request.agent in NEEDS_REFERENCE else cls(deps)  # type: ignore[call-arg]
    return await agent.handle(request)


class Orchestrator:
    def __init__(
        self,
        store: TraStore,
        invoker: Invoker,
        tools: ToolClient,
        audit: AuditLog,
        reference: Reference,
        register: RegisterWriter | None = None,
    ) -> None:
        self.store = store
        self.invoker = invoker
        self.tools = tools
        self.audit = audit
        self.reference = reference
        self.register = register
        self.gates = GateService(audit)
        self.workload = Principal.workload("agent:orchestrator")

    # ------------------------------------------------------------ helpers

    def _log(self, tra: TRA, event_type: str, actor: Principal, **detail: Any) -> None:
        self.audit.record(
            tra_id=tra.id, tra_version=tra.version, stage=tra.stage.value,
            event_type=event_type, actor=actor, detail=detail,  # type: ignore[arg-type]
            classification=tra.classification.value,
        )

    async def _call(self, tra: TRA, agent: str, user: Principal, payload: dict[str, Any], notes: list[str]) -> dict[str, Any]:
        request = SpecialistRequest(
            agent=agent, tra_id=tra.id, tra_version=tra.version, stage=tra.stage.value,
            payload=payload, reviewer_notes=notes,
        )
        return await self.invoker.invoke(request, user)

    def _require_human(self, user: Principal, role: Role) -> None:
        if user.kind is not PrincipalKind.HUMAN or not user.has(role):
            raise PermissionError(f"needs a human with the {role.value} role")

    # ------------------------------------------------------------ lifecycle

    async def create(
        self,
        *,
        title: str,
        work_type: WorkType,
        artefacts: list[tuple[str, str]],
        user: Principal,
    ) -> TRA:
        """Open a TRA from (source, locator) artefact references and run it to G1."""
        self._require_human(user, Role.PRACTITIONER)
        tra_id = self.store.next_id()
        actor = self.workload.for_user(user)
        loaded: list[Artefact] = []
        for source, locator in artefacts:
            raw = await AuditedToolClient(self.tools, self.audit, actor, tra_id, 1).call(
                "artefacts_get", {"source": source, "locator": locator}
            )
            artefact = Artefact.model_validate(raw)
            check_accepted(artefact.classification)
            loaded.append(artefact)
        tra = TRA(
            id=tra_id,
            title=title,
            work_type=work_type,
            classification=derived_label(a.classification for a in loaded),
            requested_by=user.subject,
            artefacts=[ArtefactRef.model_validate(a.model_dump(exclude={"text"})) for a in loaded],
        )
        for a in loaded:
            self.store.save_artefact(tra.id, a)
        self.store.save(tra)
        self._log(tra, "tra_created", user, title=title, artefacts=[a.sha256 for a in loaded])
        return await self.advance(tra.id, user)

    async def advance(self, tra_id: str, user: Principal, notes: list[str] | None = None) -> TRA:
        """Run stages until the TRA reaches a gate (or the final stage)."""
        tra = self.store.load(tra_id)
        notes = notes or []
        while tra.awaiting_gate is None:
            await self._run_stage(tra, user, notes)
            notes = []
            gate = gate_after(tra.stage)
            if gate is not None:
                tra.awaiting_gate = gate
                self.store.save(tra)
                self._log(tra, "gate_requested", self.workload.for_user(user), gate=gate.value)
                break
            if tra.stage is Stage.MONITOR:
                break
            self._move(tra, next_stage(tra.stage), user)
        return tra

    def _move(self, tra: TRA, stage: Stage, user: Principal) -> None:
        old = tra.stage
        tra.stage = stage
        self.store.save(tra)
        self._log(tra, "stage_changed", self.workload.for_user(user), **{"from": old.value, "to": stage.value})

    async def decide(self, tra_id: str, gate: Gate, user: Principal, decision: str, rationale: str) -> tuple[TRA, GateOutcome]:
        tra = self.store.load(tra_id)
        outcome = self.gates.decide(tra, gate, user, decision, rationale)
        if outcome.returned:
            tra.awaiting_gate = None
            tra.version += 1
            self._move(tra, RETURN_TO[gate], user)
            return await self.advance(tra.id, user, notes=[rationale]), outcome
        if not outcome.passed:
            self.store.save(tra)
            return tra, outcome
        tra.awaiting_gate = None
        self._move(tra, next_stage(tra.stage), user)
        return await self.advance(tra.id, user), outcome

    # ------------------------------------------------------------ stages

    async def _run_stage(self, tra: TRA, user: Principal, notes: list[str]) -> None:
        artefacts = [a.model_dump(mode="json") for a in self.store.load_artefacts(tra)]
        if tra.stage is Stage.INTAKE:
            out = await self._call(tra, "intake", user, {
                "title": tra.title, "work_type": tra.work_type.value, "artefacts": artefacts,
            }, notes)
            intake = IntakeRecord.model_validate(out)
            tra.classification = derived_label([tra.classification, intake.proposed_classification])
            intake.tier = compute_tier(
                classification_rank=tra.classification.rank,
                internet_facing=intake.internet_facing,
                handles_cardholder_data=intake.handles_cardholder_data,
                shared_platform=intake.shared_platform,
            )
            tra.intake, tra.tier, tra.work_type = intake, intake.tier, intake.work_type
        elif tra.stage is Stage.CONTEXT:
            out = await self._call(tra, "system_modeller", user, {
                "intake": tra.intake.model_dump(mode="json") if tra.intake else {}, "artefacts": artefacts,
            }, notes)
            tra.system_model = SystemModel.model_validate(out)
        elif tra.stage is Stage.THREATS:
            out = await self._call(tra, "threat_analyst", user, {
                "system_model": tra.system_model.model_dump(mode="json") if tra.system_model else {},
            }, notes)
            tra.threats = [Threat.model_validate(t) for t in out["threats"]]
        elif tra.stage is Stage.ANALYSIS:
            threats = [t.model_dump(mode="json") for t in tra.threats]
            out = await self._call(tra, "control_mapper", user, {
                "threats": threats, "artefacts": artefacts,
            }, notes)
            tra.controls = [ControlAssessment.model_validate(c) for c in out["controls"]]
            out = await self._call(tra, "risk_assessor", user, {
                "intake": tra.intake.model_dump(mode="json") if tra.intake else {},
                "system_model": tra.system_model.model_dump(mode="json") if tra.system_model else {},
                "threats": threats,
                "controls": [c.model_dump(mode="json") for c in tra.controls],
            }, notes)
            tra.risks = [Risk.model_validate(r) for r in out["risks"]]
        elif tra.stage is Stage.EVALUATION:
            out = await self._call(tra, "quality_critic", user, {"tra": tra.model_dump(mode="json")}, notes)
            tra.critique = Critique.model_validate(out)
        elif tra.stage is Stage.TREATMENT:
            owner = tra.intake.risk_owner if tra.intake else None
            for r in tra.risks:
                r.owner = r.owner or owner
        elif tra.stage is Stage.ACCEPTANCE:
            pass  # the report is rendered on demand; the risk owner decides at G3
        elif tra.stage is Stage.MONITOR:
            if self.register is not None:
                where = self.register.write(tra)
                self._log(tra, "export", self.workload.for_user(user), register=where)
        self.store.save(tra)
