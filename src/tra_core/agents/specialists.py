"""The six specialists. Each gathers what it needs with tools, then asks its model."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from tra_core.agents.base import Specialist, SpecialistRequest, artefact_block, as_json, derived_block
from tra_core.checks import automated_checks, check_controls, check_risks, check_threats
from tra_core.reference import Reference
from tra_core.risk import IMPACT_SCALE_AUD, LIKELIHOOD_SCALE
from tra_core.schemas import (
    TRA,
    Artefact,
    ControlAssessment,
    Critique,
    CritiqueIssue,
    IntakeRecord,
    Risk,
    SystemModel,
    Threat,
)
from tra_core.stride import applicable


def _artefacts(payload: dict[str, Any]) -> list[Artefact]:
    return [Artefact.model_validate(a) for a in payload.get("artefacts", [])]


def _artefact_section(payload: dict[str, Any]) -> str:
    return "\n\n".join(artefact_block(a) for a in _artefacts(payload))


# ---------------------------------------------------------------- intake


class IntakeAgent(Specialist[IntakeRecord]):
    name = "intake"
    output_model = IntakeRecord

    async def build_user_message(self, request: SpecialistRequest) -> str:
        p = request.payload
        labels = sorted({a.classification.value for a in _artefacts(p)})
        return (
            f"TRA title: {p['title']}\nRequested work type: {p['work_type']}\n"
            f"Artefact labels: {', '.join(labels)}\n\n{_artefact_section(p)}"
        )

    async def check(self, output: IntakeRecord, request: SpecialistRequest) -> list[str]:
        top = max((a.classification.rank for a in _artefacts(request.payload)), default=0)
        if output.proposed_classification.rank < top:
            return ["proposed_classification is lower than the highest artefact label"]
        return []


# ---------------------------------------------------------------- system model


class SystemModeller(Specialist[SystemModel]):
    name = "system_modeller"
    output_model = SystemModel

    async def build_user_message(self, request: SpecialistRequest) -> str:
        p = request.payload
        return f"Intake record:\n{derived_block('intake', p['intake'])}\n\n{_artefact_section(p)}"

    async def check(self, output: SystemModel, request: SpecialistRequest) -> list[str]:
        errors = []
        zones = {z.id for z in output.zones}
        ids = [e.id for e in output.elements]
        if len(ids) != len(set(ids)):
            errors.append("element ids must be unique")
        if not output.elements:
            errors.append("the model has no elements")
        for e in output.elements:
            if e.zone not in zones:
                errors.append(f"{e.id}: zone {e.zone} is not defined")
        by_id = {e.id: e for e in output.elements}
        for f in output.flows:
            for end in (f.source, f.target):
                if end not in by_id:
                    errors.append(f"{f.id}: {end} is not an element")
            if f.source in by_id and f.target in by_id:
                crosses = by_id[f.source].zone != by_id[f.target].zone
                if crosses != f.crosses_boundary:
                    errors.append(f"{f.id}: crosses_boundary should be {str(crosses).lower()}")
        return errors


# ---------------------------------------------------------------- threats


class ThreatList(BaseModel):
    threats: list[Threat] = Field(min_length=1)


class ThreatAnalyst(Specialist[ThreatList]):
    name = "threat_analyst"
    output_model = ThreatList

    def __init__(self, deps, reference: Reference) -> None:  # type: ignore[no-untyped-def]
        super().__init__(deps)
        self.reference = reference

    async def build_user_message(self, request: SpecialistRequest) -> str:
        model = SystemModel.model_validate(request.payload["system_model"])
        rows = []
        candidates: dict[str, dict[str, Any]] = {}
        for item in [*model.elements, *model.flows]:
            if hasattr(item, "type"):
                kind, is_ai = item.type.value, item.is_ai  # type: ignore[union-attr]
            else:
                kind, is_ai = ("boundary_flow" if item.crosses_boundary else "data_flow"), False  # type: ignore[union-attr]
            cats = "".join(sorted(c.value for c in applicable(item)))
            rows.append(f"| {item.id} | {item.name if hasattr(item, 'name') else item.data} | {kind} | {cats} | {is_ai} |")  # type: ignore[union-attr]
            result = await self.deps.tools.call("threats_search", {"applies_to": kind, "include_ai": is_ai})
            for t in result["threats"]:
                candidates[t["id"]] = t
        table = "| id | name | kind | applicable STRIDE | AI |\n|---|---|---|---|---|\n" + "\n".join(rows)
        library = "\n".join(
            f"- {t['id']} [{','.join(t['stride'])}] {t['title']} (applies to {', '.join(t['applies_to'])}"
            + (f"; ATT&CK {', '.join(t['attack'])}" if t.get("attack") else "")
            + (f"; ATLAS {', '.join(t['atlas'])}" if t.get("atlas") else "")
            + f"): {t['description']}"
            for t in candidates.values()
        )
        return f"System model:\n{derived_block('system_model', model)}\n\nElements and applicable STRIDE:\n{table}\n\nCandidate library threats:\n{library}"

    async def check(self, output: ThreatList, request: SpecialistRequest) -> list[str]:
        model = SystemModel.model_validate(request.payload["system_model"])
        draft = TRA(id="check", title="", work_type="new_system", classification="OFFICIAL", requested_by="",
                    system_model=model, threats=output.threats)
        return check_threats(draft, self.reference)


# ---------------------------------------------------------------- controls


class ControlList(BaseModel):
    controls: list[ControlAssessment]


class ControlMapper(Specialist[ControlList]):
    name = "control_mapper"
    output_model = ControlList

    def __init__(self, deps, reference: Reference) -> None:  # type: ignore[no-untyped-def]
        super().__init__(deps)
        self.reference = reference

    async def build_user_message(self, request: SpecialistRequest) -> str:
        p = request.payload
        catalogue = await self.deps.tools.call("controls_list", {})
        lines = "\n".join(f"- {c['id']} ({c['domain']}): {c['title']}" for c in catalogue["controls"])
        return (
            f"Threats:\n{derived_block('threats', p['threats'])}\n\nControl catalogue (version {catalogue['catalogue_version']}):\n"
            f"{lines}\n\n{_artefact_section(p)}"
        )

    async def check(self, output: ControlList, request: SpecialistRequest) -> list[str]:
        threats = [Threat.model_validate(t) for t in request.payload["threats"]]
        draft = TRA(id="check", title="", work_type="new_system", classification="OFFICIAL", requested_by="",
                    threats=threats, controls=output.controls)
        return check_controls(draft, self.reference)


# ---------------------------------------------------------------- risks


class RiskList(BaseModel):
    risks: list[Risk] = Field(min_length=1)


def _scales() -> str:
    impact = "\n".join(f"- {k} {v[0]}: {v[1]}; {v[2]}" for k, v in IMPACT_SCALE_AUD.items())
    likelihood = "\n".join(f"- {k} {v[0]}: {v[1]}" for k, v in LIKELIHOOD_SCALE.items())
    return (
        f"Impact scale (AUD):\n{impact}\n\nLikelihood scale:\n{likelihood}\n\n"
        "Likelihood modifiers: up one step if the weakness is on an identity or pipeline plane, or if no detection is "
        "designed in; down one step if an independent preventive guardrail blocks the path."
    )


class RiskAssessor(Specialist[RiskList]):
    name = "risk_assessor"
    output_model = RiskList

    def __init__(self, deps, reference: Reference) -> None:  # type: ignore[no-untyped-def]
        super().__init__(deps)
        self.reference = reference

    async def build_user_message(self, request: SpecialistRequest) -> str:
        p = request.payload
        taxonomy = self.reference.taxonomy
        categories = "\n".join(
            f"- {c.id} {c.name}{' (always consider)' if c.always_consider else ''}: {c.definition}\n"
            + "\n".join(f"  - {s.id} {s.name}: {s.description}" for s in c.subcategories)
            for c in taxonomy.categories
        )
        defaults = {t.id: t.risk_category for t in self.reference.threats.threats if t.risk_category}
        return (
            f"{_scales()}\n\nRisk taxonomy (version {taxonomy.version}):\n{categories}\n\n"
            f"Default categories of library threats: {as_json(defaults)}\n\n"
            f"Intake:\n{derived_block('intake', p['intake'])}\n\n"
            f"System model:\n{derived_block('system_model', p['system_model'])}\n\n"
            f"Threats:\n{derived_block('threats', p['threats'])}\n\n"
            f"Control assessments:\n{derived_block('controls', p['controls'])}"
        )

    async def check(self, output: RiskList, request: SpecialistRequest) -> list[str]:
        p = request.payload
        draft = TRA(
            id="check", title="", work_type="new_system", classification="OFFICIAL", requested_by="",
            system_model=SystemModel.model_validate(p["system_model"]),
            threats=[Threat.model_validate(t) for t in p["threats"]],
            controls=[ControlAssessment.model_validate(c) for c in p["controls"]],
            risks=output.risks,
        )
        return check_risks(draft, self.reference)


# ---------------------------------------------------------------- critic


class ModelCritique(BaseModel):
    issues: list[CritiqueIssue]


class QualityCritic(Specialist[ModelCritique]):
    name = "quality_critic"
    output_model = ModelCritique

    def __init__(self, deps, reference: Reference) -> None:  # type: ignore[no-untyped-def]
        super().__init__(deps)
        self.reference = reference

    async def build_user_message(self, request: SpecialistRequest) -> str:
        tra = TRA.model_validate(request.payload["tra"])
        checks = automated_checks(tra, self.reference)
        listed = "\n".join(f"- [{i.severity}] {i.where}: {i.issue}" for i in checks) or "- none"
        body = tra.model_dump(mode="json", include={"intake", "system_model", "threats", "controls", "risks"})
        return f"Automated check results:\n{listed}\n\nDraft TRA:\n{derived_block('draft_tra', body)}"

    async def handle(self, request: SpecialistRequest) -> dict[str, Any]:
        tra = TRA.model_validate(request.payload["tra"])
        checks = automated_checks(tra, self.reference)
        model_view = await super().handle(request)
        issues = checks + [CritiqueIssue.model_validate({**i, "source": "model"}) for i in model_view["issues"]]
        return Critique(issues=issues).model_dump(mode="json")


SPECIALISTS = {
    "intake": IntakeAgent,
    "system_modeller": SystemModeller,
    "threat_analyst": ThreatAnalyst,
    "control_mapper": ControlMapper,
    "risk_assessor": RiskAssessor,
    "quality_critic": QualityCritic,
}
NEEDS_REFERENCE = {"threat_analyst", "control_mapper", "risk_assessor", "quality_critic"}
