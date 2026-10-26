"""Typed records for a TRA. Agents produce these; validators reject anything else.

Ratings are never taken from a model: `Risk` computes them from likelihood and
impact with the SAR 5x5 matrix, so a rating can't disagree with its scores.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, computed_field

from tra_core.risk import Rating, rate


def utcnow() -> datetime:
    return datetime.now(UTC)


_CLASSIFICATION_ORDER = ["UNOFFICIAL", "OFFICIAL", "OFFICIAL_SENSITIVE", "PROTECTED", "SECRET", "TOP_SECRET"]


class Classification(str, Enum):
    """PSPF security classifications. Compare with `rank`, not string order."""

    UNOFFICIAL = "UNOFFICIAL"
    OFFICIAL = "OFFICIAL"
    OFFICIAL_SENSITIVE = "OFFICIAL_SENSITIVE"
    PROTECTED = "PROTECTED"
    SECRET = "SECRET"
    TOP_SECRET = "TOP_SECRET"

    @property
    def rank(self) -> int:
        return _CLASSIFICATION_ORDER.index(self.value)

    @property
    def label(self) -> str:
        return {"OFFICIAL_SENSITIVE": "OFFICIAL: Sensitive", "TOP_SECRET": "TOP SECRET"}.get(self.value, self.value)

    @classmethod
    def parse(cls, value: str | Classification) -> Classification:
        if isinstance(value, Classification):
            return value
        key = value.strip().upper().replace(":", "").replace("-", "_").replace(" ", "_")
        key = {"OS": "OFFICIAL_SENSITIVE", "O": "OFFICIAL"}.get(key, key)
        return cls(key)


class WorkType(str, Enum):
    NEW_SYSTEM = "new_system"
    DESIGN_CHANGE = "design_change"
    NEW_CONTROL = "new_control"
    FINDING_TRIAGE = "finding_triage"
    INCIDENT = "incident"


class Stage(str, Enum):
    INTAKE = "intake"
    CONTEXT = "context"
    THREATS = "threats"
    ANALYSIS = "analysis"
    EVALUATION = "evaluation"
    TREATMENT = "treatment"
    ACCEPTANCE = "acceptance"
    MONITOR = "monitor"


class Gate(str, Enum):
    G1 = "G1"  # scope, classification and tier confirmed
    G2 = "G2"  # threats and ratings approved
    G3 = "G3"  # risk owner accepts or treats residual risk


class Stride(str, Enum):
    S = "S"
    T = "T"
    R = "R"
    I = "I"  # noqa: E741
    D = "D"
    E = "E"


class ElementType(str, Enum):
    EXTERNAL_ENTITY = "external_entity"
    PROCESS = "process"
    DATA_STORE = "data_store"


class Treatment(str, Enum):
    MITIGATE = "mitigate"
    AVOID = "avoid"
    TRANSFER = "transfer"
    ACCEPT = "accept"


# ---------------------------------------------------------------- artefacts


class ArtefactRef(BaseModel):
    """A design artefact as the agent saw it. `sha256` pins the exact version."""

    source: str  # e.g. "git", "confluence", "upload"
    locator: str  # path, page id or URL
    title: str
    classification: Classification
    sha256: str
    revision: str | None = None  # commit SHA or page version


class Artefact(ArtefactRef):
    text: str


# ---------------------------------------------------------------- intake


class IntakeRecord(BaseModel):
    summary: str = Field(description="Two or three sentences on what is being assessed")
    work_type: WorkType
    proposed_classification: Classification
    internet_facing: bool
    handles_cardholder_data: bool
    shared_platform: bool = Field(description="Landing zone, identity, CI/CD or other shared platform")
    missing_information: list[str] = Field(default_factory=list)
    risk_owner: str | None = None
    tier: int | None = Field(default=None, description="Set by code, not by the model")


class TierFactors(BaseModel):
    """The tiering facts as the practitioner confirms them at G1; they replace the model's proposal."""

    internet_facing: bool
    handles_cardholder_data: bool
    shared_platform: bool


# ---------------------------------------------------------------- system model


class Element(BaseModel):
    id: str = Field(pattern=r"^E\d{2,3}$")
    name: str
    type: ElementType
    description: str
    zone: str = Field(description="Trust zone id the element sits in")
    classification: Classification
    is_ai: bool = Field(description="Model, agent, retrieval index, training pipeline or MCP tool")
    technologies: list[str] = Field(default_factory=list)
    evidence: str = Field(description="Short quote or reference from the artefact")


class DataFlow(BaseModel):
    id: str = Field(pattern=r"^F\d{2,3}$")
    source: str
    target: str
    data: str
    classification: Classification
    protocol: str | None = None
    crosses_boundary: bool
    authenticated: bool | None = None
    encrypted: bool | None = None
    evidence: str


class TrustZone(BaseModel):
    id: str
    name: str
    description: str


class Asset(BaseModel):
    id: str = Field(pattern=r"^A\d{2,3}$")
    name: str
    kind: Literal["data", "identity", "key", "pipeline", "service", "model"]
    classification: Classification
    confidentiality: int = Field(ge=1, le=5)
    integrity: int = Field(ge=1, le=5)
    availability: int = Field(ge=1, le=5)


class SystemModel(BaseModel):
    name: str
    summary: str
    zones: list[TrustZone]
    elements: list[Element]
    flows: list[DataFlow]
    assets: list[Asset]

    def element(self, element_id: str) -> Element | DataFlow | None:
        for item in [*self.elements, *self.flows]:
            if item.id == element_id:
                return item
        return None


# ---------------------------------------------------------------- threats, controls, risks


class Threat(BaseModel):
    id: str = Field(pattern=r"^T-\d{2,3}$")
    element_id: str = Field(description="Element (E..) or flow (F..) the threat applies to")
    stride: list[Stride] = Field(min_length=1)
    attack: list[str] = Field(default_factory=list, description="MITRE ATT&CK Enterprise technique IDs, T.... or T....nnn")
    atlas: list[str] = Field(default_factory=list, description="MITRE ATLAS technique IDs, AML.T....")
    library_ref: str | None = Field(default=None, description="Threat library ID this came from, if any")
    statement: str
    evidence: str


class ControlStatus(str, Enum):
    IN_PLACE = "in_place"
    PARTIAL = "partial"
    MISSING = "missing"


class ControlAssessment(BaseModel):
    control_id: str = Field(pattern=r"^CC-\d{3}$")
    status: ControlStatus
    threat_ids: list[str]
    evidence: str


class Risk(BaseModel):
    id: str = Field(pattern=r"^R-\d{2,3}$")
    threat_ids: list[str] = Field(min_length=1)
    statement: str = Field(description="[actor] could [action] via [weakness], leading to [impact]")
    category: str = Field(pattern=r"^[A-Z]{3}\.\d$", description="Risk taxonomy category of the root cause, such as SUP.2")
    inherent_likelihood: int = Field(ge=1, le=5)
    inherent_impact: int = Field(ge=1, le=5)
    residual_likelihood: int = Field(ge=1, le=5)
    residual_impact: int = Field(ge=1, le=5)
    rationale: str = Field(description="Why these scores, citing elements, threats and control evidence")
    citations: list[str] = Field(min_length=1, description="Element, flow, threat or control IDs relied on")
    treatment: Treatment
    proposed_controls: list[str] = Field(default_factory=list)
    owner: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def inherent_rating(self) -> Rating:
        return rate(self.inherent_likelihood, self.inherent_impact)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def residual_rating(self) -> Rating:
        return rate(self.residual_likelihood, self.residual_impact)


class CritiqueIssue(BaseModel):
    severity: Literal["blocker", "major", "minor"]
    where: str
    issue: str
    source: Literal["check", "model"] = "model"


class Critique(BaseModel):
    issues: list[CritiqueIssue] = Field(default_factory=list)

    @property
    def blocking(self) -> bool:
        return any(i.severity == "blocker" for i in self.issues)


# ---------------------------------------------------------------- gates and the TRA


class GateDecision(BaseModel):
    gate: Gate
    decision: Literal["approve", "approve_with_changes", "return"]
    by: str
    role: str
    rationale: str
    tra_hash: str
    tier_factors: TierFactors | None = None  # G1 approvals only
    at: datetime = Field(default_factory=utcnow)


class TRA(BaseModel):
    id: str
    version: int = 1
    title: str
    work_type: WorkType
    classification: Classification
    tier: int | None = None
    stage: Stage = Stage.INTAKE
    awaiting_gate: Gate | None = None
    requested_by: str
    artefacts: list[ArtefactRef] = Field(default_factory=list)
    intake: IntakeRecord | None = None
    system_model: SystemModel | None = None
    threats: list[Threat] = Field(default_factory=list)
    controls: list[ControlAssessment] = Field(default_factory=list)
    risks: list[Risk] = Field(default_factory=list)
    critique: Critique | None = None
    gates: list[GateDecision] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    def content_hash(self) -> str:
        """Hash of the assessable content, excluding gate history and timestamps."""
        body = self.model_dump(
            mode="json",
            exclude={"gates", "created_at", "updated_at", "stage", "awaiting_gate", "version"},
        )
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
