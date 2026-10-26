"""Specialist agent plumbing: prompt assembly, structured output, validation and retry.

A specialist takes a JSON request and returns a JSON response, so the same
class runs in-process or behind an A2A endpoint. Model output is validated
twice: against the Pydantic schema, then against domain checks (IDs exist,
STRIDE categories fit the element, control IDs are in the catalogue). Failures
go back to the model with the errors, up to `max_attempts`.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from dataclasses import dataclass
from importlib import resources
from typing import Any, ClassVar, Generic, TypeVar

from pydantic import BaseModel, Field, ValidationError

from tra_core.audit import AuditLog
from tra_core.identity import Principal
from tra_core.llm import ModelClient
from tra_core.schemas import Artefact
from tra_core.tools import ToolClient

Out = TypeVar("Out", bound=BaseModel)


class AgentFailure(Exception):
    pass


class SpecialistRequest(BaseModel):
    """What the orchestrator sends a specialist (over A2A in production)."""

    agent: str
    tra_id: str
    tra_version: int
    stage: str
    payload: dict[str, Any]
    reviewer_notes: list[str] = Field(default_factory=list)


@dataclass
class AgentDeps:
    model: ModelClient
    tools: ToolClient
    audit: AuditLog
    actor: Principal


def load_prompt(name: str) -> str:
    return resources.files("tra_core.agents.prompts").joinpath(f"{name}.md").read_text(encoding="utf-8")


def prompt_version(name: str) -> str:
    text = load_prompt("common") + load_prompt(name)
    return hashlib.sha256(text.encode()).hexdigest()[:12]


_UNTRUSTED_TAG = re.compile(r"<(\s*/?\s*(?:artefact|derived)\b)", re.IGNORECASE)


def artefact_block(artefact: Artefact) -> str:
    """Wrap untrusted artefact text so the model can tell data from instructions.

    Any artefact tag inside the text, opening or closing, in any case or
    spacing, is escaped: a design document must not be able to end its own
    block or forge a second one with a different label.
    """
    body = _UNTRUSTED_TAG.sub(r"&lt;\1", artefact.text)
    source, locator = html.escape(artefact.source, quote=True), html.escape(artefact.locator, quote=True)
    return (
        f'<artefact source="{source}" locator="{locator}" '
        f'classification="{artefact.classification.value}" sha256="{artefact.sha256[:12]}">\n{body}\n</artefact>'
    )


def as_json(value: Any) -> str:
    if isinstance(value, BaseModel):
        return value.model_dump_json(indent=1)
    return json.dumps(value, indent=1, default=str)


def derived_block(name: str, value: Any) -> str:
    """Wrap earlier agents' output, which quotes artefacts, so it stays untrusted downstream."""
    body = _UNTRUSTED_TAG.sub(r"&lt;\1", as_json(value))
    return f'<derived name="{html.escape(name, quote=True)}">\n{body}\n</derived>'


class Specialist(Generic[Out]):
    name: ClassVar[str]
    output_model: ClassVar[type[BaseModel]]
    max_attempts: ClassVar[int] = 3

    def __init__(self, deps: AgentDeps) -> None:
        self.deps = deps

    @property
    def prompt_version(self) -> str:
        return prompt_version(self.name)

    def system_prompt(self) -> str:
        return load_prompt("common") + "\n\n" + load_prompt(self.name)

    async def build_user_message(self, request: SpecialistRequest) -> str:
        raise NotImplementedError

    async def check(self, output: Out, request: SpecialistRequest) -> list[str]:
        """Domain checks beyond the schema. Return error strings; empty means valid."""
        return []

    async def handle(self, request: SpecialistRequest) -> dict[str, Any]:
        user = await self.build_user_message(request)
        if request.reviewer_notes:
            notes = "\n".join(f"- {n}" for n in request.reviewer_notes)
            user += f"\n\nReviewer notes from the last gate (address these first):\n{notes}"
        schema = self.output_model.model_json_schema(mode="validation")
        errors: list[str] = []
        for attempt in range(1, self.max_attempts + 1):
            message = user if not errors else user + "\n\nYour previous answer was rejected:\n" + "\n".join(
                f"- {e}" for e in errors[:30]
            )
            raw = await self.deps.model.generate(
                system=self.system_prompt(), user=message, schema=schema, schema_name=self.output_model.__name__
            )
            try:
                output = self.output_model.model_validate_json(raw)
                errors = await self.check(output, request)  # type: ignore[arg-type]
            except ValidationError as exc:
                errors = [f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()]
            if not errors:
                self.deps.audit.record(
                    tra_id=request.tra_id,
                    tra_version=request.tra_version,
                    stage=request.stage,
                    event_type="agent_output",
                    actor=self.deps.actor,
                    detail={"agent": self.name, "attempt": attempt, "prompt_version": self.prompt_version},
                )
                return output.model_dump(mode="json")
            self.deps.audit.record(
                tra_id=request.tra_id,
                tra_version=request.tra_version,
                stage=request.stage,
                event_type="validation_failed",
                actor=self.deps.actor,
                detail={"agent": self.name, "attempt": attempt, "errors": errors[:30]},
            )
        raise AgentFailure(f"{self.name} produced no valid output after {self.max_attempts} attempts: {errors[:5]}")
