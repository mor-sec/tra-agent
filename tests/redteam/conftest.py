"""Helpers for the red-team tests: an orchestrator over edited recordings."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tra_core.artefacts import GitArtefactSource
from tra_core.audit import AuditLog, MemoryAuditSink
from tra_core.llm import ModelRouter, ReplayModelClient
from tra_core.orchestrator import LocalInvoker, Orchestrator
from tra_core.reference import Reference
from tra_core.schemas import WorkType
from tra_core.store import FileTraStore
from tra_core.tools import LocalToolClient, ToolSet

ROOT = Path(__file__).resolve().parents[2]
RECORDING = json.loads((ROOT / "tests" / "fixtures" / "replay_payments.json").read_text())
EXAMPLES = ROOT / "examples" / "artefacts"


class Rig:
    def __init__(self, tmp: Path, responses: dict[str, list[Any]], artefact_root: Path = EXAMPLES) -> None:
        self.reference = Reference()
        self.audit = AuditLog(MemoryAuditSink())
        self.replay = ReplayModelClient(responses)
        self.tools = LocalToolClient(ToolSet(self.reference, {"git": GitArtefactSource(artefact_root)}))
        router = ModelRouter({}, overrides={"*": self.replay})
        self.orch = Orchestrator(
            FileTraStore(tmp / "tras"), LocalInvoker(router, self.tools, self.audit, self.reference),
            self.tools, self.audit, self.reference,
        )

    async def create(self, user, locator: str = "payments-portal-design.md"):
        return await self.orch.create(
            title="Customer payments portal", work_type=WorkType.NEW_SYSTEM, artefacts=[("git", locator)], user=user
        )


@pytest.fixture
def rig(tmp_path) -> Callable[..., Rig]:
    """rig(edit=None, artefact_root=EXAMPLES): `edit` gets a deep copy of the recording to change."""

    def make(edit: Callable[[dict[str, list[Any]]], None] | None = None, artefact_root: Path = EXAMPLES) -> Rig:
        responses = copy.deepcopy(RECORDING)
        if edit:
            edit(responses)
        return Rig(tmp_path, responses, artefact_root)

    return make
