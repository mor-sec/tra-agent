from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tra_core.artefacts import GitArtefactSource
from tra_core.audit import AuditLog, MemoryAuditSink
from tra_core.identity import Principal, Role
from tra_core.llm import ModelRouter, ReplayModelClient
from tra_core.orchestrator import LocalInvoker, Orchestrator
from tra_core.reference import Reference
from tra_core.register import CsvRegisterWriter
from tra_core.store import FileTraStore
from tra_core.tools import LocalToolClient, ToolSet

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "artefacts"
REPLAY = ROOT / "tests" / "fixtures" / "replay_payments.json"


@pytest.fixture
def reference() -> Reference:
    return Reference()


@pytest.fixture
def audit() -> AuditLog:
    return AuditLog(MemoryAuditSink())


@pytest.fixture
def replay() -> ReplayModelClient:
    return ReplayModelClient(json.loads(REPLAY.read_text()))


@pytest.fixture
def toolset(reference: Reference) -> ToolSet:
    return ToolSet(reference, {"git": GitArtefactSource(EXAMPLES)})


@pytest.fixture
def orchestrator(tmp_path: Path, reference: Reference, audit: AuditLog, replay: ReplayModelClient, toolset: ToolSet) -> Orchestrator:
    tools = LocalToolClient(toolset)
    router = ModelRouter({}, overrides={"*": replay})
    invoker = LocalInvoker(router, tools, audit, reference)
    return Orchestrator(FileTraStore(tmp_path / "tras"), invoker, tools, audit, reference, CsvRegisterWriter(tmp_path / "reg"))


@pytest.fixture
def alice() -> Principal:
    return Principal.human("alice", Role.PRACTITIONER)


@pytest.fixture
def bob() -> Principal:
    return Principal.human("bob", Role.PRACTITIONER)


@pytest.fixture
def carol() -> Principal:
    return Principal.human("carol", Role.RISK_OWNER, strong_auth=True, auth_time=datetime.now(UTC))
