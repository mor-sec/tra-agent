from __future__ import annotations

import json

import httpx
import pytest

from tests.conftest import REPLAY
from tra_core.agents.specialists import SPECIALISTS
from tra_core.llm import ModelRouter, ReplayModelClient
from tra_core.tools import LocalToolClient
from tra_platform.a2a import A2ATransport, build_a2a_app
from tra_platform.auth import DelegationValidator, LocalSigner, TokenValidator
from tra_platform.host import SpecialistHost

ORCHESTRATOR = "tra-orchestrator"
PORTAL_AUDIENCE = "api://tra-orchestrator"


def audience(agent: str) -> str:
    return f"api://tra-{agent}"


@pytest.fixture
def signer() -> LocalSigner:
    return LocalSigner()


@pytest.fixture
def make_host(signer, reference, toolset):
    def make(agent: str, replay: ReplayModelClient, allowed=frozenset({ORCHESTRATOR})) -> SpecialistHost:
        validator = TokenValidator(signer.issuer, audience(agent), signer.keys)
        return SpecialistHost(
            agent,
            ModelRouter({}, overrides={"*": replay}),
            reference,
            DelegationValidator(validator, allowed, agent),
            tools_for=lambda _token: LocalToolClient(toolset),
        )

    return make


@pytest.fixture
def a2a_apps(make_host):
    replay = ReplayModelClient(json.loads(REPLAY.read_text()))
    return {a: build_a2a_app(make_host(a, replay), f"http://{a}.test/") for a in SPECIALISTS}


@pytest.fixture
def a2a_transport(a2a_apps) -> A2ATransport:
    return A2ATransport(
        {a: f"http://{a}.test/" for a in a2a_apps},
        http_client_factory=lambda agent: httpx.AsyncClient(transport=httpx.ASGITransport(app=a2a_apps[agent])),
    )


@pytest.fixture
def store_artefact(toolset) -> dict:
    return toolset.artefacts_get("git", "payments-portal-design.md")
