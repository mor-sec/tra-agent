"""Model access behind one small interface, so agents don't care which platform runs them.

Every call asks for JSON matching a schema. Bedrock gets it by forcing a tool
call; Azure OpenAI by `response_format`. The caller validates the result.
"""

from __future__ import annotations

import asyncio
import copy
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import yaml

from tra_core.audit import AuditLog, digest
from tra_core.identity import Principal


class ModelError(Exception):
    pass


class ModelClient(Protocol):
    model_id: str

    async def generate(self, *, system: str, user: str, schema: dict[str, Any], schema_name: str) -> str:
        """Return a JSON document (as text) that should match `schema`."""
        ...


def inline_refs(schema: dict[str, Any]) -> dict[str, Any]:
    """Resolve local $ref/$defs so providers with partial JSON Schema support accept it."""
    schema = copy.deepcopy(schema)
    defs = schema.pop("$defs", {})

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node and node["$ref"].startswith("#/$defs/"):
                target = walk(copy.deepcopy(defs[node["$ref"].split("/")[-1]]))
                extras = {k: v for k, v in node.items() if k != "$ref"}
                return {**target, **extras}
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node

    return walk(schema)


class BedrockClient:
    """Amazon Bedrock Converse API. Use AU geographic inference profile IDs to keep inference in Australia."""

    def __init__(self, model_id: str, region: str = "ap-southeast-2", max_tokens: int = 16000, client: Any = None):
        self.model_id = model_id
        self.max_tokens = max_tokens
        if client is None:
            import boto3  # optional dependency

            client = boto3.client("bedrock-runtime", region_name=region)
        self._client = client

    def _call(self, system: str, user: str, schema: dict[str, Any], schema_name: str) -> str:
        resp = self._client.converse(
            modelId=self.model_id,
            system=[{"text": system}],
            messages=[{"role": "user", "content": [{"text": user}]}],
            inferenceConfig={"maxTokens": self.max_tokens},
            toolConfig={
                "tools": [
                    {
                        "toolSpec": {
                            "name": schema_name,
                            "description": f"Return the {schema_name} result.",
                            "inputSchema": {"json": inline_refs(schema)},
                        }
                    }
                ],
                "toolChoice": {"tool": {"name": schema_name}},
            },
        )
        for block in resp["output"]["message"]["content"]:
            if "toolUse" in block:
                return json.dumps(block["toolUse"]["input"])
        raise ModelError(f"{self.model_id} returned no {schema_name} tool call (stopReason={resp.get('stopReason')})")

    async def generate(self, *, system: str, user: str, schema: dict[str, Any], schema_name: str) -> str:
        return await asyncio.to_thread(self._call, system, user, schema, schema_name)


class AzureOpenAIClient:
    """Azure OpenAI (Foundry) chat completions with Entra ID auth. Use a regional deployment in Australia East."""

    def __init__(
        self,
        endpoint: str,
        deployment: str,
        api_version: str = "2024-10-21",
        client: Any = None,
        credential: Any = None,
    ):
        self.model_id = deployment
        if client is None:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider  # optional dependency
            from openai import AsyncAzureOpenAI

            token_provider = get_bearer_token_provider(
                credential or DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
            )
            client = AsyncAzureOpenAI(
                azure_endpoint=endpoint, azure_ad_token_provider=token_provider, api_version=api_version
            )
        self._client = client

    async def generate(self, *, system: str, user: str, schema: dict[str, Any], schema_name: str) -> str:
        resp = await self._client.chat.completions.create(
            model=self.model_id,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            response_format={
                "type": "json_schema",
                "json_schema": {"name": schema_name, "schema": inline_refs(schema), "strict": False},
            },
        )
        content = resp.choices[0].message.content
        if not content:
            raise ModelError(f"{self.model_id} returned an empty response")
        return content


class ReplayModelClient:
    """Returns recorded responses in order, per schema name. For tests and offline demos only."""

    def __init__(self, responses: dict[str, list[Any]], model_id: str = "replay") -> None:
        self.model_id = model_id
        self._responses = {k: list(v) for k, v in responses.items()}
        self.prompts: list[tuple[str, str]] = []

    @classmethod
    def from_file(cls, path: Path) -> ReplayModelClient:
        return cls(json.loads(path.read_text(encoding="utf-8")))

    async def generate(self, *, system: str, user: str, schema: dict[str, Any], schema_name: str) -> str:
        self.prompts.append((schema_name, user))
        queue = self._responses.get(schema_name)
        if not queue:
            raise ModelError(f"no recorded response left for {schema_name}")
        item = queue.pop(0)
        return item if isinstance(item, str) else json.dumps(item)


class AuditedModelClient:
    """Logs each call: model, prompt version, and hashes of what went in and came out.

    Full prompt and response bodies go to `blob_dir` by hash, so the audit
    stream stays small but every call can be replayed.
    """

    def __init__(
        self,
        inner: ModelClient,
        audit: AuditLog,
        actor: Principal,
        tra_ref: Callable[[], tuple[str, int, str | None]],
        prompt_version: str,
        blob_dir: Path | None = None,
    ) -> None:
        self.inner = inner
        self.model_id = inner.model_id
        self.audit = audit
        self.actor = actor
        self.tra_ref = tra_ref
        self.prompt_version = prompt_version
        self.blob_dir = blob_dir

    def _store(self, text: str) -> str:
        h = digest(text)
        if self.blob_dir is not None:
            self.blob_dir.mkdir(parents=True, exist_ok=True)
            path = self.blob_dir / h
            if not path.exists():
                path.write_text(text, encoding="utf-8")
        return h

    async def generate(self, *, system: str, user: str, schema: dict[str, Any], schema_name: str) -> str:
        out = await self.inner.generate(system=system, user=user, schema=schema, schema_name=schema_name)
        tra_id, version, stage = self.tra_ref()
        self.audit.record(
            tra_id=tra_id,
            tra_version=version,
            stage=stage,
            event_type="model_call",
            actor=self.actor,
            detail={
                "model_id": self.model_id,
                "prompt_version": self.prompt_version,
                "schema": schema_name,
                "system_sha256": self._store(system),
                "input_sha256": self._store(user),
                "output_sha256": self._store(out),
            },
        )
        return out


# ---------------------------------------------------------------- routing


@dataclass
class ModelRoute:
    provider: str
    model: str


class ModelRouter:
    """Which model each agent uses, from config/models.yaml.

    `bedrock_client` and `azure_credential` let a host on the other cloud supply
    federated credentials (see `tra_platform.federation`); otherwise each SDK
    finds its own credentials.
    """

    def __init__(
        self,
        config: dict[str, Any],
        overrides: dict[str, ModelClient] | None = None,
        bedrock_client: Any = None,
        azure_credential: Any = None,
    ) -> None:
        self.config = config
        self.overrides = overrides or {}
        self.bedrock_client = bedrock_client
        self.azure_credential = azure_credential
        self._cache: dict[tuple[str, str], ModelClient] = {}

    @classmethod
    def from_file(cls, path: Path, **kwargs: Any) -> ModelRouter:
        return cls(yaml.safe_load(path.read_text(encoding="utf-8")), **kwargs)

    def route(self, agent: str) -> ModelRoute:
        agents = self.config.get("agents", {})
        entry = agents.get(agent) or agents.get("default")
        if entry is None:
            raise ModelError(f"no model configured for {agent}")
        return ModelRoute(entry["provider"], entry["model"])

    def client_for(self, agent: str) -> ModelClient:
        if agent in self.overrides:
            return self.overrides[agent]
        if "*" in self.overrides:
            return self.overrides["*"]
        r = self.route(agent)
        key = (r.provider, r.model)
        if key not in self._cache:
            p = self.config.get("providers", {}).get(r.provider, {})
            if r.provider == "bedrock":
                self._cache[key] = BedrockClient(
                    r.model, region=p.get("region", "ap-southeast-2"), client=self.bedrock_client
                )
            elif r.provider == "azure":
                self._cache[key] = AzureOpenAIClient(
                    p["endpoint"], r.model, p.get("api_version", "2024-10-21"), credential=self.azure_credential
                )
            else:
                raise ModelError(f"unknown provider {r.provider}")
        return self._cache[key]
