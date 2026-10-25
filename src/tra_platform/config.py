"""Settings for a deployed container, from environment variables set by the IaC.

Every container image is the same; `TRA_ROLE` picks what it runs. Endpoints
and audiences are JSON maps so the same settings shape works on both platforms.

| Variable | Used by | Meaning |
|---|---|---|
| TRA_ROLE | all | `orchestrator`, a specialist name, `mcp-reference` or `mcp-artefacts` |
| TRA_IDP_ISSUER, TRA_IDP_JWKS_URL | all | The IdP that signs user and delegation tokens |
| TRA_AUDIENCE | all | This service's own audience (application ID URI) |
| TRA_ALLOWED_CALLERS | specialists, MCP | Comma-separated actor IDs allowed to call this service |
| TRA_EXCHANGE | orchestrator, specialists | `entra-obo` or `rfc8693` |
| TRA_TENANT_ID, TRA_CLIENT_ID | entra-obo | This service's app registration |
| TRA_TOKEN_ENDPOINT | rfc8693 | The IdP's token endpoint |
| TRA_SPECIALISTS | orchestrator | `{"intake": {"endpoint": "...", "audience": "..."}, ...}` |
| TRA_MCP | orchestrator, specialists | `{"reference": {"endpoint": "...", "audience": "..."}, "artefacts": {...}}` |
| TRA_MODELS_FILE | specialists | Model routing (default: config/models.yaml in the image) |
| TRA_STATE_URI, TRA_AUDIT_URI | orchestrator | `s3://bucket/prefix`, `https://<account>.blob.core.windows.net/<container>` or `file:///path` |
| TRA_KMS_KEY_ID | orchestrator on AWS | KMS key for S3 writes |
| TRA_GIT_ROOT, TRA_CONFLUENCE_* | mcp-artefacts | Artefact sources (see `tra_core.mcp_servers`) |
| TRA_BEDROCK_ROLE_ARN | Foundry specialists | IAM role to assume through Entra federation, for Claude on Bedrock |
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tra_platform.auth import (
    ClaimsMapper,
    DelegationValidator,
    EntraOboExchanger,
    JwksKeySource,
    Rfc8693Exchanger,
    TokenExchanger,
    TokenValidator,
)
from tra_platform.storage import BlobObjectStore, LocalObjectStore, ObjectStore, S3ObjectStore


@dataclass(frozen=True)
class Endpoint:
    endpoint: str
    audience: str


def _endpoints(raw: str) -> dict[str, Endpoint]:
    return {k: Endpoint(v["endpoint"], v["audience"]) for k, v in json.loads(raw or "{}").items()}


@dataclass
class Settings:
    role: str
    issuer: str
    jwks_url: str
    audience: str
    allowed_callers: frozenset[str] = frozenset()
    exchange: str = "entra-obo"
    tenant_id: str = ""
    client_id: str = ""
    token_endpoint: str = ""
    specialists: dict[str, Endpoint] = field(default_factory=dict)
    mcp: dict[str, Endpoint] = field(default_factory=dict)
    models_file: Path = Path("config/models.yaml")
    state_uri: str = ""
    audit_uri: str = ""
    kms_key_id: str | None = None
    bedrock_role_arn: str = ""

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        e = dict(os.environ if env is None else env)
        return cls(
            role=e["TRA_ROLE"],
            issuer=e["TRA_IDP_ISSUER"],
            jwks_url=e["TRA_IDP_JWKS_URL"],
            audience=e["TRA_AUDIENCE"],
            allowed_callers=frozenset(c.strip() for c in e.get("TRA_ALLOWED_CALLERS", "").split(",") if c.strip()),
            exchange=e.get("TRA_EXCHANGE", "entra-obo"),
            tenant_id=e.get("TRA_TENANT_ID", ""),
            client_id=e.get("TRA_CLIENT_ID", ""),
            token_endpoint=e.get("TRA_TOKEN_ENDPOINT", ""),
            specialists=_endpoints(e.get("TRA_SPECIALISTS", "")),
            mcp=_endpoints(e.get("TRA_MCP", "")),
            models_file=Path(e.get("TRA_MODELS_FILE", "config/models.yaml")),
            state_uri=e.get("TRA_STATE_URI", ""),
            audit_uri=e.get("TRA_AUDIT_URI", ""),
            kms_key_id=e.get("TRA_KMS_KEY_ID") or None,
            bedrock_role_arn=e.get("TRA_BEDROCK_ROLE_ARN", ""),
        )

    def validator(self) -> TokenValidator:
        return TokenValidator(self.issuer, self.audience, JwksKeySource(self.jwks_url))

    def delegation(self, mapper: ClaimsMapper | None = None) -> DelegationValidator:
        if not self.allowed_callers:
            raise ValueError("TRA_ALLOWED_CALLERS is empty: nobody could call this service")
        return DelegationValidator(self.validator(), self.allowed_callers, self.role, mapper or ClaimsMapper())

    def exchanger(self, client_assertion: Any = None, client_secret: Any = None) -> TokenExchanger:
        if self.exchange == "entra-obo":
            if client_assertion is None:
                raise ValueError("Entra OBO needs a client assertion source")
            return EntraOboExchanger(self.tenant_id, self.client_id, client_assertion)
        if self.exchange == "rfc8693":
            if client_secret is None:
                raise ValueError("RFC 8693 exchange needs a client secret source")
            return Rfc8693Exchanger(self.token_endpoint, self.client_id, client_secret)
        raise ValueError(f"unknown TRA_EXCHANGE {self.exchange!r}")


def object_store(uri: str, kms_key_id: str | None = None) -> ObjectStore:
    if uri.startswith("s3://"):
        bucket, _, prefix = uri[5:].partition("/")
        return S3ObjectStore(bucket, kms_key_id, prefix + "/" if prefix and not prefix.endswith("/") else prefix)
    if uri.startswith("https://") and ".blob." in uri:
        account, _, container = uri[8:].partition("/")
        return BlobObjectStore(f"https://{account}", container)
    if uri.startswith("file://"):
        return LocalObjectStore(Path(uri[7:]))
    raise ValueError(f"unsupported storage URI {uri!r}")
