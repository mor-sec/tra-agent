"""Tokens in, Principals out; and delegation tokens for agent-to-agent calls.

The core never parses tokens (see `tra_core.identity`). This module does, for
every platform:

- `TokenValidator` checks a JWT's signature, issuer, audience and expiry
  against the IdP's published keys.
- `ClaimsMapper` turns validated claims into a `Principal`: roles, PSPF
  clearance, and whether the sign-in met the step-up policy G3 needs.
- `DelegationValidator` is what a specialist runs on each request. It accepts
  only a token issued for this specialist (audience), naming the user (subject)
  and the orchestrator (actor), and returns the user it acts for. A specialist
  never sees the user's original token.
- `TokenExchanger` is how the orchestrator gets such a token: RFC 8693 token
  exchange, or Entra ID on-behalf-of where the IdP is Entra.

Platform authorizers (AgentCore's inbound JWT authorizer, Foundry's Entra
front door) check tokens before the container sees the request. The checks
here run again inside the container, so a misconfigured authorizer fails
closed rather than open.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

import jwt

from tra_core.identity import Principal, Role
from tra_core.schemas import Classification


class AuthError(Exception):
    """The token is missing, invalid, or does not grant what was asked."""


class KeySource(Protocol):
    def key_for(self, token: str) -> Any: ...


class JwksKeySource:
    """Signing keys from the IdP's JWKS endpoint, cached by PyJWT."""

    def __init__(self, jwks_url: str) -> None:
        self.client = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=3600)

    def key_for(self, token: str) -> Any:
        return self.client.get_signing_key_from_jwt(token).key


class StaticKeySource:
    """Fixed public keys by `kid`. For tests and local development."""

    def __init__(self, keys: dict[str, Any]) -> None:
        self.keys = keys

    def key_for(self, token: str) -> Any:
        kid = jwt.get_unverified_header(token).get("kid")
        if kid not in self.keys:
            raise AuthError(f"unknown signing key {kid!r}")
        return self.keys[kid]


@dataclass
class TokenValidator:
    issuer: str
    audience: str | list[str]
    keys: KeySource
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    leeway_seconds: int = 60

    def validate(self, token: str) -> dict[str, Any]:
        if not token:
            raise AuthError("no token")
        try:
            return jwt.decode(
                token,
                key=self.keys.key_for(token),
                algorithms=list(self.algorithms),
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"token rejected: {exc}") from exc


def bearer(header_value: str | None) -> str:
    if not header_value or not header_value.lower().startswith("bearer "):
        raise AuthError("expected a bearer token")
    return header_value.split(" ", 1)[1].strip()


DEFAULT_ROLE_MAP = {
    "TRA.Viewer": Role.VIEWER,
    "TRA.Practitioner": Role.PRACTITIONER,
    "TRA.RiskOwner": Role.RISK_OWNER,
    "TRA.CISO": Role.CISO,
    "TRA.Admin": Role.ADMIN,
}

DEFAULT_CLEARANCE_MAP = {
    "TRA.Clearance.Official": Classification.OFFICIAL,
    "TRA.Clearance.OfficialSensitive": Classification.OFFICIAL_SENSITIVE,
}


@dataclass
class ClaimsMapper:
    """Maps IdP claims to a Principal. Defaults follow Entra ID app roles.

    Clearance comes from an app role (or group) the identity team assigns from
    the personnel security record; the highest one held wins, and someone with
    none is treated as OFFICIAL. PROTECTED is never mapped while the system is
    capped at OFFICIAL: Sensitive.

    Step-up: Entra puts satisfied authentication contexts in `acrs`. Configure a
    conditional access authentication context (for example `c1`) that requires
    phishing-resistant MFA with sign-in frequency "every time", and list it in
    `step_up_acrs`. Access tokens carry no `auth_time`, so `iat` stands in for it:
    a token minted under that policy was minted at the step-up.
    """

    role_claim: str = "roles"
    role_map: dict[str, Role] = field(default_factory=lambda: dict(DEFAULT_ROLE_MAP))
    clearance_map: dict[str, Classification] = field(default_factory=lambda: dict(DEFAULT_CLEARANCE_MAP))
    subject_claim: str = "oid"  # Entra object ID; stable across UPN changes
    step_up_acrs: frozenset[str] = frozenset({"c1"})
    step_up_amr: frozenset[str] = frozenset({"phr", "phrh", "fido", "hwk"})

    def _values(self, claims: dict[str, Any], name: str) -> list[str]:
        raw = claims.get(name, [])
        return [raw] if isinstance(raw, str) else list(raw)

    def subject(self, claims: dict[str, Any]) -> str:
        return str(claims.get(self.subject_claim) or claims["sub"])

    def human(self, claims: dict[str, Any]) -> Principal:
        held = self._values(claims, self.role_claim) + self._values(claims, "groups")
        roles = [self.role_map[r] for r in held if r in self.role_map]
        clearances = [self.clearance_map[r] for r in held if r in self.clearance_map]
        clearance = max(clearances, key=lambda c: c.rank, default=Classification.OFFICIAL)
        stepped_up = bool(
            self.step_up_acrs & set(self._values(claims, "acrs"))
            or self.step_up_amr & set(self._values(claims, "amr"))
        )
        when = claims.get("auth_time") or claims.get("iat")
        auth_time = datetime.fromtimestamp(int(when), UTC) if stepped_up and when else None
        return Principal.human(
            self.subject(claims), *roles, clearance=clearance, strong_auth=stepped_up, auth_time=auth_time
        )


@dataclass
class DelegationValidator:
    """Run by a specialist on every request.

    The token must be addressed to this specialist and must name an allowed
    caller as the actor: the `act` claim (RFC 8693) or, for Entra OBO tokens,
    the calling application in `azp`/`appid`.
    """

    validator: TokenValidator
    allowed_actors: frozenset[str]
    agent_name: str
    mapper: ClaimsMapper = field(default_factory=ClaimsMapper)

    @staticmethod
    def actor_of(claims: dict[str, Any]) -> str | None:
        act = claims.get("act")
        if isinstance(act, dict) and act.get("sub"):
            return str(act["sub"])
        return claims.get("azp") or claims.get("appid")

    def user(self, token: str) -> Principal:
        """The user this request acts for. The host runs the specialist as agent-for-user."""
        claims = self.validator.validate(token)
        actor = self.actor_of(claims)
        if actor not in self.allowed_actors:
            raise AuthError(f"caller {actor!r} may not invoke {self.agent_name}")
        return self.mapper.human(claims)


class TokenExchanger(Protocol):
    async def exchange(self, subject_token: str, audience: str) -> str: ...


TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class _Cached:
    def __init__(self) -> None:
        self._cache: dict[tuple[str, str], tuple[str, float]] = {}

    def get(self, subject_token: str, audience: str) -> str | None:
        hit = self._cache.get((subject_token, audience))
        return hit[0] if hit and hit[1] - 60 > time.time() else None

    def put(self, subject_token: str, audience: str, token: str, expires_in: int) -> None:
        self._cache[(subject_token, audience)] = (token, time.time() + expires_in)


async def _post_form(url: str, form: dict[str, str]) -> dict[str, Any]:
    import httpx

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, data=form)
    if resp.status_code != 200:
        raise AuthError(f"token endpoint returned {resp.status_code}: {resp.text[:200]}")
    return resp.json()


class Rfc8693Exchanger:
    """RFC 8693 token exchange (Okta, Ping, Keycloak, Cognito with a pre-token hook, etc.)."""

    def __init__(self, token_endpoint: str, client_id: str, client_secret: Callable[[], Awaitable[str]]) -> None:
        self.token_endpoint = token_endpoint
        self.client_id = client_id
        self.client_secret = client_secret
        self.cache = _Cached()

    async def exchange(self, subject_token: str, audience: str) -> str:
        if hit := self.cache.get(subject_token, audience):
            return hit
        body = await _post_form(
            self.token_endpoint,
            {
                "grant_type": TOKEN_EXCHANGE_GRANT,
                "subject_token": subject_token,
                "subject_token_type": ACCESS_TOKEN_TYPE,
                "requested_token_type": ACCESS_TOKEN_TYPE,
                "audience": audience,
                "client_id": self.client_id,
                "client_secret": await self.client_secret(),
            },
        )
        self.cache.put(subject_token, audience, body["access_token"], int(body.get("expires_in", 300)))
        return body["access_token"]


class EntraOboExchanger:
    """Entra ID on-behalf-of. The orchestrator authenticates with a client assertion.

    `client_assertion` returns a signed assertion: a federated credential from the
    platform's workload identity (AgentCore workload identity via an IAM OIDC
    federation, or the Foundry agent's managed identity). No client secrets.
    `audience` is the specialist's application ID URI; the scope requested is
    `<audience>/.default`.
    """

    def __init__(self, tenant_id: str, client_id: str, client_assertion: Callable[[], Awaitable[str]]) -> None:
        self.token_endpoint = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        self.client_id = client_id
        self.client_assertion = client_assertion
        self.cache = _Cached()

    async def exchange(self, subject_token: str, audience: str) -> str:
        if hit := self.cache.get(subject_token, audience):
            return hit
        body = await _post_form(
            self.token_endpoint,
            {
                "grant_type": JWT_BEARER_GRANT,
                "requested_token_use": "on_behalf_of",
                "assertion": subject_token,
                "scope": f"{audience}/.default",
                "client_id": self.client_id,
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": await self.client_assertion(),
            },
        )
        self.cache.put(subject_token, audience, body["access_token"], int(body.get("expires_in", 300)))
        return body["access_token"]


class LocalSigner:
    """Mints user and delegation tokens with a local key. Tests and local runs only.

    Never configure this in a deployed environment: it is an IdP in a box.
    """

    def __init__(self, issuer: str = "https://idp.local", kid: str = "local-1") -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa

        self.issuer = issuer
        self.kid = kid
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @property
    def keys(self) -> StaticKeySource:
        return StaticKeySource({self.kid: self._key.public_key()})

    def user_token(self, sub: str, roles: Iterable[str], audience: str, ttl: int = 600, **extra: Any) -> str:
        now = int(time.time())
        claims = {"iss": self.issuer, "sub": sub, "aud": audience, "iat": now, "exp": now + ttl, "roles": list(roles)}
        return jwt.encode({**claims, **extra}, self._key, algorithm="RS256", headers={"kid": self.kid})

    def exchanger(self, actor: str) -> TokenExchanger:
        signer = self

        class _Exchanger:
            async def exchange(self, subject_token: str, audience: str) -> str:
                claims = jwt.decode(
                    subject_token, signer._key.public_key(), algorithms=["RS256"], options={"verify_aud": False}
                )
                claims.update(aud=audience, act={"sub": actor}, exp=int(time.time()) + 300)
                return jwt.encode(claims, signer._key, algorithm="RS256", headers={"kid": signer.kid})

        return _Exchanger()
