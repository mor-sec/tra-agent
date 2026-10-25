"""Forged, replayed and misdirected tokens at the platform edge.

OWASP LLM06 (excessive agency through a confused deputy);
ATLAS AML.T0012 (valid accounts).
"""

import base64
import hashlib
import hmac
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from tra_platform.auth import AuthError, DelegationValidator, LocalSigner, TokenValidator

ISSUER = "https://idp.local"
SPECIALIST_AUD = "api://tra-threat-analyst"
ORCHESTRATOR = "orchestrator-client-id"


@pytest.fixture
def signer() -> LocalSigner:
    return LocalSigner(ISSUER)


@pytest.fixture
def validator(signer) -> TokenValidator:
    return TokenValidator(issuer=ISSUER, audience=SPECIALIST_AUD, keys=signer.keys)


@pytest.fixture
def delegation(validator) -> DelegationValidator:
    return DelegationValidator(validator, frozenset({ORCHESTRATOR}), "threat_analyst")


def _b64(obj) -> str:
    raw = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _claims(**extra):
    now = int(time.time())
    return {"iss": ISSUER, "sub": "alice", "aud": SPECIALIST_AUD, "iat": now, "exp": now + 300,
            "roles": ["TRA.Practitioner"], "act": {"sub": ORCHESTRATOR}, **extra}


async def test_genuine_delegation_token_is_accepted(signer, delegation):
    token = await signer.exchanger(ORCHESTRATOR).exchange(
        signer.user_token("alice", ["TRA.Practitioner"], "api://tra-orchestrator"), SPECIALIST_AUD
    )
    assert delegation.user(token).subject == "alice"


def test_alg_none_is_rejected(validator):
    token = f"{_b64({'alg': 'none', 'typ': 'JWT', 'kid': 'local-1'})}.{_b64(_claims())}."
    with pytest.raises(AuthError):
        validator.validate(token)


def test_hs256_signed_with_the_public_key_is_rejected(signer, validator):
    public_pem = signer.keys.keys["local-1"].public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    head, body = _b64({"alg": "HS256", "typ": "JWT", "kid": "local-1"}), _b64(_claims())
    sig = _b64(hmac.new(public_pem, f"{head}.{body}".encode(), hashlib.sha256).digest())
    with pytest.raises(AuthError):
        validator.validate(f"{head}.{body}.{sig}")


def test_tampered_payload_is_rejected(signer, validator):
    head, _, sig = signer.user_token("alice", ["TRA.Viewer"], SPECIALIST_AUD).split(".")
    forged = _b64(_claims(roles=["TRA.Admin", "TRA.RiskOwner"]))
    with pytest.raises(AuthError, match="Signature"):
        validator.validate(f"{head}.{forged}.{sig}")


def test_token_from_another_key_is_rejected(validator):
    rogue = LocalSigner(ISSUER, kid="local-1")  # same kid, different key
    with pytest.raises(AuthError):
        validator.validate(rogue.user_token("alice", [], SPECIALIST_AUD))


def test_unknown_kid_is_rejected(validator):
    with pytest.raises(AuthError, match="unknown signing key"):
        validator.validate(LocalSigner(ISSUER, kid="attacker").user_token("alice", [], SPECIALIST_AUD))


@pytest.mark.parametrize("change,match", [
    ({"exp": int(time.time()) - 3600}, "expired"),
    ({"iss": "https://evil.example"}, "issuer"),
    ({"aud": "api://tra-risk-assessor"}, "(?i)audience"),
    ({"iat": None}, "iat"),
])
def test_claim_checks(signer, validator, change, match):
    claims = {k: v for k, v in {**_claims(), **change}.items() if v is not None}
    token = jwt.encode(claims, signer._key, algorithm="RS256", headers={"kid": signer.kid})
    with pytest.raises(AuthError, match=match):
        validator.validate(token)


def test_user_token_replayed_at_a_specialist_is_rejected(signer, delegation):
    # A user who obtains a token for the specialist's audience still has no actor claim.
    token = signer.user_token("alice", ["TRA.Practitioner"], SPECIALIST_AUD)
    with pytest.raises(AuthError, match="may not invoke"):
        delegation.user(token)


async def test_delegation_from_a_caller_not_on_the_list_is_rejected(signer, delegation):
    token = await signer.exchanger("risk-assessor-client-id").exchange(
        signer.user_token("alice", ["TRA.Practitioner"], "api://x"), SPECIALIST_AUD
    )
    with pytest.raises(AuthError, match="may not invoke"):
        delegation.user(token)


async def test_token_for_one_specialist_is_rejected_by_another(signer, validator):
    token = await signer.exchanger(ORCHESTRATOR).exchange(
        signer.user_token("alice", ["TRA.Practitioner"], "api://x"), "api://tra-risk-assessor"
    )
    with pytest.raises(AuthError, match="(?i)audience"):
        validator.validate(token)


def test_self_asserted_step_up_needs_the_signed_claim(signer, validator):
    from tra_platform.auth import ClaimsMapper

    plain = validator.validate(signer.user_token("olivia", ["TRA.RiskOwner"], SPECIALIST_AUD, step_up=True))
    assert not ClaimsMapper().human(plain).strong_auth
    stepped = validator.validate(signer.user_token("olivia", ["TRA.RiskOwner"], SPECIALIST_AUD, acrs=["c1"]))
    assert ClaimsMapper().human(stepped).strong_auth


def test_unmapped_roles_and_protected_clearance_grant_nothing(signer, validator):
    from tra_core.classification import Classification
    from tra_platform.auth import ClaimsMapper

    claims = validator.validate(signer.user_token(
        "mallory", ["TRA.SuperAdmin", "TRA.Clearance.Protected", "Global Administrator"], SPECIALIST_AUD
    ))
    p = ClaimsMapper().human(claims)
    assert not p.roles and p.clearance is Classification.OFFICIAL
