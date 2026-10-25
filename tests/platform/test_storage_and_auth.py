import threading

import pytest

from tra_core.audit import AuditLog, verify
from tra_core.identity import Principal, Role
from tra_core.schemas import Classification
from tra_platform.auth import AuthError, ClaimsMapper, DelegationValidator, TokenValidator
from tra_platform.config import Settings, object_store
from tra_platform.storage import AlreadyExists, LocalObjectStore, ObjectAuditSink, ObjectTraStore


def test_two_writers_keep_one_chain(tmp_path):
    store = LocalObjectStore(tmp_path)
    a, b = AuditLog(ObjectAuditSink(store)), AuditLog(ObjectAuditSink(store))
    actor = Principal.workload("agent:orchestrator")

    def write(log, n):
        for i in range(n):
            log.record(tra_id="T", tra_version=1, stage=None, event_type="stage_changed", actor=actor, detail={"i": i})

    errors = []

    def run(log):
        try:
            write(log, 20)
        except Exception as exc:  # noqa: BLE001 - surface thread failures in the assertion
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(log,)) for log in (a, b)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    events = ObjectAuditSink(store).read_all()
    assert len(events) == 40 and verify(events) == []


def test_audit_objects_are_write_once(tmp_path):
    store = LocalObjectStore(tmp_path)
    store.put("audit/000000000001.json", b"{}", create_only=True)
    with pytest.raises(AlreadyExists):
        store.put("audit/000000000001.json", b"{}", create_only=True)


def test_tra_ids_are_claimed_once(tmp_path):
    s1, s2 = ObjectTraStore(LocalObjectStore(tmp_path)), ObjectTraStore(LocalObjectStore(tmp_path))
    ids = {s1.next_id(), s2.next_id(), s1.next_id()}
    assert len(ids) == 3


def test_claims_mapper_entra_shape():
    mapper = ClaimsMapper()
    p = mapper.human({"sub": "s", "oid": "o-1", "roles": ["TRA.RiskOwner", "TRA.Clearance.OfficialSensitive"],
                      "acrs": ["c1"], "iat": 1_800_000_000})
    assert p.subject == "o-1" and p.has(Role.RISK_OWNER) and p.clearance is Classification.OFFICIAL_SENSITIVE
    assert p.strong_auth and p.auth_time is not None
    plain = mapper.human({"sub": "s", "roles": "TRA.Practitioner"})
    assert plain.clearance is Classification.OFFICIAL and not plain.strong_auth and plain.auth_time is None


def test_entra_obo_token_actor_is_azp(signer):
    validator = DelegationValidator(TokenValidator(signer.issuer, "api://tra-intake", signer.keys),
                                    frozenset({"orch-app-id"}), "intake")
    obo = signer.user_token("alice", ["TRA.Practitioner"], "api://tra-intake", azp="orch-app-id")
    assert validator.user(obo).subject == "alice"
    with pytest.raises(AuthError):
        validator.user(signer.user_token("alice", [], "api://tra-intake", azp="someone"))


def test_settings_from_env_and_storage_uris(tmp_path):
    s = Settings.from_env({
        "TRA_ROLE": "intake", "TRA_IDP_ISSUER": "https://login.microsoftonline.com/t/v2.0",
        "TRA_IDP_JWKS_URL": "https://login.microsoftonline.com/t/discovery/v2.0/keys",
        "TRA_AUDIENCE": "api://tra-intake", "TRA_ALLOWED_CALLERS": "orch-app-id, other",
        "TRA_SPECIALISTS": '{"intake": {"endpoint": "arn:aws:bedrock-agentcore:ap-southeast-2:1:runtime/x", "audience": "api://tra-intake"}}',
    })
    assert s.allowed_callers == {"orch-app-id", "other"} and s.specialists["intake"].audience == "api://tra-intake"
    assert isinstance(object_store(f"file://{tmp_path}"), LocalObjectStore)
    with pytest.raises(ValueError):
        object_store("ftp://nope")
    with pytest.raises(ValueError):
        Settings.from_env({**{k: "x" for k in ("TRA_ROLE", "TRA_IDP_ISSUER", "TRA_IDP_JWKS_URL", "TRA_AUDIENCE")}}).delegation()
