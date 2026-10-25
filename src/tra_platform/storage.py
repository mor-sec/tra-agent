"""Durable storage for deployed runs: TRA state, the audit chain and the risk register.

One small `ObjectStore` interface with three backends (local directory, S3,
Azure Blob), and the core's store, audit sink and register writer built on it.
Keys are the same on every backend, so moving platforms is a copy, not a
migration.

Layout:
    tras/<TRA id>/tra.json
    tras/<TRA id>/artefacts/<sha256>.json
    audit/<seq, zero padded>.json      one object per event, write-once
    register/<TRA id>-risk-register.csv

The audit bucket or container must be immutable: S3 Object Lock in compliance
mode, or an Azure time-based retention policy, locked. The IaC sets this up.
Writes use create-only conditions (S3 `If-None-Match`, Blob `if_none_match`),
so two writers can never both claim the same sequence number.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Protocol

from tra_core.audit import AuditEvent, SequenceTaken
from tra_core.register import to_csv
from tra_core.schemas import TRA, Artefact, utcnow


class AlreadyExists(SequenceTaken):
    """A create-only write found the key already there."""


class ObjectStore(Protocol):
    def put(self, key: str, data: bytes, *, create_only: bool = False, content_type: str = "application/json") -> None: ...
    def get(self, key: str) -> bytes: ...
    def list(self, prefix: str) -> list[str]: ...


class LocalObjectStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def put(self, key: str, data: bytes, *, create_only: bool = False, content_type: str = "application/json") -> None:
        """Writes are atomic, like S3 and Blob: readers never see a partly written object."""
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            if create_only:
                os.link(tmp, path)  # fails if the key exists, so the first writer wins
            else:
                os.replace(tmp, path)
        except FileExistsError as exc:
            raise AlreadyExists(key) from exc
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def get(self, key: str) -> bytes:
        path = self.root / key
        if not path.exists():
            raise KeyError(key)
        return path.read_bytes()

    def list(self, prefix: str) -> list[str]:
        base = self.root / prefix
        if not base.exists():
            return []
        return sorted(str(p.relative_to(self.root)) for p in base.rglob("*") if p.is_file() and not p.name.startswith(".tmp-"))


class S3ObjectStore:
    """S3 with SSE-KMS. `bucket` must have versioning on; the audit bucket also Object Lock."""

    def __init__(self, bucket: str, kms_key_id: str | None = None, prefix: str = "", client: Any = None) -> None:
        import boto3

        self.bucket = bucket
        self.kms_key_id = kms_key_id
        self.prefix = prefix
        self.s3 = client or boto3.client("s3")

    def put(self, key: str, data: bytes, *, create_only: bool = False, content_type: str = "application/json") -> None:
        from botocore.exceptions import ClientError

        args: dict[str, Any] = {"Bucket": self.bucket, "Key": self.prefix + key, "Body": data, "ContentType": content_type}
        if self.kms_key_id:
            args.update(ServerSideEncryption="aws:kms", SSEKMSKeyId=self.kms_key_id)
        if create_only:
            args["IfNoneMatch"] = "*"
        try:
            self.s3.put_object(**args)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("PreconditionFailed", "ConditionalRequestConflict"):
                raise AlreadyExists(key) from exc
            raise

    def get(self, key: str) -> bytes:
        from botocore.exceptions import ClientError

        try:
            return self.s3.get_object(Bucket=self.bucket, Key=self.prefix + key)["Body"].read()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("NoSuchKey", "404"):
                raise KeyError(key) from exc
            raise

    def list(self, prefix: str) -> list[str]:
        keys: list[str] = []
        for page in self.s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=self.prefix + prefix):
            keys += [o["Key"][len(self.prefix):] for o in page.get("Contents", [])]
        return sorted(keys)


class BlobObjectStore:
    """Azure Blob Storage, reached with the workload's Entra identity (no account keys)."""

    def __init__(self, account_url: str, container: str, credential: Any = None, client: Any = None) -> None:
        if client is None:
            from azure.identity import DefaultAzureCredential
            from azure.storage.blob import ContainerClient

            client = ContainerClient(account_url, container, credential=credential or DefaultAzureCredential())
        self.container = client

    def put(self, key: str, data: bytes, *, create_only: bool = False, content_type: str = "application/json") -> None:
        from azure.core import MatchConditions
        from azure.core.exceptions import ResourceExistsError
        from azure.storage.blob import ContentSettings

        kwargs: dict[str, Any] = {"overwrite": not create_only, "content_settings": ContentSettings(content_type=content_type)}
        if create_only:
            kwargs.update(etag="*", match_condition=MatchConditions.IfMissing)
        try:
            self.container.upload_blob(key, data, **kwargs)
        except ResourceExistsError as exc:
            raise AlreadyExists(key) from exc

    def get(self, key: str) -> bytes:
        from azure.core.exceptions import ResourceNotFoundError

        try:
            return self.container.download_blob(key).readall()
        except ResourceNotFoundError as exc:
            raise KeyError(key) from exc

    def list(self, prefix: str) -> list[str]:
        return sorted(b.name for b in self.container.list_blobs(name_starts_with=prefix))


class ObjectTraStore:
    def __init__(self, objects: ObjectStore) -> None:
        self.objects = objects

    def save(self, tra: TRA) -> None:
        tra.updated_at = utcnow()
        self.objects.put(f"tras/{tra.id}/tra.json", tra.model_dump_json(indent=1).encode())

    def load(self, tra_id: str) -> TRA:
        return TRA.model_validate_json(self.objects.get(f"tras/{tra_id}/tra.json"))

    def save_artefact(self, tra_id: str, artefact: Artefact) -> None:
        self.objects.put(f"tras/{tra_id}/artefacts/{artefact.sha256}.json", artefact.model_dump_json().encode())

    def load_artefacts(self, tra: TRA) -> list[Artefact]:
        return [
            Artefact.model_validate_json(self.objects.get(f"tras/{tra.id}/artefacts/{a.sha256}.json"))
            for a in tra.artefacts
        ]

    def next_id(self) -> str:
        """Claims the next ID with a create-only marker, so concurrent creates never collide."""
        year = utcnow().year
        taken = {k.split("/")[1] for k in self.objects.list(f"tras/TRA-{year}-")}
        n = max((int(x.rsplit("-", 1)[1]) for x in taken), default=0)
        while True:
            n += 1
            tra_id = f"TRA-{year}-{n:03d}"
            try:
                self.objects.put(f"tras/{tra_id}/.claimed", b"", create_only=True, content_type="text/plain")
                return tra_id
            except AlreadyExists:
                continue


class ObjectAuditSink:
    """One write-once object per event. A sequence clash raises `AlreadyExists` rather than forking the chain."""

    def __init__(self, objects: ObjectStore) -> None:
        self.objects = objects

    def append(self, event: AuditEvent) -> None:
        self.objects.put(f"audit/{event.seq:012d}.json", event.model_dump_json().encode(), create_only=True)

    def read_all(self) -> list[AuditEvent]:
        return [AuditEvent.model_validate_json(self.objects.get(k)) for k in self.objects.list("audit/")]

    def tail(self) -> AuditEvent | None:
        keys = self.objects.list("audit/")
        return AuditEvent.model_validate_json(self.objects.get(keys[-1])) if keys else None


class ObjectRegisterWriter:
    """Writes the SAR register CSV for each TRA. An Eramba writer can replace this later."""

    def __init__(self, objects: ObjectStore) -> None:
        self.objects = objects

    def write(self, tra: TRA) -> str:
        key = f"register/{tra.id}-risk-register.csv"
        self.objects.put(key, to_csv(tra).encode(), content_type="text/csv")
        return key
