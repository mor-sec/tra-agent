"""TRA working state (D2). Local JSON files here; a managed database in deployment."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from tra_core.schemas import TRA, Artefact, utcnow


class TraStore(Protocol):
    def save(self, tra: TRA) -> None: ...
    def load(self, tra_id: str) -> TRA: ...
    def save_artefact(self, tra_id: str, artefact: Artefact) -> None: ...
    def load_artefacts(self, tra: TRA) -> list[Artefact]: ...
    def next_id(self) -> str: ...


class FileTraStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _dir(self, tra_id: str) -> Path:
        d = self.root / tra_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save(self, tra: TRA) -> None:
        tra.updated_at = utcnow()
        (self._dir(tra.id) / "tra.json").write_text(tra.model_dump_json(indent=1), encoding="utf-8")

    def load(self, tra_id: str) -> TRA:
        path = self.root / tra_id / "tra.json"
        if not path.exists():
            raise KeyError(tra_id)
        return TRA.model_validate_json(path.read_text(encoding="utf-8"))

    def save_artefact(self, tra_id: str, artefact: Artefact) -> None:
        d = self._dir(tra_id) / "artefacts"
        d.mkdir(exist_ok=True)
        (d / f"{artefact.sha256}.json").write_text(artefact.model_dump_json(), encoding="utf-8")

    def load_artefacts(self, tra: TRA) -> list[Artefact]:
        d = self.root / tra.id / "artefacts"
        return [Artefact.model_validate_json((d / f"{a.sha256}.json").read_text(encoding="utf-8")) for a in tra.artefacts]

    def next_id(self) -> str:
        year = utcnow().year
        existing = [p.name for p in self.root.glob(f"TRA-{year}-*") if p.is_dir()]
        n = max((int(x.rsplit("-", 1)[1]) for x in existing), default=0) + 1
        return f"TRA-{year}-{n:03d}"
