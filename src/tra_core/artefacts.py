"""Where design artefacts come from: Git checkouts and Confluence.

Every artefact must carry a PSPF label. Unlabelled or over-classified material
is refused here, before any model sees it, and so is material whose body
carries a higher protective marking than its label.

Labels:
- Git and local files: a front-matter line `classification: OFFICIAL_SENSITIVE`
  in the first 20 lines, or a sidecar file `<name>.label` holding the label.
- Confluence: a page label such as `official-sensitive` or `official`.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Protocol

from tra_core.classification import check_accepted, marking_conflict
from tra_core.schemas import Artefact, Classification

_LABEL_LINE = re.compile(r"^\s*classification\s*:\s*(.+?)\s*$", re.IGNORECASE)
_TEXT_SUFFIXES = {".md", ".txt", ".yaml", ".yml", ".json", ".mmd", ".puml", ".drawio", ".adoc", ".rst"}


class ArtefactError(Exception):
    pass


class ArtefactSource(Protocol):
    name: str

    def get(self, locator: str) -> Artefact: ...
    def list(self, prefix: str = "") -> list[str]: ...


def _check_label(locator: str, text: str, label: Classification) -> None:
    check_accepted(label)
    if marking := marking_conflict(text, label):
        raise ArtefactError(f"{locator} is labelled {label.label} but its text is marked {marking}; fix the label first")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class GitArtefactSource:
    """Read-only access to files under a Git checkout (or any local folder).

    Paths are resolved inside `root`; anything outside it is refused.
    """

    name = "git"

    def __init__(self, root: Path, max_bytes: int = 2_000_000) -> None:
        self.root = root.resolve()
        self.max_bytes = max_bytes

    def _resolve(self, locator: str) -> Path:
        path = (self.root / locator).resolve()
        if not path.is_relative_to(self.root):
            raise ArtefactError(f"{locator} is outside the artefact root")
        if not path.is_file():
            raise ArtefactError(f"{locator} not found")
        if path.suffix.lower() not in _TEXT_SUFFIXES:
            raise ArtefactError(f"{locator}: only text artefacts are supported ({', '.join(sorted(_TEXT_SUFFIXES))})")
        if path.stat().st_size > self.max_bytes:
            raise ArtefactError(f"{locator} is larger than {self.max_bytes} bytes")
        return path

    def _label(self, path: Path, text: str) -> Classification:
        sidecar = path.with_name(path.name + ".label")
        if sidecar.exists():
            return Classification.parse(sidecar.read_text(encoding="utf-8").strip())
        for line in text.splitlines()[:20]:
            m = _LABEL_LINE.match(line)
            if m:
                return Classification.parse(m.group(1))
        raise ArtefactError(f"{path.name} has no classification label")

    def _revision(self) -> str | None:
        try:
            out = subprocess.run(
                ["git", "-C", str(self.root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
            )
            return out.stdout.strip() or None
        except (OSError, subprocess.CalledProcessError):
            return None

    def get(self, locator: str) -> Artefact:
        path = self._resolve(locator)
        text = path.read_text(encoding="utf-8", errors="replace")
        label = self._label(path, text)
        _check_label(locator, text, label)
        return Artefact(
            source=self.name,
            locator=str(path.relative_to(self.root)),
            title=path.stem,
            classification=label,
            sha256=_sha(text),
            revision=self._revision(),
            text=text,
        )

    def list(self, prefix: str = "") -> list[str]:
        base = (self.root / prefix).resolve()
        if not base.is_relative_to(self.root) or not base.exists():
            return []
        return sorted(
            str(p.relative_to(self.root))
            for p in base.rglob("*")
            if p.is_file() and p.suffix.lower() in _TEXT_SUFFIXES and ".git" not in p.parts
        )


class ConfluenceArtefactSource:
    """Confluence Cloud REST v2, read-only. Authenticate with a scoped token held by the MCP server.

    Not yet exercised against a live site: test against your instance before relying on it.
    """

    name = "confluence"
    _LABELS = {
        "official": Classification.OFFICIAL,
        "official-sensitive": Classification.OFFICIAL_SENSITIVE,
        "protected": Classification.PROTECTED,
    }

    def __init__(self, base_url: str, email: str, api_token: str, timeout: float = 30.0) -> None:
        import httpx  # optional dependency

        self._client = httpx.Client(base_url=base_url.rstrip("/"), auth=(email, api_token), timeout=timeout)

    def _label(self, page_id: str) -> Classification:
        r = self._client.get(f"/wiki/api/v2/pages/{page_id}/labels")
        r.raise_for_status()
        names = {lbl["name"].lower() for lbl in r.json().get("results", [])}
        found = [c for n, c in self._LABELS.items() if n in names]
        if not found:
            raise ArtefactError(f"Confluence page {page_id} has no classification label")
        return max(found, key=lambda c: c.rank)

    @staticmethod
    def _to_text(storage_html: str) -> str:
        text = re.sub(r"<(br|/p|/h\d|/li|/tr)[^>]*>", "\n", storage_html)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"[ \t]+", " ", text)
        return re.sub(r"\n\s*\n+", "\n\n", text).strip()

    def get(self, locator: str) -> Artefact:
        page_id = locator.rsplit("/", 1)[-1]
        label = self._label(page_id)
        check_accepted(label)
        r = self._client.get(f"/wiki/api/v2/pages/{page_id}", params={"body-format": "storage"})
        r.raise_for_status()
        page = r.json()
        text = self._to_text(page["body"]["storage"]["value"])
        _check_label(page_id, text, label)
        return Artefact(
            source=self.name,
            locator=page_id,
            title=page.get("title", page_id),
            classification=label,
            sha256=_sha(text),
            revision=str(page.get("version", {}).get("number")),
            text=text,
        )

    def list(self, prefix: str = "") -> list[str]:
        r = self._client.get("/wiki/api/v2/pages", params={"space-id": prefix, "limit": 250})
        r.raise_for_status()
        return [p["id"] for p in r.json().get("results", [])]
