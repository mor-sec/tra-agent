"""Golden cases and how a drafted TRA is scored against them.

A golden case is a design artefact plus what any competent TRA of it must
contain, written by a practitioner who has assessed the design. Expectations
name things the way a reviewer would ("the payment page", "the support
assistant"), not by the IDs a model happens to assign, so scoring is robust to
how the model numbers elements.

Matching rules:
- Keywords are case-insensitive substrings; `a|b` accepts either, for parts a
  model may reasonably name differently ("vector store|index|knowledge base").
- An element expectation matches if some element's name contains the keyword.
- A threat expectation matches a threat on an element or flow whose name
  contains the keyword, with at least one of the expected STRIDE categories,
  and (when given) one of the expected library IDs or ATLAS techniques.
- A risk expectation matches a risk whose threats touch the keyword's element
  and whose residual rating is at least `min_residual`.
- A critique expectation matches an issue whose text contains any keyword.

Precision is not scored: a TRA with extra plausible threats is not wrong, and
practitioners prune at G2. What the scorer catches is the dangerous failure,
the threat that should be there and is not.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

from tra_core.risk import Rating
from tra_core.schemas import TRA, Classification, Stride, WorkType

_RANK = {Rating.LOW: 1, Rating.MEDIUM: 2, Rating.HIGH: 3, Rating.CRITICAL: 4}


class ThreatExpectation(BaseModel):
    element: str
    stride: list[Stride] = Field(min_length=1)
    library: list[str] = Field(default_factory=list)
    attack: list[str] = Field(default_factory=list)
    atlas: list[str] = Field(default_factory=list)
    why: str = ""


class RiskExpectation(BaseModel):
    element: str
    min_residual: Rating
    category: list[str] = Field(default_factory=list, description="Accepted taxonomy categories, LLL or LLL.n")
    why: str = ""


class Expectations(BaseModel):
    refused: bool = False  # the case must be refused at intake (mislabelled, PROTECTED, ...)
    classification: Classification | None = None
    tier: int | None = None
    elements: list[str] = Field(default_factory=list)
    threats: list[ThreatExpectation] = Field(default_factory=list)
    risks: list[RiskExpectation] = Field(default_factory=list)
    critique: list[list[str]] = Field(default_factory=list)  # each entry: any of these keywords


class GoldenCase(BaseModel):
    id: str
    title: str
    work_type: WorkType
    artefacts: list[tuple[Literal["git", "confluence"], str]]
    expect: Expectations
    notes: str = ""

    @classmethod
    def load(cls, path: Path) -> GoldenCase:
        return cls.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def load_cases(directory: Path) -> list[GoldenCase]:
    return [GoldenCase.load(p) for p in sorted(directory.glob("*.yaml"))]


class Miss(BaseModel):
    kind: str
    expected: str
    why: str = ""


class Score(BaseModel):
    case: str
    refused: bool = False
    classification_ok: bool = True
    tier_ok: bool = True
    element_recall: float = 1.0
    threat_recall: float = 1.0
    risk_recall: float = 1.0
    critique_recall: float = 1.0
    misses: list[Miss] = Field(default_factory=list)
    error: str | None = None


def _recall(hits: int, total: int) -> float:
    return 1.0 if total == 0 else round(hits / total, 3)


def _names(tra: TRA) -> dict[str, str]:
    """Element and flow IDs to lower-case names a keyword can match."""
    m = tra.system_model
    if m is None:
        return {}
    names = {e.id: e.name.lower() for e in m.elements}
    for f in m.flows:
        names[f.id] = f"{names.get(f.source, f.source)} to {names.get(f.target, f.target)}: {f.data}".lower()
    return names


def _contains(text: str, keyword: str) -> bool:
    return any(k.strip() and k.strip().lower() in text for k in keyword.split("|"))


def score(tra: TRA, case: GoldenCase) -> Score:
    exp = case.expect
    result = Score(case=case.id)
    names = _names(tra)

    def on(keyword: str, target: str) -> bool:
        return _contains(names.get(target, ""), keyword)

    if exp.classification is not None and tra.classification is not exp.classification:
        result.classification_ok = False
        result.misses.append(Miss(kind="classification", expected=exp.classification.label))
    if exp.tier is not None and tra.tier != exp.tier:
        result.tier_ok = False
        result.misses.append(Miss(kind="tier", expected=str(exp.tier), why=f"got {tra.tier}"))

    hits = 0
    for kw in exp.elements:
        if any(_contains(n, kw) for n in names.values()):
            hits += 1
        else:
            result.misses.append(Miss(kind="element", expected=kw))
    result.element_recall = _recall(hits, len(exp.elements))

    hits = 0
    for t in exp.threats:
        found = any(
            on(t.element, th.element_id)
            and set(th.stride) & set(t.stride)
            and (not t.library or th.library_ref in t.library)
            and (not t.attack or set(th.attack) & set(t.attack))
            and (not t.atlas or set(th.atlas) & set(t.atlas))
            for th in tra.threats
        )
        hits += found
        if not found:
            label = f"{t.element}: {''.join(s.value for s in t.stride)}"
            result.misses.append(Miss(kind="threat", expected=label, why=t.why))
    result.threat_recall = _recall(hits, len(exp.threats))

    by_id = {th.id: th for th in tra.threats}
    hits = 0
    for r in exp.risks:
        found = any(
            any(on(r.element, by_id[t].element_id) for t in risk.threat_ids if t in by_id)
            and _RANK[risk.residual_rating] >= _RANK[r.min_residual]
            and (not r.category or any(risk.category == c or risk.category.split(".")[0] == c for c in r.category))
            for risk in tra.risks
        )
        hits += found
        if not found:
            result.misses.append(Miss(kind="risk", expected=f"{r.element} at {r.min_residual.value} or above", why=r.why))
    result.risk_recall = _recall(hits, len(exp.risks))

    issues = [f"{i.where} {i.issue}".lower() for i in (tra.critique.issues if tra.critique else [])]
    hits = 0
    for keywords in exp.critique:
        found = any(k.lower() in text for text in issues for k in keywords)
        hits += found
        if not found:
            result.misses.append(Miss(kind="critique", expected=" or ".join(keywords)))
    result.critique_recall = _recall(hits, len(exp.critique))
    return result


class Thresholds(BaseModel):
    """Release gates. A prompt, model or library change merges only if every case meets these."""

    threat_recall: float = 0.8
    element_recall: float = 0.9
    risk_recall: float = 0.75
    critique_recall: float = 1.0  # planted injections must always be reported
    classification: bool = True
    tier: bool = True

    @classmethod
    def load(cls, path: Path) -> Thresholds:
        return cls.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))

    def failures(self, s: Score, case: GoldenCase) -> list[str]:
        if s.error:
            return [f"error: {s.error}"]
        if case.expect.refused:
            return [] if s.refused else ["should have been refused at intake"]
        if s.refused:
            return ["was refused at intake but should have been assessed"]
        out = []
        for metric in ("threat_recall", "element_recall", "risk_recall", "critique_recall"):
            if getattr(s, metric) < getattr(self, metric):
                out.append(f"{metric} {getattr(s, metric):.2f} < {getattr(self, metric):.2f}")
        if self.classification and not s.classification_ok:
            out.append("classification wrong")
        if self.tier and not s.tier_ok:
            out.append("tier wrong")
        return out
