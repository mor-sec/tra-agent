"""Deterministic checks on a draft TRA. These run before every gate, with or without a model."""

from __future__ import annotations

import re

from tra_core.reference import Reference
from tra_core.risk import impact_floor
from tra_core.schemas import TRA, ControlStatus, CritiqueIssue, Stride
from tra_core.stride import invalid_categories

ATLAS_ID = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def check_threats(tra: TRA, reference: Reference) -> list[str]:
    errors: list[str] = []
    model = tra.system_model
    if model is None:
        return ["no system model"]
    seen: set[str] = set()
    for t in tra.threats:
        if t.id in seen:
            errors.append(f"{t.id}: duplicate threat id")
        seen.add(t.id)
        item = model.element(t.element_id)
        if item is None:
            errors.append(f"{t.id}: element {t.element_id} is not in the system model")
            continue
        bad = invalid_categories(item, t.stride)
        if bad:
            errors.append(f"{t.id}: STRIDE {','.join(b.value for b in bad)} does not apply to {t.element_id}")
        if t.library_ref and reference.threats.get(t.library_ref) is None:
            errors.append(f"{t.id}: library_ref {t.library_ref} does not exist")
        for a in t.attack:
            if not ATTACK_ID.match(a):
                errors.append(f"{t.id}: {a} is not an ATT&CK technique ID")
            elif a not in reference.attack:
                errors.append(f"{t.id}: {a} is not in ATT&CK {reference.attack.version}")
        for a in t.atlas:
            if not ATLAS_ID.match(a):
                errors.append(f"{t.id}: {a} is not an ATLAS technique ID")
            elif a not in reference.atlas:
                errors.append(f"{t.id}: {a} is not in ATLAS {reference.atlas.version}")
    return errors


def check_controls(tra: TRA, reference: Reference) -> list[str]:
    errors = []
    threat_ids = {t.id for t in tra.threats}
    for c in tra.controls:
        if not reference.controls.exists(c.control_id):
            errors.append(f"{c.control_id}: not in the control catalogue")
        for tid in c.threat_ids:
            if tid not in threat_ids:
                errors.append(f"{c.control_id}: threat {tid} does not exist")
    return errors


def check_risks(tra: TRA, reference: Reference) -> list[str]:
    errors = []
    model = tra.system_model
    threats = {t.id: t for t in tra.threats}
    known = threats.keys() | {c.control_id for c in tra.controls}
    if model is not None:
        known |= {e.id for e in model.elements} | {f.id for f in model.flows} | {a.id for a in model.assets}
    for r in tra.risks:
        for tid in r.threat_ids:
            if tid not in threats:
                errors.append(f"{r.id}: threat {tid} does not exist")
        for cite in r.citations:
            if cite not in known:
                errors.append(f"{r.id}: citation {cite} does not exist")
        if not reference.taxonomy.exists(r.category):
            errors.append(f"{r.id}: category {r.category} is not in the risk taxonomy")
        for cid in r.proposed_controls:
            if not reference.controls.exists(cid):
                errors.append(f"{r.id}: proposed control {cid} is not in the catalogue")
        if r.residual_likelihood > r.inherent_likelihood or r.residual_impact > r.inherent_impact:
            errors.append(f"{r.id}: residual scores exceed inherent scores")
        if model is not None:
            disclosure = [threats[t] for t in r.threat_ids if t in threats and Stride.I in threats[t].stride]
            ranks = []
            for t in disclosure:
                item = model.element(t.element_id)
                if item is not None:
                    ranks.append(item.classification.rank)
            if ranks and r.inherent_impact < impact_floor(max(ranks)):
                errors.append(
                    f"{r.id}: inherent impact {r.inherent_impact} is below the floor {impact_floor(max(ranks))} "
                    "for the data's classification"
                )
    return errors


def coverage_issues(tra: TRA, reference: Reference | None = None) -> list[CritiqueIssue]:
    issues: list[CritiqueIssue] = []
    model = tra.system_model
    if model is None:
        return issues
    covered = {t.element_id for t in tra.threats}
    for e in model.elements:
        if e.id not in covered:
            issues.append(CritiqueIssue(severity="major", where=e.id, issue=f"no threats recorded for {e.name}", source="check"))
        if e.is_ai and not any(t.atlas for t in tra.threats if t.element_id == e.id):
            issues.append(CritiqueIssue(severity="major", where=e.id, issue="AI element has no ATLAS-tagged threat", source="check"))
    for f in model.flows:
        if f.crosses_boundary and f.id not in covered:
            issues.append(CritiqueIssue(severity="major", where=f.id, issue="boundary-crossing flow has no threats", source="check"))
    threatened = {tid for r in tra.risks for tid in r.threat_ids}
    for t in tra.threats:
        if t.id not in threatened:
            issues.append(CritiqueIssue(severity="minor", where=t.id, issue="threat is not linked to any risk", source="check"))
    for c in tra.controls:
        if c.status is ControlStatus.IN_PLACE and "not described" in c.evidence.lower():
            issues.append(CritiqueIssue(severity="major", where=c.control_id, issue="marked in place without evidence", source="check"))
    if reference is not None and tra.risks:
        recorded = {r.category.split(".")[0] for r in tra.risks}
        for cat in reference.taxonomy.categories:
            if cat.always_consider and cat.id not in recorded:
                issues.append(CritiqueIssue(
                    severity="minor", where=cat.id, source="check",
                    issue=f"no risk recorded for {cat.name}; confirm it was considered and does not apply",
                ))
    return issues


def automated_checks(tra: TRA, reference: Reference) -> list[CritiqueIssue]:
    problems = check_threats(tra, reference) + check_controls(tra, reference) + check_risks(tra, reference)
    blockers = [CritiqueIssue(severity="blocker", where=p.split(":")[0], issue=p, source="check") for p in problems]
    return blockers + coverage_issues(tra, reference)
