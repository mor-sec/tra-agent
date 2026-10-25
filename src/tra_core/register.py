"""Risk register output. CSV in the SAR format now; an Eramba writer can replace it later."""

from __future__ import annotations

import csv
import io
from functools import cache
from pathlib import Path
from typing import Protocol

from tra_core.reference import RiskTaxonomy
from tra_core.risk import AUTHORITY
from tra_core.schemas import TRA

# Columns from templates/risk-register.csv in the SAR process.
SAR_COLUMNS = [
    "risk_id", "sar_ref", "finding", "domain", "risk_statement", "threat_ids",
    "inherent_likelihood", "inherent_impact", "inherent_rating", "mitigations",
    "residual_likelihood", "residual_impact", "residual_rating", "treatment", "owner",
    "due_date_or_milestone", "acceptance_ref", "acceptance_expiry", "status", "notes",
]


class RegisterWriter(Protocol):
    def write(self, tra: TRA) -> str:
        """Write the TRA's risks; return where they went."""
        ...


@cache
def _default_taxonomy() -> RiskTaxonomy:
    return RiskTaxonomy()


def register_rows(tra: TRA, taxonomy: RiskTaxonomy | None = None) -> list[dict[str, str]]:
    taxonomy = taxonomy or _default_taxonomy()
    rows = []
    for r in tra.risks:
        authority = AUTHORITY[r.residual_rating]
        rows.append({
            "risk_id": f"{tra.id}/{r.id}",
            "sar_ref": tra.id,
            "finding": r.statement.split(",")[0][:120],
            "domain": taxonomy.label(r.category),
            "risk_statement": r.statement,
            "threat_ids": ";".join(r.threat_ids),
            "inherent_likelihood": str(r.inherent_likelihood),
            "inherent_impact": str(r.inherent_impact),
            "inherent_rating": r.inherent_rating.value,
            "mitigations": ";".join(r.proposed_controls),
            "residual_likelihood": str(r.residual_likelihood),
            "residual_impact": str(r.residual_impact),
            "residual_rating": r.residual_rating.value,
            "treatment": r.treatment.value.capitalize(),
            "owner": r.owner or (tra.intake.risk_owner if tra.intake and tra.intake.risk_owner else ""),
            "due_date_or_milestone": authority.remediation_window,
            "acceptance_ref": "",
            "acceptance_expiry": "",
            "status": "Open",
            "notes": f"Acceptance authority: {authority.who_may_accept}",
        })
    return rows


def to_csv(tra: TRA) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=SAR_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(register_rows(tra))
    return buf.getvalue()


class CsvRegisterWriter:
    def __init__(self, out_dir: Path) -> None:
        self.out_dir = out_dir

    def write(self, tra: TRA) -> str:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        path = self.out_dir / f"{tra.id}-risk-register.csv"
        path.write_text(to_csv(tra), encoding="utf-8")
        return str(path)
