"""Classification handling: what the system accepts, and how labels propagate."""

from __future__ import annotations

import re
from collections.abc import Iterable

from tra_core.schemas import Classification

# The design is accredited for OFFICIAL: Sensitive. PROTECTED is a future state.
MAX_ACCEPTED = Classification.OFFICIAL_SENSITIVE

# A TRA lists a system's weaknesses, so it is at least OFFICIAL: Sensitive.
TRA_FLOOR = Classification.OFFICIAL_SENSITIVE


class ClassificationError(Exception):
    pass


def highest(labels: Iterable[Classification]) -> Classification:
    labels = list(labels)
    if not labels:
        raise ClassificationError("no labels to combine")
    return max(labels, key=lambda c: c.rank)


def check_accepted(label: Classification) -> None:
    if label.rank > MAX_ACCEPTED.rank:
        raise ClassificationError(
            f"{label.label} material is not accepted: this deployment is limited to {MAX_ACCEPTED.label}"
        )


def derived_label(inputs: Iterable[Classification]) -> Classification:
    """Label for anything derived from the inputs: their highest, never below the TRA floor."""
    return highest([*inputs, TRA_FLOOR])


def can_read(clearance: Classification, label: Classification) -> bool:
    return clearance.rank >= label.rank


# A protective marking written as an upper-case banner line ("PROTECTED",
# "== SECRET//AUSTEO =="), or as the value of a "Classification:" field in any
# case. Prose such as "data is protected by TLS" is not a marking.
_BANNER = re.compile(r"^[\s#*_>|=~-]*(TOP SECRET|SECRET|PROTECTED)\b[^a-z\n]*$", re.MULTILINE)
_FIELD = re.compile(r"^\W*classification\s*:\s*(top secret|secret|protected)\b", re.MULTILINE | re.IGNORECASE)
_RANK_OF_MARKING = {"PROTECTED": 3, "SECRET": 4, "TOP SECRET": 5}


def marking_conflict(text: str, label: Classification) -> str | None:
    """The highest banner marking in `text` above `label`, if any.

    Catches a document labelled OFFICIAL: Sensitive whose body is marked
    PROTECTED or higher: mislabelled material must be refused, not processed.
    """
    found = [m.group(1).upper() for rx in (_BANNER, _FIELD) for m in rx.finditer(text)]
    above = [f for f in found if _RANK_OF_MARKING[f] > label.rank]
    return max(above, key=_RANK_OF_MARKING.__getitem__) if above else None
