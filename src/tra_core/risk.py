"""SAR risk method (docs/03-risk-methodology.md) with AUD impact thresholds.

Everything here is deterministic. Models propose likelihood and impact scores
with a rationale; this module turns scores into ratings, tiers and authorities.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Rating(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


_L, _M, _H, _C = Rating.LOW, Rating.MEDIUM, Rating.HIGH, Rating.CRITICAL

# MATRIX[likelihood][impact], both 1..5. Row 0 and column 0 are unused.
MATRIX: list[list[Rating | None]] = [
    [None] * 6,
    [None, _L, _L, _L, _M, _M],
    [None, _L, _L, _M, _M, _H],
    [None, _L, _M, _M, _H, _H],
    [None, _L, _M, _H, _H, _C],
    [None, _M, _H, _H, _C, _C],
]


def rate(likelihood: int, impact: int) -> Rating:
    if not (1 <= likelihood <= 5 and 1 <= impact <= 5):
        raise ValueError(f"likelihood and impact must be 1..5, got {likelihood}, {impact}")
    rating = MATRIX[likelihood][impact]
    assert rating is not None
    return rating


def adjust_likelihood(
    likelihood: int,
    *,
    identity_or_pipeline_plane: bool = False,
    no_designed_detection: bool = False,
    independent_preventive_guardrail: bool = False,
) -> int:
    """Apply the SAR likelihood modifiers, clamped to 1..5."""
    if identity_or_pipeline_plane or no_designed_detection:
        likelihood += 1
    if independent_preventive_guardrail:
        likelihood -= 1
    return max(1, min(5, likelihood))


# Impact scale localised to AUD. Thresholds are defaults: replace them with the
# enterprise matrix when it is plugged in.
IMPACT_SCALE_AUD = {
    5: ("Severe", "> $10m", "Mass exposure of OFFICIAL: Sensitive or regulated data, or loss of key material"),
    4: ("Major", "$2m to $10m", "Exposure of OFFICIAL: Sensitive data at scale; mandatory breach notification"),
    3: ("Moderate", "$200k to $2m", "Limited OFFICIAL: Sensitive exposure; contractual breach"),
    2: ("Minor", "$20k to $200k", "OFFICIAL data exposure; internal impact only"),
    1: ("Negligible", "< $20k", "Public data only"),
}

LIKELIHOOD_SCALE = {
    5: ("Almost certain", "Internet or all-user reachable and trivially exploitable"),
    4: ("Likely", "Reachable by a broad population with known techniques; no compensating control"),
    3: ("Possible", "Needs a foothold plus moderate skill"),
    2: ("Unlikely", "Needs privileged insider access or several independent control failures"),
    1: ("Rare", "Needs provider compromise or nation-state capability"),
}


@dataclass(frozen=True)
class Authority:
    default_treatment: str
    remediation_window: str
    who_may_accept: str
    max_acceptance_months: int


AUTHORITY = {
    Rating.CRITICAL: Authority("Mitigate before go-live", "Blocker", "CISO plus executive risk owner (risk committee)", 3),
    Rating.HIGH: Authority("Mitigate before go-live, or accept with a dated plan", "30 days", "CISO or delegate plus risk owner", 6),
    Rating.MEDIUM: Authority("Mitigate on the roadmap", "90 days", "Risk owner with security architect concurrence", 12),
    Rating.LOW: Authority("Mitigate opportunistically", "Backlog", "Risk owner", 24),
}


def impact_floor(classification_rank: int) -> int:
    """Minimum confidentiality impact implied by the data's classification.

    OFFICIAL: Sensitive (rank 2) exposure is at least Moderate (3).
    """
    return {0: 1, 1: 2, 2: 3}.get(classification_rank, 4)


def tier(
    *,
    classification_rank: int,
    internet_facing: bool,
    handles_cardholder_data: bool,
    shared_platform: bool,
) -> int:
    """SAR tiering: take the highest tier any factor implies (1 is highest).

    `internet_facing` means anonymous internet exposure, which the SAR treats as Tier 1.
    """
    if classification_rank >= 3 or handles_cardholder_data or shared_platform or internet_facing:
        return 1
    if classification_rank >= 2:
        return 2
    return 3
