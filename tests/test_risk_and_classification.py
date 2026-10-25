import pytest

from tra_core.classification import ClassificationError, check_accepted, derived_label
from tra_core.risk import Rating, adjust_likelihood, impact_floor, rate, tier
from tra_core.schemas import Classification, Element, ElementType, Stride
from tra_core.stride import applicable


@pytest.mark.parametrize(
    "l,i,expected",
    [(5, 5, Rating.CRITICAL), (5, 1, Rating.MEDIUM), (1, 5, Rating.MEDIUM), (3, 3, Rating.MEDIUM),
     (4, 3, Rating.HIGH), (2, 5, Rating.HIGH), (1, 1, Rating.LOW), (4, 5, Rating.CRITICAL), (3, 4, Rating.HIGH)],
)
def test_matrix_matches_sar(l, i, expected):
    assert rate(l, i) is expected


def test_rate_rejects_out_of_range():
    with pytest.raises(ValueError):
        rate(0, 3)


def test_likelihood_modifiers_clamp():
    assert adjust_likelihood(5, identity_or_pipeline_plane=True) == 5
    assert adjust_likelihood(1, independent_preventive_guardrail=True) == 1
    assert adjust_likelihood(3, no_designed_detection=True, independent_preventive_guardrail=True) == 3


def test_tiering():
    assert tier(classification_rank=1, internet_facing=False, handles_cardholder_data=False, shared_platform=False) == 3
    assert tier(classification_rank=2, internet_facing=False, handles_cardholder_data=False, shared_platform=False) == 2
    assert tier(classification_rank=2, internet_facing=False, handles_cardholder_data=True, shared_platform=False) == 1
    assert tier(classification_rank=1, internet_facing=True, handles_cardholder_data=False, shared_platform=False) == 1


def test_impact_floor_for_official_sensitive():
    assert impact_floor(Classification.OFFICIAL_SENSITIVE.rank) == 3


def test_classification_parse_and_order():
    assert Classification.parse("OFFICIAL: Sensitive") is Classification.OFFICIAL_SENSITIVE
    assert Classification.parse("os") is Classification.OFFICIAL_SENSITIVE
    assert Classification.PROTECTED.rank > Classification.OFFICIAL_SENSITIVE.rank


def test_protected_is_refused_until_uplift():
    with pytest.raises(ClassificationError):
        check_accepted(Classification.PROTECTED)
    check_accepted(Classification.OFFICIAL_SENSITIVE)


def test_derived_label_has_tra_floor():
    assert derived_label([Classification.OFFICIAL]) is Classification.OFFICIAL_SENSITIVE


def test_stride_per_element():
    store = Element(id="E01", name="db", type=ElementType.DATA_STORE, description="", zone="z",
                    classification=Classification.OFFICIAL, is_ai=False, evidence="")
    assert Stride.S not in applicable(store)
    assert Stride.I in applicable(store)
