"""The reference data cites only framework IDs that exist in the pinned releases."""

import pytest

from tra_core.reference import Reference


@pytest.fixture(scope="module")
def ref() -> Reference:
    return Reference()


def test_every_library_technique_exists(ref):
    bad = [(t.id, a) for t in ref.threats.threats for a in t.attack if a not in ref.attack]
    bad += [(t.id, a) for t in ref.threats.threats for a in t.atlas if a not in ref.atlas]
    assert bad == []


def test_ai_threats_carry_atlas_and_the_rest_carry_attack(ref):
    for t in ref.threats.threats:
        if "ai" in t.tags:
            assert t.atlas or t.id == "TL-060", t.id  # over-reliance has no adversary technique
        elif "non-adversarial" not in t.tags:
            assert t.attack, t.id


def test_every_control_maps_to_ism_controls_in_the_baseline(ref):
    for c in ref.controls.controls:
        assert c.ism, f"{c.id} has no ISM mapping"
        missing = [i for i in c.ism if i not in ref.ism]
        assert missing == [], f"{c.id}: {missing} not in ISM {ref.ism.version}"


def test_the_catalogue_includes_the_tra_requirement(ref):
    assert any("ISM-1203" in c.ism for c in ref.controls.controls)


def test_versions_are_recorded(ref):
    assert ref.threats.meta["attack_version"] == ref.attack.version
    assert ref.threats.meta["atlas_version"] == ref.atlas.version
    assert ref.ism.version in ref.controls.meta["frameworks"]["ism"]


def test_every_library_threat_has_a_valid_default_category(ref):
    for t in ref.threats.threats:
        assert t.risk_category and ref.taxonomy.exists(t.risk_category), t.id


def test_taxonomy_covers_the_categories_the_sar_must_always_consider(ref):
    always = {c.id for c in ref.taxonomy.categories if c.always_consider}
    assert always == {"SDL", "SUP", "FOC", "CRY"}
    ids = [s.id for c in ref.taxonomy.categories for s in c.subcategories]
    assert len(ids) == len(set(ids))
    assert all(s.startswith(c.id + ".") for c in ref.taxonomy.categories for s in [x.id for x in c.subcategories])


def test_new_categories_have_library_threats_and_controls(ref):
    by_cat = {t.risk_category.split(".")[0] for t in ref.threats.threats}
    assert {"SDL", "SUP", "FOC", "CRY"} <= by_cat
    foci = ref.controls.get("CC-038")
    assert foci and "PSPF" in foci.references()
    assert "ISM-2073" in ref.controls.get("CC-039").ism
