"""The golden-set harness: scoring, thresholds, the runner, and the shipped cases."""

import json
from pathlib import Path

import pytest

from tra_core.llm import ModelRouter, ReplayModelClient
from tra_core.risk import Rating
from tra_core.schemas import TRA, Critique, Stride
from tra_eval import runner
from tra_eval.golden import (
    GoldenCase,
    RiskExpectation,
    Score,
    ThreatExpectation,
    Thresholds,
    load_cases,
    score,
)

ROOT = Path(__file__).resolve().parents[2]
EVAL = ROOT / "eval"


def _router() -> ModelRouter:
    return ModelRouter({}, overrides={"*": ReplayModelClient.from_file(EVAL / "replays" / "payments-portal.json")})


@pytest.fixture
def payments() -> GoldenCase:
    return GoldenCase.load(EVAL / "golden" / "payments-portal.yaml")


@pytest.fixture
async def drafted(payments, tmp_path):
    """The payments TRA drafted from the recording, up to G2."""
    s = await runner.run_case(payments, _router(), EVAL / "artefacts", tmp_path)
    assert s.error is None
    orch_tras = list(tmp_path.glob("*/tra.json"))
    assert orch_tras, "the runner should leave the drafted TRA in its work directory"
    return TRA.model_validate_json(orch_tras[0].read_text())


def test_shipped_cases_load_and_have_artefacts():
    cases = load_cases(EVAL / "golden")
    assert {c.id for c in cases} >= {"payments-portal", "hr-leave", "rag-assistant", "tra-agent-self", "mislabelled"}
    for c in cases:
        for _, locator in c.artefacts:
            assert (EVAL / "artefacts" / locator).exists(), f"{c.id}: {locator} missing"
        if not c.expect.refused:
            assert c.expect.threats, f"{c.id} expects no threats; a golden case must say what a TRA needs"


async def test_replay_meets_every_threshold(payments, tmp_path):
    s = await runner.run_case(payments, _router(), EVAL / "artefacts", tmp_path)
    assert Thresholds.load(EVAL / "thresholds.yaml").failures(s, payments) == []
    assert (s.threat_recall, s.element_recall, s.risk_recall, s.critique_recall) == (1.0, 1.0, 1.0, 1.0)


async def test_missing_threat_fails_the_gate(drafted, payments):
    case = payments.model_copy(deep=True)
    case.expect.threats = [ThreatExpectation(element="payment gateway", stride=[Stride.R], why="no reconciliation")]
    s = score(drafted, case)
    assert s.threat_recall == 0.0
    assert any("threat_recall" in f for f in Thresholds().failures(s, case))
    assert s.misses[0].kind == "threat" and s.misses[0].why == "no reconciliation"


async def test_library_and_techniques_must_match_when_given(drafted, payments):
    case = payments.model_copy(deep=True)
    case.expect.threats = [
        ThreatExpectation(element="web front end", stride=[Stride.T], library=["TL-020"]),  # wrong library entry
        ThreatExpectation(element="support assistant", stride=[Stride.I], atlas=["AML.T0024"]),  # wrong technique
        ThreatExpectation(element="web front end", stride=[Stride.T], attack=["T1486"]),  # wrong technique
    ]
    assert score(drafted, case).threat_recall == 0.0


async def test_underrated_risk_fails(drafted, payments):
    case = payments.model_copy(deep=True)
    case.expect.risks = [RiskExpectation(element="invoice database", min_residual=Rating.CRITICAL)]
    s = score(drafted, case)
    assert s.risk_recall == 0.0 and s.misses[-1].kind == "risk"


async def test_critic_that_misses_the_planted_injection_fails(drafted, payments):
    quiet = drafted.model_copy(update={"critique": Critique(issues=[i for i in drafted.critique.issues if "hidden" not in i.issue])})
    s = score(quiet, payments)
    assert s.critique_recall == 0.0
    assert "critique_recall 0.00 < 1.00" in Thresholds().failures(s, payments)


async def test_wrong_tier_and_classification_fail(drafted, payments):
    case = payments.model_copy(deep=True)
    case.expect.tier = 3
    s = score(drafted, case)
    assert not s.tier_ok and "tier wrong" in Thresholds().failures(s, case)


async def test_keyword_alternatives(drafted, payments):
    case = payments.model_copy(deep=True)
    case.expect.elements = ["vector store|support assistant", "nothing like this|nor this"]
    assert score(drafted, case).element_recall == 0.5


async def test_mislabelled_case_is_refused_before_any_model_call(tmp_path):
    case = GoldenCase.load(EVAL / "golden" / "mislabelled.yaml")
    client = ReplayModelClient({})
    s = await runner.run_case(case, ModelRouter({}, overrides={"*": client}), EVAL / "artefacts", tmp_path)
    assert s.refused and s.error is None and client.prompts == []
    assert Thresholds().failures(s, case) == []


def test_refusal_expectations_both_ways(payments):
    refused_case = GoldenCase.load(EVAL / "golden" / "mislabelled.yaml")
    assert Thresholds().failures(Score(case="x"), refused_case) == ["should have been refused at intake"]
    assert Thresholds().failures(Score(case="x", refused=True), payments) == [
        "was refused at intake but should have been assessed"
    ]


def test_worst_run_gates():
    good = Score(case="c", threat_recall=1.0)
    flaky = Score(case="c", threat_recall=0.6)
    broken = Score(case="c", error="agent failed")
    assert runner.worst([good, flaky]) is flaky
    assert runner.worst([good, flaky, broken]) is broken


def test_cli_writes_summary_and_exit_status(tmp_path):
    out = tmp_path / "out"
    code = runner.main([
        "--cases", str(EVAL / "golden"), "--artefacts", str(EVAL / "artefacts"),
        "--replay-dir", str(EVAL / "replays"), "--thresholds", str(EVAL / "thresholds.yaml"),
        "--only", "payments-portal", "mislabelled", "--out", str(out),
    ])
    assert code == 0
    rows = json.loads((out / "scores.json").read_text())
    assert {r["case"] for r in rows} == {"payments-portal", "mislabelled"}
    assert "| payments-portal | pass |" in (out / "summary.md").read_text()


def test_cli_fails_when_a_case_misses(tmp_path):
    cases = tmp_path / "cases"
    cases.mkdir()
    case = GoldenCase.load(EVAL / "golden" / "payments-portal.yaml")
    case.expect.threats.append(ThreatExpectation(element="payment gateway", stride=[Stride.R]))
    case.expect.threats.append(ThreatExpectation(element="application logs", stride=[Stride.I], library=["TL-013"]))
    (cases / "payments-portal.yaml").write_text(json.dumps(case.model_dump(mode="json")))  # JSON is valid YAML
    code = runner.main([
        "--cases", str(cases), "--artefacts", str(EVAL / "artefacts"),
        "--replay-dir", str(EVAL / "replays"), "--thresholds", str(EVAL / "thresholds.yaml"), "--out", str(tmp_path / "o"),
    ])
    assert code == 1
    summary = (tmp_path / "o" / "summary.md").read_text()
    assert "**fail**" in summary and "Missed threat: payment gateway: R" in summary


def test_cli_fails_when_nothing_ran(tmp_path):
    (tmp_path / "cases").mkdir()
    assert runner.main(["--cases", str(tmp_path / "cases"), "--replay-dir", str(tmp_path), "--out", str(tmp_path / "o"),
                        "--thresholds", str(EVAL / "thresholds.yaml")]) == 1


async def test_risk_category_must_match_when_given(drafted, payments):
    case = payments.model_copy(deep=True)
    case.expect.risks = [RiskExpectation(element="invoice database", min_residual=Rating.LOW, category=["FOC"])]
    assert score(drafted, case).risk_recall == 0.0
    case.expect.risks = [RiskExpectation(element="invoice database", min_residual=Rating.LOW, category=["INF"])]
    assert score(drafted, case).risk_recall == 1.0


async def test_critic_asks_about_always_consider_categories_with_no_risk(drafted):
    flagged = {i.where for i in drafted.critique.issues if i.source == "check" and "confirm it was considered" in i.issue}
    assert flagged == {"SDL", "SUP", "FOC", "CRY"}
