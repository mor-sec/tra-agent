"""Run the golden set: draft each case's TRA up to G2, score it, gate on thresholds.

    tra-eval --cases eval/golden --artefacts eval/artefacts --models config/models.yaml --out eval-out/
    tra-eval --cases eval/golden --artefacts eval/artefacts --replay-dir eval/replays --only payments-portal

G1 is approved by a dedicated evaluation identity (`eval-runner`), recorded in
the audit log like any other decision, so evaluation runs are never mistaken
for real assessments. Each case can run several times (`--repeat`); the gate
uses the worst run, because a model that finds the card-skimming threat two
times in three is not good enough.

Exit status: 0 when every case meets the thresholds, 1 otherwise.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from tra_core.agents.base import AgentFailure
from tra_core.artefacts import ArtefactError, GitArtefactSource
from tra_core.audit import AuditLog, MemoryAuditSink, verify
from tra_core.classification import ClassificationError
from tra_core.identity import Principal, Role
from tra_core.llm import ModelRouter, ReplayModelClient
from tra_core.orchestrator import LocalInvoker, Orchestrator
from tra_core.reference import Reference
from tra_core.store import FileTraStore
from tra_core.tools import LocalToolClient, ToolError, ToolSet
from tra_eval.golden import GoldenCase, Score, Thresholds, load_cases, score

EVAL_PRINCIPAL = Principal.human("eval-runner", Role.PRACTITIONER)
WORST_FIRST = ("threat_recall", "element_recall", "risk_recall", "critique_recall")


async def run_case(case: GoldenCase, router: ModelRouter, artefact_root: Path, work: Path) -> Score:
    reference = Reference()
    audit = AuditLog(MemoryAuditSink())
    tools = LocalToolClient(ToolSet(reference, {"git": GitArtefactSource(artefact_root)}))
    orch = Orchestrator(FileTraStore(work), LocalInvoker(router, tools, audit, reference), tools, audit, reference)
    try:
        tra = await orch.create(
            title=case.title, work_type=case.work_type, artefacts=list(case.artefacts), user=EVAL_PRINCIPAL
        )
    except (ArtefactError, ClassificationError, ToolError) as exc:
        return Score(case=case.id, refused=True, error=None if case.expect.refused else str(exc))
    try:
        tra, _ = await orch.decide(tra.id, tra.awaiting_gate, EVAL_PRINCIPAL, "approve", "automated evaluation run")  # type: ignore[arg-type]
    except AgentFailure as exc:
        return Score(case=case.id, error=f"agent failed: {exc}")
    result = score(tra, case)
    if problems := verify(audit.sink.read_all()):
        result.error = f"audit chain broken: {problems[:2]}"
    return result


def worst(scores: list[Score]) -> Score:
    """The run that would fail first: errors, then the lowest recall."""
    errored = [s for s in scores if s.error]
    if errored:
        return errored[0]
    return min(scores, key=lambda s: tuple(getattr(s, m) for m in WORST_FIRST))


def summary_markdown(rows: list[tuple[GoldenCase, Score, list[str]]], thresholds: Thresholds) -> str:
    out = [
        "# TRA agent evaluation",
        "",
        f"Thresholds: threat recall {thresholds.threat_recall:.0%}, element recall {thresholds.element_recall:.0%}, "
        f"risk recall {thresholds.risk_recall:.0%}, critique recall {thresholds.critique_recall:.0%}.",
        "",
        "| Case | Result | Threats | Elements | Risks | Critique | Classification | Tier |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for case, s, fails in rows:
        result = "pass" if not fails else "**fail**"
        if case.expect.refused:
            out.append(f"| {case.id} | {result} | refused as expected: {s.refused} | | | | | |")
            continue
        out.append(
            f"| {case.id} | {result} | {s.threat_recall:.0%} | {s.element_recall:.0%} | {s.risk_recall:.0%} "
            f"| {s.critique_recall:.0%} | {'ok' if s.classification_ok else 'wrong'} | {'ok' if s.tier_ok else 'wrong'} |"
        )
    for case, s, fails in rows:
        if fails or s.misses:
            out += ["", f"## {case.id}", ""]
            out += [f"- Gate: {f}" for f in fails]
            out += [f"- Missed {m.kind}: {m.expected}" + (f" ({m.why})" if m.why else "") for m in s.misses]
    return "\n".join(out) + "\n"


async def run(args: argparse.Namespace) -> int:
    cases = [c for c in load_cases(args.cases) if not args.only or c.id in args.only]
    thresholds = Thresholds.load(args.thresholds) if args.thresholds else Thresholds()
    args.out.mkdir(parents=True, exist_ok=True)
    rows = []
    for case in cases:
        runs = []
        for i in range(args.repeat):
            if args.replay_dir:
                replay = args.replay_dir / f"{case.id}.json"
                if replay.exists():
                    client = ReplayModelClient.from_file(replay)
                elif case.expect.refused:
                    client = ReplayModelClient({})  # must be refused before any model call
                else:
                    print(f"{case.id}: no recording at {replay}, skipped", file=sys.stderr)
                    break
                router = ModelRouter({}, overrides={"*": client})
            else:
                router = ModelRouter.from_file(args.models)
            runs.append(await run_case(case, router, args.artefacts, args.out / "work" / f"{case.id}-{i}"))
        if not runs:
            continue
        s = worst(runs)
        rows.append((case, s, thresholds.failures(s, case)))
        print(f"{case.id}: {'pass' if not rows[-1][2] else 'FAIL ' + '; '.join(rows[-1][2])}")
    (args.out / "summary.md").write_text(summary_markdown(rows, thresholds), encoding="utf-8")
    (args.out / "scores.json").write_text(
        json.dumps([{"case": c.id, "failures": f, **s.model_dump(mode="json")} for c, s, f in rows], indent=1),
        encoding="utf-8",
    )
    return 1 if any(f for _, _, f in rows) or not rows else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tra-eval", description="Score the TRA agent against the golden set.")
    p.add_argument("--cases", type=Path, default=Path("eval/golden"))
    p.add_argument("--artefacts", type=Path, default=Path("eval/artefacts"))
    p.add_argument("--models", type=Path, default=Path("config/models.yaml"))
    p.add_argument("--replay-dir", type=Path, help="use recorded model output instead of live models")
    p.add_argument("--thresholds", type=Path, default=Path("eval/thresholds.yaml"))
    p.add_argument("--repeat", type=int, default=1, help="runs per case; the gate uses the worst")
    p.add_argument("--only", nargs="*")
    p.add_argument("--out", type=Path, default=Path("eval-out"))
    return asyncio.run(run(p.parse_args(argv)))


if __name__ == "__main__":
    sys.exit(main())
