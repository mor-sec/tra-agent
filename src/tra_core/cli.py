"""Local command line for running TRAs on a workstation.

Identity here comes from flags, for local development only. Deployed, the
portal builds the Principal from the user's validated Entra ID token.

Examples:
    tra-agent new --title "Payments portal" --artefact git:payments-portal-design.md \\
        --git-root examples/artefacts --user alice
    tra-agent gate TRA-2026-001 G1 approve --user alice --rationale "Scope confirmed" \\
        --internet-facing yes --cardholder-data yes --shared-platform no
    tra-agent show TRA-2026-001
    tra-agent report TRA-2026-001 --out out/
    tra-agent verify-audit
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from tra_core.artefacts import ArtefactSource, GitArtefactSource
from tra_core.audit import AuditLog, JsonlAuditSink, verify
from tra_core.gates import GateError
from tra_core.identity import Principal, Role
from tra_core.llm import ModelRouter, ReplayModelClient
from tra_core.orchestrator import LocalInvoker, Orchestrator
from tra_core.reference import Reference
from tra_core.register import CsvRegisterWriter, to_csv
from tra_core.report import render
from tra_core.schemas import Classification, Gate, TierFactors, WorkType
from tra_core.store import FileTraStore
from tra_core.tools import LocalToolClient, ToolSet


def _principal(args: argparse.Namespace) -> Principal:
    roles = [Role(r) for r in args.role]
    return Principal.human(
        args.user,
        *roles,
        clearance=Classification.parse(args.clearance),
        strong_auth=args.strong_auth,
        auth_time=datetime.now(UTC) if args.strong_auth else None,
    )


def _build(args: argparse.Namespace) -> tuple[Orchestrator, Reference, FileTraStore, AuditLog]:
    home = Path(args.home)
    reference = Reference()
    sources: dict[str, ArtefactSource] = {}
    if getattr(args, "git_root", None):
        sources["git"] = GitArtefactSource(Path(args.git_root))
    # Artefacts are read at the caller's clearance; commands without --clearance read no artefacts.
    clearance = Classification.parse(getattr(args, "clearance", "OFFICIAL"))
    toolset = ToolSet(reference, sources, lambda: clearance)
    tools = LocalToolClient(toolset)
    audit = AuditLog(JsonlAuditSink(home / "audit" / "events.jsonl"))
    if args.replay:
        router = ModelRouter({}, overrides={"*": ReplayModelClient.from_file(Path(args.replay))})
    else:
        router = ModelRouter.from_file(Path(args.models))
    invoker = LocalInvoker(router, tools, audit, reference, blob_dir=home / "audit" / "blobs")
    store = FileTraStore(home / "tras")
    orch = Orchestrator(store, invoker, tools, audit, reference, CsvRegisterWriter(home / "register"))
    return orch, reference, store, audit


def _status(tra) -> str:  # type: ignore[no-untyped-def]
    waiting = f", waiting at {tra.awaiting_gate.value}" if tra.awaiting_gate else ""
    counts = f"{len(tra.threats)} threats, {len(tra.risks)} risks"
    return f"{tra.id} [{tra.classification.label}] tier {tra.tier}: stage {tra.stage.value}{waiting}; {counts}"


async def _run(args: argparse.Namespace) -> int:
    orch, reference, store, audit = _build(args)
    if args.command == "new":
        refs = []
        for a in args.artefact:
            source, _, locator = a.partition(":")
            refs.append((source, locator))
        tra = await orch.create(
            title=args.title, work_type=WorkType(args.work_type), artefacts=refs, user=_principal(args)
        )
        print(_status(tra))
    elif args.command == "gate":
        try:
            flags = {"internet_facing": args.internet_facing, "handles_cardholder_data": args.cardholder_data,
                     "shared_platform": args.shared_platform}
            given = {k: v == "yes" for k, v in flags.items() if v is not None}
            if given and len(given) < len(flags):
                print("refused: give all three of --internet-facing, --cardholder-data and --shared-platform", file=sys.stderr)
                return 2
            factors = TierFactors(**given) if given else None
            tra, outcome = await orch.decide(
                args.tra, Gate(args.gate), _principal(args), args.decision, args.rationale, factors
            )
        except GateError as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 2
        if outcome.waiting_for:
            print(f"recorded; still waiting for {outcome.waiting_for}")
        print(_status(tra))
    elif args.command == "show":
        tra = store.load(args.tra)
        print(_status(tra))
        if tra.intake:
            i = tra.intake
            print(f"  tier factors: internet_facing={i.internet_facing} handles_cardholder_data="
                  f"{i.handles_cardholder_data} shared_platform={i.shared_platform}")
        if tra.critique:
            for i in tra.critique.issues:
                print(f"  [{i.severity}] {i.where}: {i.issue}")
    elif args.command == "report":
        tra = store.load(args.tra)
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{tra.id}.md").write_text(render(tra, reference), encoding="utf-8")
        (out / f"{tra.id}-risk-register.csv").write_text(to_csv(tra), encoding="utf-8")
        (out / f"{tra.id}.json").write_text(tra.model_dump_json(indent=1), encoding="utf-8")
        print(f"wrote {out}/{tra.id}.md, .json and -risk-register.csv")
    elif args.command == "verify-audit":
        events = audit.sink.read_all()
        problems = verify(events)
        print(json.dumps({"events": len(events), "problems": problems}, indent=1))
        return 1 if problems else 0
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tra-agent", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--home", default=".tra", help="local working folder for state, audit log and register")
    p.add_argument("--models", default="config/models.yaml")
    p.add_argument("--replay", help="replay recorded model responses from a JSON file (offline demo and tests)")
    sub = p.add_subparsers(dest="command", required=True)

    def identity(sp: argparse.ArgumentParser, default_roles: list[str]) -> None:
        sp.add_argument("--user", required=True)
        sp.add_argument("--role", action="append", default=None, choices=[r.value for r in Role])
        sp.add_argument("--clearance", default="OFFICIAL_SENSITIVE")
        sp.add_argument("--strong-auth", action="store_true", help="assert a fresh phishing-resistant MFA sign-in")
        sp.set_defaults(default_roles=default_roles)

    new = sub.add_parser("new", help="open a TRA and run it to G1")
    new.add_argument("--title", required=True)
    new.add_argument("--work-type", default="new_system", choices=[w.value for w in WorkType])
    new.add_argument("--artefact", action="append", required=True, help="source:locator, e.g. git:design.md")
    new.add_argument("--git-root")
    identity(new, ["practitioner"])

    gate = sub.add_parser("gate", help="record a gate decision and continue")
    gate.add_argument("tra")
    gate.add_argument("gate", choices=[g.value for g in Gate])
    gate.add_argument("decision", choices=["approve", "approve_with_changes", "return"])
    gate.add_argument("--rationale", required=True)
    for flag in ("--internet-facing", "--cardholder-data", "--shared-platform"):
        gate.add_argument(flag, choices=["yes", "no"], help="G1: confirm this tier factor (see `show`)")
    gate.add_argument("--git-root")
    identity(gate, ["practitioner"])

    show = sub.add_parser("show")
    show.add_argument("tra")
    report = sub.add_parser("report")
    report.add_argument("tra")
    report.add_argument("--out", default="out")
    sub.add_parser("verify-audit")

    args = p.parse_args(argv)
    if hasattr(args, "default_roles") and args.role is None:
        args.role = args.default_roles
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
