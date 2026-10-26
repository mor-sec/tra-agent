"""The TRA stage machine. Only this module decides which stage comes next."""

from __future__ import annotations

from tra_core.schemas import Gate, Stage

ORDER = [
    Stage.INTAKE,
    Stage.CONTEXT,
    Stage.THREATS,
    Stage.ANALYSIS,
    Stage.EVALUATION,
    Stage.TREATMENT,
    Stage.ACCEPTANCE,
    Stage.MONITOR,
]

# A gate sits at the end of these stages; the TRA cannot leave the stage until it passes.
GATE_AFTER = {Stage.INTAKE: Gate.G1, Stage.EVALUATION: Gate.G2, Stage.ACCEPTANCE: Gate.G3}

# Where a TRA goes when a reviewer returns it at a gate. G3 goes back to analysis so the
# risks are re-rated (treatment runs no model) and the changed draft passes G2 again.
RETURN_TO = {Gate.G1: Stage.INTAKE, Gate.G2: Stage.THREATS, Gate.G3: Stage.ANALYSIS}


def next_stage(stage: Stage) -> Stage:
    i = ORDER.index(stage)
    if i == len(ORDER) - 1:
        raise ValueError("monitor is the final stage")
    return ORDER[i + 1]


def gate_after(stage: Stage) -> Gate | None:
    return GATE_AFTER.get(stage)
