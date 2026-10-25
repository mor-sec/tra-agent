"""STRIDE-per-element: which categories apply to which DFD element."""

from __future__ import annotations

from tra_core.schemas import DataFlow, Element, ElementType, Stride

S, T, R, I, D, E = Stride.S, Stride.T, Stride.R, Stride.I, Stride.D, Stride.E  # noqa: E741 (STRIDE letters)

APPLICABLE: dict[str, set[Stride]] = {
    ElementType.EXTERNAL_ENTITY.value: {S, R},
    ElementType.PROCESS.value: {S, T, R, I, D, E},
    ElementType.DATA_STORE.value: {T, R, I, D},
    "data_flow": {T, I, D},
    "boundary_flow": {S, T, I, D, E},
}


def applicable(item: Element | DataFlow) -> set[Stride]:
    if isinstance(item, DataFlow):
        return APPLICABLE["boundary_flow" if item.crosses_boundary else "data_flow"]
    return APPLICABLE[item.type.value]


def invalid_categories(item: Element | DataFlow, categories: list[Stride]) -> list[Stride]:
    allowed = applicable(item)
    return [c for c in categories if c not in allowed]
