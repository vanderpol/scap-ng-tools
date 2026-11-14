"""Explicit implementation budgets for SCAP-NG conversion.

These limits are safeguards, not OVAL language restrictions or normative
SCAP-NG thresholds. Exceeding one must never produce a complete-looking
partial Assessment.
"""
from __future__ import annotations
from dataclasses import dataclass
import time


@dataclass(frozen=True)
class ConversionBudget:
    dependency_nodes: int | None = None
    dependency_edges: int | None = None
    expression_depth: int | None = None
    generated_values: int | None = None
    value_bytes: int | None = None
    output_nodes: int | None = None
    elapsed_ms: int | None = None

    def __post_init__(self):
        for name, value in self.__dict__.items():
            if value is not None and value < 0:
                raise ValueError(f"{name} budget must be non-negative")


class ConversionBudgetExceeded(RuntimeError):
    def __init__(self, resource: str, limit: int, observed: int):
        self.resource = resource
        self.limit = limit
        self.observed = observed
        super().__init__(
            f"conversion_resource_limit:{resource}:limit={limit}:observed={observed}"
        )

    @property
    def diagnostic(self):
        return str(self)


class ConversionBudgetTracker:
    def __init__(self, budget=None, *, clock=None):
        self.budget = budget or ConversionBudget()
        self._clock = clock or time.monotonic
        self._start = self._clock()
        self.dependency_nodes = 0
        self.dependency_edges = 0

    def _check(self, resource, observed):
        limit = getattr(self.budget, resource)
        if limit is not None and observed > limit:
            raise ConversionBudgetExceeded(resource, limit, observed)

    def note_node(self, count=1):
        self.dependency_nodes += count
        self._check("dependency_nodes", self.dependency_nodes)

    def note_edge(self, count=1):
        self.dependency_edges += count
        self._check("dependency_edges", self.dependency_edges)

    def note_expression_depth(self, depth):
        self._check("expression_depth", depth)

    def note_generated_values(self, count):
        self._check("generated_values", count)

    def note_value_bytes(self, count):
        self._check("value_bytes", count)

    def note_output_nodes(self, count):
        self._check("output_nodes", count)

    def check_elapsed(self):
        if self.budget.elapsed_ms is None:
            return
        elapsed_ms = int((self._clock() - self._start) * 1000)
        self._check("elapsed_ms", elapsed_ms)


def count_output_nodes(value):
    """Count generated native structural/value nodes iteratively."""
    count = 0
    stack = [value]
    while stack:
        current = stack.pop()
        count += 1
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend(current)
    return count
