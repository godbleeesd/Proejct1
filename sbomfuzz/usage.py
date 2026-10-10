"""Token and cost accounting across all components of a run."""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass

# USD per million tokens: (input, output, cache read). Cache writes (5-minute TTL)
# cost 1.25x input. Models not listed are reported in tokens only.
PRICES = {
    "claude-fable-5-1": (10.00, 50.00, 0.25),
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20),
    # Server-side fallback target for cyber-category refusals.
    "claude-opus-4-8": (5.00, 25.00, 0.50),
}


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: float | None = 0.0

    def add(self, other: "Usage") -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens
        if self.cost_usd is None or other.cost_usd is None:
            self.cost_usd = None
        else:
            self.cost_usd += other.cost_usd

    def to_dict(self) -> dict:
        d = asdict(self)
        if d["cost_usd"] is not None:
            d["cost_usd"] = round(d["cost_usd"], 4)
        return d


def from_response(model: str, usage) -> Usage:
    """Convert an API response's usage block, priced at the model that served it."""
    u = Usage(
        input_tokens=usage.input_tokens or 0,
        output_tokens=usage.output_tokens or 0,
        cache_read_tokens=getattr(usage, "cache_read_input_tokens", None) or 0,
        cache_write_tokens=getattr(usage, "cache_creation_input_tokens", None) or 0,
    )
    price = PRICES.get(model)
    if price is None:
        u.cost_usd = None
    else:
        inp, out, read = price
        u.cost_usd = (u.input_tokens * inp + u.output_tokens * out + u.cache_read_tokens * read
                      + u.cache_write_tokens * inp * 1.25) / 1_000_000
    return u


class BudgetTracker:
    """Thread-safe running total with an optional spending limit."""

    def __init__(self, budget_usd: float | None):
        self.budget_usd = budget_usd
        self.total = Usage()
        self._lock = threading.Lock()

    def add(self, usage: Usage) -> None:
        with self._lock:
            self.total.add(usage)

    def exhausted(self) -> bool:
        with self._lock:
            cost = self.total.cost_usd
            return self.budget_usd is not None and cost is not None and cost >= self.budget_usd
