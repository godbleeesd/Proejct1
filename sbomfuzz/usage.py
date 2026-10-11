"""Token accounting for the harness-generation sessions."""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    # Claude Code's API-equivalent estimate; not a bill on a subscription.
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


class UsageTotal:
    """Thread-safe running total across components."""

    def __init__(self):
        self.total = Usage()
        self._lock = threading.Lock()

    def add(self, usage: Usage) -> None:
        with self._lock:
            self.total.add(usage)
