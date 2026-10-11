"""Fuzzing one validated harness for a fixed time, without the model.

libFuzzer-style fuzzers stop at the first crash. To keep fuzzing past it, the campaign
restarts the fuzzer on the same (growing) corpus until the time budget is spent, so deep
bugs get the full time even when a shallow one keeps recurring. Crashes are grouped by
signature; inputs that only rediscover a known crash are deleted and just counted.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from .crashes import classify
from .ecosystems import Ecosystem
from .workspace import Workspace

log = logging.getLogger(__name__)

MIN_RUN_SECONDS = 5


@dataclass
class CrashGroup:
    kind: str
    signature: str
    summary: str
    stack: str
    crash_file: str          # first input that triggered it
    reproduction: str
    count: int = 1           # how many runs hit it

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class HarnessResult:
    name: str
    target: str
    status: str = "pending"  # clean | crashes | error
    fuzz_seconds: float = 0.0
    runs: int = 0
    executions: int = 0
    last_stats: str = ""
    error: str = ""
    crashes: list[CrashGroup] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["fuzz_seconds"] = round(self.fuzz_seconds, 1)
        d["crashes"] = [c.to_dict() for c in self.crashes]
        return d


def run_campaign(ws: Workspace, ecosystem: Ecosystem, name: str, target: str, seconds: int,
                 stop_after_duplicates: int = 0) -> HarnessResult:
    """Fuzz for `seconds`. With stop_after_duplicates > 0, stop early once that many restarts
    in a row found only known crashes."""
    result = HarnessResult(name=name, target=target)
    corpus = ws.corpus / name
    deadline = time.monotonic() + seconds
    duplicates_in_a_row = 0
    by_signature: dict[str, CrashGroup] = {}

    while (remaining := int(deadline - time.monotonic())) >= MIN_RUN_SECONDS:
        run = ecosystem.fuzz(ws, target, corpus, remaining)
        result.runs += 1
        result.fuzz_seconds += run.duration
        result.executions += run.executions
        result.last_stats = run.stats or result.last_stats

        if run.status == "error":
            result.error = run.output[-3000:]
            break
        if run.status == "clean":
            break  # ran the whole remaining time without crashing

        info = classify(run.output)
        crash_file = run.crash_files[0] if run.crash_files else ""
        group = by_signature.get(info.signature)
        if group:
            group.count += 1
            duplicates_in_a_row += 1
            for path in run.new_files:  # keep crashes/ to one input per signature
                (ws.root / path).unlink(missing_ok=True)
            if stop_after_duplicates and duplicates_in_a_row >= stop_after_duplicates:
                log.info("  %s: only known crashes for %d restarts, stopping", name, duplicates_in_a_row)
                break
        else:
            duplicates_in_a_row = 0
            by_signature[info.signature] = CrashGroup(
                kind=info.kind, signature=info.signature, summary=info.summary, stack=info.stack,
                crash_file=crash_file,
                reproduction=ecosystem.repro_command(ws, target, crash_file) if crash_file else "",
            )
            log.info("  %s: new crash: %s", name, info.summary)

    result.crashes = list(by_signature.values())
    result.status = "error" if result.error and not result.crashes else ("crashes" if result.crashes else "clean")
    return result
