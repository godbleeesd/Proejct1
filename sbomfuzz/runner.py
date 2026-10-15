"""`sbomfuzz run`: all pipeline stages in one go on one machine, through the same code (and the
same files) as the CI jobs: plan -> generate -> fuzz -> report under one output directory."""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import stages
from .ecosystems import ECOSYSTEMS
from .prompts import AgentConfig
from .report import ComponentResult

log = logging.getLogger(__name__)

PLAN_FILE = "plan.json"
BUNDLES_DIR = "bundles"
FUZZ_DIR = "fuzz"


@dataclass
class RunConfig:
    sbom: Path
    out: Path
    workdir: Path
    agent: AgentConfig = field(default_factory=AgentConfig)
    fuzz_seconds: int = 600  # per harness
    stop_after_duplicates: int = 0  # 0: always fuzz the full time
    ecosystems: list[str] = field(default_factory=lambda: list(ECOSYSTEMS))
    include: list[str] = field(default_factory=list)  # glob patterns on name / purl
    limit: int | None = None
    jobs: int = 1
    keep_workdirs: bool = False


def run(config: RunConfig) -> tuple[list[ComponentResult], dict]:
    # Absolute paths: the MCP server and Claude Code run in other working directories.
    out, workdir = config.out.resolve(), config.workdir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    workdir.mkdir(parents=True, exist_ok=True)
    plan = stages.plan(config.sbom, stages.Selection(config.ecosystems, config.include, config.limit))
    stages.write_json(out / PLAN_FILE, plan)
    log.info("%d components to fuzz, %d skipped", len(plan["components"]), len(plan["skipped"]))

    stop = threading.Event()  # set once the subscription's usage limit is reached
    lock = threading.Lock()
    counter = [0]

    def work(entry: dict) -> None:
        c = stages.component_from(entry)
        with lock:
            counter[0] += 1
            tag = f"[{counter[0]}/{len(plan['components'])}]"
        if stop.is_set():
            stages.skipped_bundle(c, out / BUNDLES_DIR, "usage_limit",
                                  "the subscription usage limit was reached before this component")
            log.info("%s %s: skipped, usage limit reached", tag, c.display_name)
            return
        log.info("%s %s", tag, c.display_name)
        bundle = stages.generate(c, config.agent, out / BUNDLES_DIR, workdir, config.keep_workdirs)
        if bundle["status"] == "usage_limit":
            stop.set()
        if bundle["status"] == "ready":
            stages.fuzz(out / BUNDLES_DIR / c.slug, out / FUZZ_DIR, workdir, config.fuzz_seconds,
                        config.stop_after_duplicates, keep_workdir=config.keep_workdirs)

    if config.jobs <= 1:
        for entry in plan["components"]:
            work(entry)
    else:
        with ThreadPoolExecutor(max_workers=config.jobs) as pool:
            for future in [pool.submit(work, e) for e in plan["components"]]:
                future.result()  # re-raises fatal errors such as bad credentials

    results = stages.report(plan, out / BUNDLES_DIR, out / FUZZ_DIR, out)
    meta = stages.read_json(out / "report.json")
    meta.pop("components", None)
    return results, meta
