"""Fuzzing every selected component of an SBOM and collecting the results."""

from __future__ import annotations

import fnmatch
import logging
import os
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import anthropic

from . import report
from .agent import FuzzAgent
from .claude_code import ClaudeCodeAgent, ClaudeCodeAuthError
from .ecosystems import ECOSYSTEMS
from .fetch import FetchError, fetch
from .prompts import AgentConfig
from .report import ComponentResult
from .sbom import Component, load_cyclonedx
from .tools import ToolBox
from .usage import BudgetTracker
from .workspace import Workspace

log = logging.getLogger(__name__)

BACKENDS = ("api", "subscription")


@dataclass
class RunConfig:
    sbom: Path
    out: Path
    workdir: Path
    backend: str = "api"  # api: Messages API with ANTHROPIC_API_KEY; subscription: Claude Code CLI
    agent: AgentConfig = field(default_factory=AgentConfig)
    ecosystems: list[str] = field(default_factory=lambda: list(ECOSYSTEMS))
    include: list[str] = field(default_factory=list)  # glob patterns on name / purl
    limit: int | None = None
    jobs: int = 1
    budget_usd: float | None = None
    keep_workdirs: bool = False


@dataclass
class _Shared:
    """State shared by all components of a run."""

    config: RunConfig
    tracker: BudgetTracker
    client: anthropic.Anthropic | None
    total: int
    stop_reason: str | None = None  # set when no further component should start
    started: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def next_tag(self) -> str:
        with self.lock:
            self.started += 1
            return f"[{self.started}/{self.total}]"


def select(components: list[Component], config: RunConfig) -> list[Component]:
    def wanted(c: Component) -> bool:
        if not config.include:
            return True
        return any(fnmatch.fnmatch(c.name, p) or fnmatch.fnmatch(c.purl or "", p) for p in config.include)

    return [c for c in components if wanted(c)]


def run(config: RunConfig) -> tuple[list[ComponentResult], dict]:
    components = select(load_cyclonedx(config.sbom), config)
    started = datetime.now(timezone.utc)
    config.out.mkdir(parents=True, exist_ok=True)
    config.workdir.mkdir(parents=True, exist_ok=True)

    results: dict[str, ComponentResult] = {}
    todo: list[Component] = []
    for c in components:
        reason = c.skip_reason()
        if reason is None and c.ecosystem not in config.ecosystems:
            reason = f"ecosystem {c.ecosystem} not selected"
        if reason is None and config.limit is not None and len(todo) >= config.limit:
            reason = "over --limit"
        if reason:
            results[c.key] = ComponentResult(c.to_dict(), "skipped", reason)
        else:
            todo.append(c)

    client = anthropic.Anthropic(max_retries=5) if config.backend == "api" else None
    shared = _Shared(config, BudgetTracker(config.budget_usd), client, len(todo))
    log.info("%d components in SBOM, %d to fuzz (backend: %s)", len(components), len(todo), config.backend)

    def work(c: Component) -> None:
        results[c.key] = _process(c, shared)

    if config.jobs <= 1:
        for c in todo:
            work(c)
    else:
        with ThreadPoolExecutor(max_workers=config.jobs) as pool:
            for future in [pool.submit(work, c) for c in todo]:
                future.result()  # re-raises fatal errors such as bad credentials

    ordered = [results[c.key] for c in components]
    meta = {
        "tool": "sbomfuzz",
        "sbom": str(config.sbom),
        "started": started.isoformat(timespec="seconds"),
        "finished": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "backend": config.backend,
        "model": config.agent.model or "default",
        "effort": config.agent.effort,
        "fuzz_seconds_per_run": config.agent.fuzz_seconds,
    }
    total = shared.tracker.total
    report.write_json(config.out / "report.json", meta, ordered, total)
    (config.out / "report.md").write_text(report.render_markdown(meta, ordered, total), encoding="utf-8")
    _match_owner(config.out)
    return ordered, meta


def _process(c: Component, shared: _Shared) -> ComponentResult:
    config = shared.config
    tag = shared.next_tag()
    result = ComponentResult(c.to_dict(), "error")
    if shared.stop_reason is None and shared.tracker.exhausted():
        shared.stop_reason = "budget_exhausted"
    if shared.stop_reason:
        result.status = shared.stop_reason
        result.detail = {"budget_exhausted": "the run's budget was used up before this component",
                         "usage_limit": "the subscription usage limit was reached before this component"
                         }.get(shared.stop_reason, "")
        log.info("%s %s: skipped (%s)", tag, c.display_name, shared.stop_reason)
        return result

    start = time.monotonic()
    ws_root = config.workdir / c.slug
    shutil.rmtree(ws_root, ignore_errors=True)
    ws = Workspace.create(ws_root)
    artifacts = config.out / "components" / c.slug
    artifacts.mkdir(parents=True, exist_ok=True)
    transcript = artifacts / "transcript.jsonl"
    session_dir = _sessions_root() / c.slug
    try:
        log.info("%s %s (%s): downloading", tag, c.display_name, c.ecosystem)
        try:
            fetched = fetch(c, ws)
        except FetchError as e:
            result.status, result.detail = "fetch_failed", str(e)
            log.warning("%s %s: download failed: %s", tag, c.display_name, str(e).splitlines()[0])
            return result

        log.info("%s %s: agent started", tag, c.display_name)
        ecosystem = ECOSYSTEMS[c.ecosystem]
        if config.backend == "subscription":
            agent = ClaudeCodeAgent(config.agent, ecosystem, c, ws, fetched.detail, shared.tracker, transcript,
                                    session_dir)
        else:
            toolbox = ToolBox(ws, ecosystem, config.agent.fuzz_seconds, config.agent.command_timeout,
                              transcript, c.display_name)
            agent = FuzzAgent.for_component(shared.client, config.agent, ecosystem, c, ws, fetched.detail,
                                            shared.tracker, toolbox)
        outcome = agent.run()
        result.status, result.detail, result.report = outcome.status, outcome.detail, outcome.report
        result.usage, result.turns, result.fuzz_runs = outcome.usage, outcome.turns, outcome.fuzz_runs
        if outcome.status == "usage_limit":
            shared.stop_reason = "usage_limit"
        cost = f"${outcome.usage.cost_usd:.2f}" if outcome.usage.cost_usd is not None else "n/a"
        log.info("%s %s: %s, %d bug(s), %d turns, est. %s", tag, c.display_name, result.status,
                 len(result.bugs), outcome.turns, cost)
        return result
    except (anthropic.AuthenticationError, ClaudeCodeAuthError):
        raise
    except Exception as e:
        log.exception("%s %s: failed", tag, c.display_name)
        result.status, result.detail = "error", f"{type(e).__name__}: {e}"
        return result
    finally:
        result.duration_seconds = time.monotonic() - start
        _save_artifacts(ws, artifacts)
        result.artifacts = str(artifacts)
        shutil.rmtree(session_dir, ignore_errors=True)
        if not config.keep_workdirs:
            shutil.rmtree(ws_root, ignore_errors=True)


def _sessions_root() -> Path:
    # Under the orchestrator's home (/root in the image), which the sandbox user cannot enter.
    root = Path.home() / ".cache" / "sbomfuzz" / "sessions"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _save_artifacts(ws: Workspace, dest: Path) -> None:
    for name in ("harnesses", "crashes"):
        src = ws.root / name
        if src.is_dir() and any(src.iterdir()):
            shutil.copytree(src, dest / name, symlinks=True, dirs_exist_ok=True)


def _match_owner(out: Path) -> None:
    """Give results the owner of the output directory (a bind mount owned by the host user)."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    st = out.stat()
    if st.st_uid == 0:
        return
    for root, dirs, files in os.walk(out):
        os.chown(root, st.st_uid, st.st_gid)
        for name in files:
            os.chown(os.path.join(root, name), st.st_uid, st.st_gid, follow_symlinks=False)
