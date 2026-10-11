"""The pipeline: for each SBOM component, download it, let Claude write harnesses and seeds,
then fuzz every accepted harness for a fixed time and collect the crashes."""

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

from . import report
from .campaign import run_campaign
from .claude_code import ClaudeCodeAuthError, HarnessGenerator
from .ecosystems import ECOSYSTEMS
from .fetch import FetchError, fetch
from .prompts import AgentConfig
from .report import ComponentResult
from .sbom import Component, load_cyclonedx
from .usage import UsageTotal
from .workspace import Workspace

log = logging.getLogger(__name__)


@dataclass
class RunConfig:
    sbom: Path
    out: Path
    workdir: Path
    agent: AgentConfig = field(default_factory=AgentConfig)
    fuzz_seconds: int = 600  # per harness
    ecosystems: list[str] = field(default_factory=lambda: list(ECOSYSTEMS))
    include: list[str] = field(default_factory=list)  # glob patterns on name / purl
    limit: int | None = None
    jobs: int = 1
    keep_workdirs: bool = False


@dataclass
class _Shared:
    """State shared by all components of a run."""

    config: RunConfig
    usage: UsageTotal
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
    # Absolute paths: the MCP server and Claude Code run in other working directories.
    config.out, config.workdir = config.out.resolve(), config.workdir.resolve()
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

    shared = _Shared(config, UsageTotal(), len(todo))
    log.info("%d components in SBOM, %d to fuzz", len(components), len(todo))

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
        "model": config.agent.model or "default",
        "effort": config.agent.effort,
        "fuzz_seconds_per_harness": config.fuzz_seconds,
    }
    report.write_json(config.out / "report.json", meta, ordered, shared.usage.total)
    (config.out / "report.md").write_text(report.render_markdown(meta, ordered, shared.usage.total), encoding="utf-8")
    _match_owner(config.out)
    return ordered, meta


def _process(c: Component, shared: _Shared) -> ComponentResult:
    config = shared.config
    tag = shared.next_tag()
    result = ComponentResult(c.to_dict(), "error")
    if shared.stop_reason:
        result.status = shared.stop_reason
        result.detail = "the subscription usage limit was reached before this component"
        log.info("%s %s: skipped (%s)", tag, c.display_name, shared.stop_reason)
        return result

    start = time.monotonic()
    ws_root = config.workdir / c.slug
    shutil.rmtree(ws_root, ignore_errors=True)
    ws = Workspace.create(ws_root)
    artifacts = config.out / "components" / c.slug
    artifacts.mkdir(parents=True, exist_ok=True)
    session_dir = _sessions_root() / c.slug
    ecosystem = ECOSYSTEMS[c.ecosystem]
    try:
        log.info("%s %s (%s): downloading", tag, c.display_name, c.ecosystem)
        try:
            fetched = fetch(c, ws)
        except FetchError as e:
            result.status, result.detail = "fetch_failed", str(e)
            log.warning("%s %s: download failed: %s", tag, c.display_name, str(e).splitlines()[0])
            return result

        log.info("%s %s: Claude is writing harnesses", tag, c.display_name)
        generated = HarnessGenerator(config.agent, ecosystem, c, ws, fetched.detail, artifacts / "transcript.jsonl",
                                     session_dir).run()
        shared.usage.add(generated.usage)
        result.usage, result.turns = generated.usage, generated.turns
        result.attempts, result.validation = generated.attempts, generated.validation
        if generated.status != "done":
            result.status, result.detail = generated.status, generated.detail
            if generated.status == "usage_limit":
                shared.stop_reason = "usage_limit"
            log.info("%s %s: harness generation %s: %s", tag, c.display_name, generated.status, generated.detail)
            return result
        if not generated.harnesses:
            result.status = "no_harness"
            result.detail = "no harness passed validation" if generated.attempts else "the model submitted no harnesses"
            log.info("%s %s: %s", tag, c.display_name, result.detail)
            return result

        log.info("%s %s: %d harness(es) accepted, fuzzing each for %ss", tag, c.display_name,
                 len(generated.harnesses), config.fuzz_seconds)
        for h in generated.harnesses:
            log.info("%s %s: fuzzing %s", tag, c.display_name, h["name"])
            fuzzed = run_campaign(ws, ecosystem, h["name"], h["target"], config.fuzz_seconds)
            result.harnesses.append({**h, **fuzzed.to_dict()})
        result.status = "completed"
        crashes = sum(len(h["crashes"]) for h in result.harnesses)
        log.info("%s %s: done, %d unique crash(es)", tag, c.display_name, crashes)
        return result
    except ClaudeCodeAuthError:
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
    # Only the seeds: the fuzzed corpus can be large.
    for seed in ws.corpus.glob("*/seed-*"):
        target = dest / "seeds" / seed.parent.name / seed.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(seed, target)


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
