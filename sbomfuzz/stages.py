"""The fuzzing pipeline as separate stages that exchange files, so a CI system can run each
as its own job and pass the results on as artifacts:

  plan      SBOM -> plan.json: the components to process (one job each) and the skipped ones
  generate  one component -> bundle: Claude's validated harnesses, seeds and build script
  fuzz      one bundle (optionally one harness) -> fuzz result: crashes and statistics
  report    plan + bundles + fuzz results -> report.md / report.json

Stages share nothing but these files: `fuzz` downloads the component again into a fresh
workspace and rebuilds the harnesses from the bundle, so it can run on another machine.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import report as report_md
from . import sandbox
from .campaign import run_campaign
from .claude_code import ClaudeCodeAuthError, HarnessGenerator
from .ecosystems import ECOSYSTEMS
from .fetch import FetchError, fetch
from .prompts import AgentConfig
from .report import ComponentResult
from .sbom import Component, load_cyclonedx
from .usage import Usage
from .workspace import Workspace

log = logging.getLogger(__name__)

BUNDLE_FILE = "bundle.json"
RESULT_FILE = "result.json"
BUNDLE_FILES = "workspace"  # bundle subdirectory mirroring the workspace paths of the harness files
_BINARY_MAGIC = (b"\x7fELF", b"!<arch>")  # build outputs: rebuilt by the fuzz stage, not shipped


@dataclass
class Selection:
    ecosystems: list[str] = field(default_factory=lambda: list(ECOSYSTEMS))
    include: list[str] = field(default_factory=list)  # glob patterns on name / purl
    limit: int | None = None


# --- plan --------------------------------------------------------------------------------

def plan(sbom: Path, selection: Selection) -> dict:
    """The components to process and the skipped ones, with reasons."""
    components = load_cyclonedx(sbom)
    if selection.include:
        components = [c for c in components
                      if any(fnmatch.fnmatch(c.name, p) or fnmatch.fnmatch(c.purl or "", p) for p in selection.include)]
    todo, skipped = [], []
    for c in components:
        reason = c.skip_reason()
        if reason is None and c.ecosystem not in selection.ecosystems:
            reason = f"ecosystem {c.ecosystem} not selected"
        if reason is None and selection.limit is not None and len(todo) >= selection.limit:
            reason = "over --limit"
        if reason:
            skipped.append({"slug": c.slug, "reason": reason, "component": c.to_dict()})
        else:
            todo.append({"slug": c.slug, "name": c.display_name, "ecosystem": c.ecosystem, "component": c.to_dict()})
    return {"sbom": str(sbom), "created": _now(), "components": todo, "skipped": skipped}


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def component_from(entry: dict) -> Component:
    return Component(**entry["component"])


# --- generate ----------------------------------------------------------------------------

def generate(c: Component, agent: AgentConfig, out_root: Path, workdir: Path, keep_workdir: bool = False) -> dict:
    """Download the component and let Claude write validated harnesses; writes <out_root>/<slug>/.

    Bundle statuses: ready (harnesses accepted), no_harness, incomplete, usage_limit, fetch_failed, error.
    Bad credentials raise ClaudeCodeAuthError: no other component can succeed either.
    """
    out_root, workdir = out_root.resolve(), workdir.resolve()
    out = out_root / c.slug
    shutil.rmtree(out, ignore_errors=True)  # never mix in files from an earlier run
    out.mkdir(parents=True)
    bundle = {"component": c.to_dict(), "slug": c.slug, "status": "error", "detail": "", "harnesses": [],
              "attempts": 0, "validation": [], "turns": 0, "usage": Usage().to_dict(), "files": [],
              "model": agent.model or "default", "effort": agent.effort, "created": _now()}
    start = time.monotonic()
    ws = Workspace.create(workdir / c.slug)
    session_dir = _sessions_root() / c.slug
    try:
        log.info("%s (%s): downloading", c.display_name, c.ecosystem)
        try:
            fetched = fetch(c, ws)
        except FetchError as e:
            bundle.update(status="fetch_failed", detail=str(e))
            log.warning("%s: download failed: %s", c.display_name, str(e).splitlines()[0])
            return bundle

        log.info("%s: Claude is writing harnesses", c.display_name)
        generated = HarnessGenerator(agent, ECOSYSTEMS[c.ecosystem], c, ws, fetched.detail, out / "transcript.jsonl",
                                     session_dir).run()
        bundle.update(attempts=generated.attempts, validation=generated.validation, turns=generated.turns,
                      usage=generated.usage.to_dict(), fetch_detail=fetched.detail)
        if generated.status != "done":
            bundle.update(status=generated.status, detail=generated.detail)
        elif not generated.harnesses:
            bundle.update(status="no_harness", detail="no harness passed validation" if generated.attempts
                          else "the model submitted no harnesses")
        else:
            bundle.update(status="ready", harnesses=generated.harnesses,
                          files=_save_bundle_files(ws, out / BUNDLE_FILES, generated.written))
        log.info("%s: %s%s", c.display_name, bundle["status"],
                 f", {len(bundle['harnesses'])} harness(es)" if bundle["harnesses"] else f": {bundle['detail']}")
        return bundle
    except ClaudeCodeAuthError:
        raise
    except Exception as e:
        log.exception("%s: harness generation failed", c.display_name)
        bundle.update(status="error", detail=f"{type(e).__name__}: {e}")
        return bundle
    finally:
        bundle["duration_seconds"] = round(time.monotonic() - start, 1)
        write_json(out / BUNDLE_FILE, bundle)
        shutil.rmtree(session_dir, ignore_errors=True)
        if not keep_workdir:
            shutil.rmtree(ws.root, ignore_errors=True)


def skipped_bundle(c: Component, out_root: Path, status: str, detail: str) -> dict:
    """A bundle for a component that was not attempted (e.g. after the usage limit was hit)."""
    out = out_root.resolve() / c.slug
    shutil.rmtree(out, ignore_errors=True)
    bundle = {"component": c.to_dict(), "slug": c.slug, "status": status, "detail": detail, "harnesses": [],
              "attempts": 0, "validation": [], "turns": 0, "usage": Usage().to_dict(), "files": [], "created": _now()}
    write_json(out / BUNDLE_FILE, bundle)
    return bundle


def _save_bundle_files(ws: Workspace, dest: Path, written: list[str]) -> list[str]:
    """Copy the harness sources, build script, seeds and any other file the model wrote."""
    paths = {ws.relative(p) for p in ws.harnesses.rglob("*") if p.is_file()}
    paths |= {ws.relative(p) for p in ws.corpus.glob("*/seed-*") if p.is_file()}
    paths |= {p for p in written if (ws.root / p).is_file()}
    saved = []
    for relative in sorted(paths):
        src = ws.root / relative
        if src.is_symlink() or _is_build_output(src):
            continue
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        saved.append(relative)
    return saved


def _is_build_output(path: Path) -> bool:
    with path.open("rb") as f:
        return f.read(8).startswith(_BINARY_MAGIC)


# --- fuzz --------------------------------------------------------------------------------

def fuzz(bundle_dir: Path, out_root: Path, workdir: Path, seconds: int, stop_after_duplicates: int = 0,
         harnesses: list[str] | None = None, keep_workdir: bool = False) -> list[dict]:
    """Fuzz a ready bundle's harnesses (all, or the named ones); writes <out_root>/<slug>/<harness>/."""
    bundle_dir, out_root, workdir = bundle_dir.resolve(), out_root.resolve(), workdir.resolve()
    bundle = read_json(bundle_dir / BUNDLE_FILE)
    if bundle["status"] != "ready":
        log.info("%s: nothing to fuzz (%s)", bundle["slug"], bundle["status"])
        return []
    c = Component(**bundle["component"])
    chosen = [h for h in bundle["harnesses"] if not harnesses or h["name"] in harnesses]
    unknown = set(harnesses or []) - {h["name"] for h in bundle["harnesses"]}
    if unknown:
        raise ValueError(f"{c.display_name} has no harness named {', '.join(sorted(unknown))}")
    ecosystem = ECOSYSTEMS[c.ecosystem]

    ws = Workspace.create(workdir / f"{c.slug}-fuzz")
    results = []
    try:
        problem = None
        try:
            fetch(c, ws)
        except FetchError as e:
            problem = f"download failed: {str(e).splitlines()[0]}"
        if problem is None:
            _restore_bundle_files(bundle_dir / BUNDLE_FILES, ws)
            build_error = ecosystem.build(ws)
            if build_error:
                problem = f"the harnesses no longer build in a fresh workspace:\n{build_error}"

        for h in chosen:
            out = out_root / c.slug / h["name"]
            shutil.rmtree(out, ignore_errors=True)
            out.mkdir(parents=True)
            entry = {"slug": c.slug, "component": c.to_dict(), "harness": h, "created": _now()}
            start = time.monotonic()
            error = problem
            if error is None:
                ok, text = ecosystem.validate(ws, h["target"], [ws.root / s for s in h["seeds"]])
                if not ok:
                    error = f"the harness fails on its seeds in a fresh workspace:\n{text}"
            if error:
                log.warning("%s: %s: %s", c.display_name, h["name"], error.splitlines()[0])
                entry["result"] = {"name": h["name"], "target": h["target"], "status": "error", "error": error,
                                   "fuzz_seconds": 0.0, "runs": 0, "executions": 0, "last_stats": "", "crashes": []}
            else:
                log.info("%s: fuzzing %s for %ss", c.display_name, h["name"], seconds)
                before = set(os.listdir(ws.crashes))
                result = run_campaign(ws, ecosystem, h["name"], h["target"], seconds, stop_after_duplicates)
                for name in sorted(set(os.listdir(ws.crashes)) - before):
                    (out / "crashes").mkdir(exist_ok=True)
                    shutil.copy2(ws.crashes / name, out / "crashes" / name)
                entry["result"] = result.to_dict()
                log.info("%s: %s: %s, %d unique crash(es)", c.display_name, h["name"], result.status,
                         len(result.crashes))
            entry["duration_seconds"] = round(time.monotonic() - start, 1)
            write_json(out / RESULT_FILE, entry)
            results.append(entry)
        return results
    finally:
        if not keep_workdir:
            shutil.rmtree(ws.root, ignore_errors=True)


def _restore_bundle_files(src: Path, ws: Workspace) -> None:
    if not src.is_dir():
        return
    for path in src.rglob("*"):
        if path.is_file():
            target = ws.resolve(path.relative_to(src).as_posix())
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    sandbox.give_to_sandbox(ws.root)


# --- report ------------------------------------------------------------------------------

def report(plan_data: dict, bundles_root: Path, fuzz_root: Path | None, out: Path) -> list[ComponentResult]:
    """Combine the stages' files into report.md and report.json; returns the per-component results."""
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    results: list[ComponentResult] = []
    total = Usage()
    models, efforts, seconds = set(), set(), set()

    for entry in plan_data["components"]:
        slug = entry["slug"]
        bundle_path = bundles_root / slug / BUNDLE_FILE
        if not bundle_path.is_file():
            results.append(ComponentResult(entry["component"], "missing", "no generate result for this component"))
            continue
        bundle = read_json(bundle_path)
        usage = Usage(**bundle["usage"])
        total.add(usage)
        models.add(bundle.get("model", "default"))
        efforts.add(bundle.get("effort", ""))
        r = ComponentResult(bundle["component"], bundle["status"], bundle.get("detail", ""),
                            attempts=bundle["attempts"], validation=bundle["validation"], usage=usage,
                            turns=bundle["turns"], duration_seconds=bundle.get("duration_seconds", 0.0),
                            artifacts=_rel(bundles_root / slug, out))
        if bundle["status"] == "ready":
            fuzzed = 0
            for h in bundle["harnesses"]:
                result_path = (fuzz_root / slug / h["name"] / RESULT_FILE) if fuzz_root else None
                if result_path and result_path.is_file():
                    fuzz_entry = read_json(result_path)
                    seconds.add(round(fuzz_entry["result"].get("fuzz_seconds", 0)))
                    r.duration_seconds += fuzz_entry.get("duration_seconds", 0.0)
                    r.harnesses.append({**h, **fuzz_entry["result"], "artifacts": _rel(result_path.parent, out)})
                    fuzzed += 1
                else:
                    r.harnesses.append({**h, "status": "not_fuzzed", "fuzz_seconds": 0.0, "runs": 0, "executions": 0,
                                        "last_stats": "", "error": "", "crashes": [], "artifacts": ""})
            r.status = "completed" if fuzzed == len(bundle["harnesses"]) else "not_fuzzed"
            if r.status == "not_fuzzed":
                r.detail = f"{fuzzed} of {len(bundle['harnesses'])} harness(es) have fuzz results"
        results.append(r)

    for entry in plan_data["skipped"]:
        results.append(ComponentResult(entry["component"], "skipped", entry["reason"]))

    meta = {
        "tool": "sbomfuzz",
        "sbom": plan_data["sbom"],
        "started": plan_data["created"],
        "finished": _now(),
        "model": ", ".join(sorted(models)) or "-",
        "effort": ", ".join(sorted(e for e in efforts if e)) or "-",
        "fuzz_seconds_per_harness": max(seconds) if seconds else 0,
    }
    report_md.write_json(out / "report.json", meta, results, total)
    (out / "report.md").write_text(report_md.render_markdown(meta, results, total), encoding="utf-8")
    match_owner(out)
    return results


# --- helpers -----------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _rel(path: Path, base: Path) -> str:
    try:
        return os.path.relpath(path.resolve(), base)
    except ValueError:
        return str(path)


def _sessions_root() -> Path:
    # Under the orchestrator's home (/root in the image), which the sandbox user cannot enter.
    root = Path.home() / ".cache" / "sbomfuzz" / "sessions"
    root.mkdir(parents=True, exist_ok=True)
    return root


def match_owner(out: Path) -> None:
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
