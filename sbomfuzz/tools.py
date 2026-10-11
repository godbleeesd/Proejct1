"""The agent's tools, shared by the API backend and the Claude Code (MCP) backend."""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path

from . import sandbox
from .ecosystems import Ecosystem
from .workspace import Workspace

log = logging.getLogger(__name__)

MAX_WRITE_BYTES = 1024 * 1024
VERDICTS = ["confirmed_bug", "likely_bug", "harness_issue", "expected_behavior"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]
HARNESS_OUTCOMES = ["ran_clean", "found_crashes", "could_not_run"]


class ToolBox:
    """Executes tool calls inside one component's workspace and records what happened.

    Each method returns (text for the model, is_error). Thread-safe: the MCP server
    may run calls concurrently.
    """

    def __init__(self, ws: Workspace, ecosystem: Ecosystem, fuzz_seconds: int, command_timeout: int,
                 transcript: Path | None = None, label: str = ""):
        self.ws = ws
        self.ecosystem = ecosystem
        self.fuzz_seconds = fuzz_seconds
        self.command_timeout = command_timeout
        self.transcript = transcript
        self.label = label
        self.fuzz_runs: list[dict] = []
        self.report: dict | None = None
        self._lock = threading.Lock()

    def run_command(self, command: str, timeout_seconds: int) -> tuple[str, bool]:
        timeout = max(1, min(int(timeout_seconds), self.command_timeout))
        result = sandbox.run(command, cwd=self.ws.root, timeout=timeout, env=self.ecosystem.command_env(self.ws))
        status = f"timed out after {timeout}s" if result.timed_out else f"exit code {result.returncode}"
        return f"{status}\n{result.output}", False

    def write_file(self, path: str, content: str) -> tuple[str, bool]:
        if len(content.encode()) > MAX_WRITE_BYTES:
            return f"file too large (limit {MAX_WRITE_BYTES} bytes)", True
        target = self.ws.resolve(path)
        first_new = next((p for p in reversed(target.parents) if not p.exists()), None)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        sandbox.give_to_sandbox(first_new or target)
        return f"wrote {len(content)} characters to {self.ws.relative(target)}", False

    def run_fuzzer(self, target: str, seconds: int) -> tuple[str, bool]:
        seconds = max(5, min(int(seconds), self.fuzz_seconds))
        log.info("  %s: fuzzing %s for %ss", self.label, target, seconds)
        run = self.ecosystem.fuzz(self.ws, target, seconds)
        with self._lock:
            self.fuzz_runs.append({"target": target, "seconds": seconds, "status": run.status,
                                   "stats": run.stats, "crash_files": run.crash_files})
        return run.to_text(), run.status == "error"

    def submit_report(self, report: dict) -> tuple[str, bool]:
        problems = validate_report(report)
        if problems:
            return "Report rejected: " + "; ".join(problems), True
        with self._lock:
            self.report = report
        return "Report received.", False

    def call(self, name: str, args: dict) -> tuple[str, bool]:
        """Dispatch a tool call by name, turning exceptions into error results."""
        self.log({"type": "tool_call", "tool": name, "input": _loggable(name, args)})
        try:
            if name == "run_command":
                text, is_error = self.run_command(args["command"], args["timeout_seconds"])
            elif name == "write_file":
                text, is_error = self.write_file(args["path"], args["content"])
            elif name == "run_fuzzer":
                text, is_error = self.run_fuzzer(args["target"], args["seconds"])
            elif name == "submit_report":
                text, is_error = self.submit_report(args)
            else:
                text, is_error = f"unknown tool {name}", True
        except Exception as e:  # report tool failures to the agent instead of aborting the component
            log.debug("tool %s failed", name, exc_info=True)
            text, is_error = f"{type(e).__name__}: {e}", True
        self.log({"type": "tool_result", "tool": name, "is_error": is_error, "result": sandbox.truncate(text, 4000)})
        return text or "(no output)", is_error

    def log(self, entry: dict) -> None:
        if self.transcript is None:
            return
        entry["time"] = round(time.time(), 1)
        try:
            with self._lock, self.transcript.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        except OSError:
            # A broken transcript must never break the tool call itself.
            log.warning("cannot write transcript %s", self.transcript, exc_info=True)


def validate_report(report: dict) -> list[str]:
    """Checks the report's shape; the API backend's strict schema already guarantees it."""
    problems = []
    for key, kind in (("summary", str), ("harnesses", list), ("findings", list), ("limitations", str)):
        if not isinstance(report.get(key), kind):
            problems.append(f"{key} must be a {kind.__name__}")
    for f in report.get("findings") or []:
        if not isinstance(f, dict):
            problems.append("each finding must be an object")
            continue
        if f.get("verdict") not in VERDICTS:
            problems.append(f"verdict must be one of {VERDICTS}")
        if f.get("severity") not in SEVERITIES:
            problems.append(f"severity must be one of {SEVERITIES}")
    return problems


def _loggable(name: str, args: dict) -> dict:
    args = dict(args)
    if name == "write_file":
        args["content"] = sandbox.truncate(str(args.get("content", "")), 2000)
    return args
