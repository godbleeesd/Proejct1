"""MCP server exposing the fuzzing tools to Claude Code (the subscription backend).

Claude Code runs with its own built-in tools disabled and starts this server over stdio,
so every command still goes through sbomfuzz's sandbox (unprivileged user, no secrets).
State (report, fuzz runs) is written to a JSON file that the runner reads afterwards.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from .ecosystems import ECOSYSTEMS
from .tools import ToolBox
from .workspace import Workspace


class Harness(BaseModel):
    path: str
    target_api: str = Field(description="Functions/classes the harness exercises.")
    outcome: Literal["ran_clean", "found_crashes", "could_not_run"]
    notes: str = Field(description="Coverage reached, problems, anything notable.")


class Finding(BaseModel):
    title: str
    verdict: Literal["confirmed_bug", "likely_bug", "harness_issue", "expected_behavior"]
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        description="Use info for harness_issue and expected_behavior.")
    harness: str
    crash_file: str = Field(description="Path in crashes/, or empty if none.")
    description: str = Field(description="Root cause, affected code and impact.")
    reproduction: str = Field(description="Command(s) that reproduce the issue.")


class SessionState:
    """Tool-call bookkeeping persisted for the runner."""

    def __init__(self, toolbox: ToolBox, path: Path, warn_after_calls: int):
        self.toolbox = toolbox
        self.path = path
        self.warn_after_calls = warn_after_calls
        self.calls = 0
        self._lock = threading.Lock()
        self.save()

    def finish(self, text: str, is_error: bool) -> str:
        with self._lock:
            self.calls += 1
            calls = self.calls
        self.save()
        if is_error:
            text = "ERROR: " + text
        if self.toolbox.report is None and calls >= self.warn_after_calls:
            text += "\n\nYou are close to your turn limit: call submit_report now with the results you have."
        return text

    def save(self) -> None:
        data = {"calls": self.calls, "report": self.toolbox.report, "fuzz_runs": self.toolbox.fuzz_runs}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)


def build_server(state: SessionState):
    from mcp.server.mcpserver import MCPServer

    toolbox = state.toolbox
    server = MCPServer("sbomfuzz", instructions="Tools for fuzz testing one SBOM component in its workspace.")

    @server.tool()
    def run_command(command: str, timeout_seconds: int = 120) -> str:
        """Run a bash command in the component workspace (the current directory) as an unprivileged
        user. Use it to explore files, read sources, build code and reproduce crashes. Returns the
        exit code and combined stdout/stderr (long output is truncated to its beginning and end).
        timeout_seconds: kill the command after this many seconds (max 1800)."""
        return state.finish(*toolbox.call("run_command", {"command": command, "timeout_seconds": timeout_seconds}))

    @server.tool()
    def write_file(path: str, content: str) -> str:
        """Create or overwrite a text file in the workspace, e.g. a harness or a build script.
        path is relative to the workspace root, e.g. harnesses/fuzz_parse.py."""
        return state.finish(*toolbox.call("write_file", {"path": path, "content": content}))

    @server.tool()
    def run_fuzzer(target: str, seconds: int) -> str:
        """Fuzz one harness with the ecosystem's fuzzer (libFuzzer-compatible). target is the harness
        to fuzz (see the system prompt for what that is in this ecosystem); seconds is how long to
        fuzz, short (10-20) for smoke tests. Crash inputs are saved to crashes/ and the corpus to
        corpus/<harness name>/. Returns the status (clean, crash or error), coverage statistics,
        new crash files and the relevant part of the fuzzer output."""
        return state.finish(*toolbox.call("run_fuzzer", {"target": target, "seconds": seconds}))

    @server.tool()
    def submit_report(summary: str, harnesses: list[Harness], findings: list[Finding], limitations: str) -> str:
        """Submit the final report for this component. Call it exactly once, when you are done.
        findings lists every distinct crash or issue, including the ones you judged to be harness
        issues or expected behaviour."""
        report = {
            "summary": summary,
            "harnesses": [h.model_dump() for h in harnesses],
            "findings": [f.model_dump() for f in findings],
            "limitations": limitations,
        }
        return state.finish(*toolbox.call("submit_report", report))

    return server


def serve(config_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    ws = Workspace(Path(config["workspace"]))
    toolbox = ToolBox(
        ws,
        ECOSYSTEMS[config["ecosystem"]],
        fuzz_seconds=config["fuzz_seconds"],
        command_timeout=config["command_timeout"],
        transcript=Path(config["transcript"]),
        label=config.get("label", ""),
    )
    state = SessionState(toolbox, Path(config["state"]), config["warn_after_calls"])
    build_server(state).run(transport="stdio")
