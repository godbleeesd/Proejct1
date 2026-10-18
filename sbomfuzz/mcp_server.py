"""MCP server exposing the harness-generation tools to Claude Code.

Claude Code runs with its own built-in tools disabled and starts this server over stdio,
so every command goes through sbomfuzz's sandbox (unprivileged user, no secrets). The
outcome (accepted harnesses, validation log) is written to a JSON file that the runner
reads after Claude Code exits.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from .ecosystems import ECOSYSTEMS
from .tools import SEEDS_PER_HARNESS, ToolBox
from .workspace import Workspace


class Seed(BaseModel):
    content: str = Field(description='The input itself; base64-encoded when encoding is "base64".')
    encoding: Literal["text", "base64"] = "text"


class Harness(BaseModel):
    name: str = Field(description="Short identifier: letters, digits, underscores, e.g. parse_document.")
    source: str = Field(description="Harness source file, relative to the workspace, e.g. harnesses/fuzz_parse.py.")
    target: str = Field(description="What the fuzzer runs; see the system prompt for this ecosystem.")
    target_api: str = Field(description="Functions/classes the harness exercises.")
    description: str = Field(description="What the harness does and why this entry point matters.")
    seeds: list[Seed] = Field(description=f"Exactly {SEEDS_PER_HARNESS} valid example inputs.")


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
        if not self.toolbox.done and calls >= self.warn_after_calls:
            text += "\n\nYou are close to your turn limit: call submit_harnesses now with what you have."
        return text

    def save(self) -> None:
        tb = self.toolbox
        data = {
            "calls": self.calls,
            "attempts": tb.attempts,
            "accepted": [h.to_dict() for h in tb.accepted] if tb.accepted is not None else None,
            "validation": tb.validation_log,
            "written": sorted(tb.written),
            "last_valid": [h.to_dict() for h in tb.last_valid],
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)


def build_server(state: SessionState):
    from mcp.server.mcpserver import MCPServer

    toolbox = state.toolbox
    server = MCPServer("sbomfuzz", instructions="Tools for writing fuzzing harnesses for one SBOM component.")

    @server.tool()
    def run_command(command: str, timeout_seconds: int = 120) -> str:
        """Run a bash command in the component workspace (the current directory) as an unprivileged
        user. Use it to explore files, read sources and check that code builds. Returns the exit
        code and combined stdout/stderr (long output is truncated to its beginning and end).
        timeout_seconds: kill the command after this many seconds (max 1800)."""
        return state.finish(*toolbox.call("run_command", {"command": command, "timeout_seconds": timeout_seconds}))

    @server.tool()
    def write_file(path: str, content: str) -> str:
        """Create or overwrite a text file in the workspace, e.g. a harness or a build script.
        path is relative to the workspace root, e.g. harnesses/fuzz_parse.py."""
        return state.finish(*toolbox.call("write_file", {"path": path, "content": content}))

    @server.tool()
    def submit_harnesses(harnesses: list[Harness]) -> str:
        """Hand in the complete set of harnesses, each with exactly 3 seed inputs. The program builds
        them and runs each harness on its seeds, and reports what failed. Resubmit the complete set
        after fixing failures; the number of attempts is limited."""
        payload = [h.model_dump() for h in harnesses]
        return state.finish(*toolbox.call("submit_harnesses", {"harnesses": payload}))

    return server


def serve(config_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    toolbox = ToolBox(
        Workspace(Path(config["workspace"])),
        ECOSYSTEMS[config["ecosystem"]],
        max_harnesses=config["max_harnesses"],
        max_attempts=config["max_attempts"],
        command_timeout=config["command_timeout"],
        transcript=Path(config["transcript"]),
        label=config.get("label", ""),
    )
    state = SessionState(toolbox, Path(config["state"]), config["warn_after_calls"])
    build_server(state).run(transport="stdio")
