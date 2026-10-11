"""Harness generation with Claude Code (`claude -p`) on a Claude subscription.

Authenticates with CLAUDE_CODE_OAUTH_TOKEN, the long-lived token `claude setup-token` creates
for a Claude Pro/Max/Team/Enterprise subscription. Claude Code's own tools are disabled; the
model can only use sbomfuzz's MCP tools, which run everything in the sandbox.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .ecosystems import Ecosystem
from .prompts import AgentConfig, system_prompt, task_prompt
from .sbom import Component
from .usage import Usage
from .workspace import Workspace

log = logging.getLogger(__name__)

# The CLI command; CLAUDE_BIN may include arguments (tests point it at a fake).
CLAUDE_CMD = shlex.split(os.environ.get("CLAUDE_BIN", "claude"))
SERVER_NAME = "sbomfuzz"

_USAGE_LIMIT = re.compile(r"usage limit|rate limit|limit reached|limit will reset|out of extra usage|hit your limit", re.I)
_AUTH_ERROR = re.compile(r"not logged in|invalid api key|authentication|oauth token|please run /login|unauthorized", re.I)


class ClaudeCodeAuthError(RuntimeError):
    pass


@dataclass
class GenerationOutcome:
    # done (harnesses accepted, possibly none) | incomplete | usage_limit | error
    status: str
    detail: str = ""
    harnesses: list[dict] = field(default_factory=list)
    attempts: int = 0
    validation: list[dict] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    turns: int = 0


class HarnessGenerator:
    def __init__(self, config: AgentConfig, ecosystem: Ecosystem, component: Component, ws: Workspace,
                 fetch_detail: str, transcript: Path, session_dir: Path):
        self.config = config
        self.ecosystem = ecosystem
        self.component = component
        self.ws = ws
        self.fetch_detail = fetch_detail
        self.transcript = transcript
        # Holds prompts, MCP config and state; root-only and outside any sandbox-writable
        # directory, so code running in the sandbox cannot tamper with them.
        self.session_dir = session_dir

    def command(self) -> list[str]:
        d = self.session_dir
        cmd = [
            *CLAUDE_CMD, "-p", task_prompt(self.component, self.ecosystem, self.ws, self.fetch_detail),
            "--output-format", "json",
            "--system-prompt-file", str(d / "system.txt"),
            "--mcp-config", str(d / "mcp.json"),
            "--strict-mcp-config",
            # Never read project settings (hooks!) or CLAUDE.md that sandboxed code could plant.
            "--setting-sources", "user",
            "--tools", "",  # no built-in tools: only the sandboxed MCP tools
            "--allowedTools", f"mcp__{SERVER_NAME}",
            "--permission-prompts", "none",
            "--max-turns", str(self.config.max_turns),
            "--effort", self.config.effort,
            "--no-session-persistence",
        ]
        if self.config.model:
            cmd += ["--model", self.config.model]
        return cmd

    def prepare(self) -> None:
        d = self.session_dir
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        (d / "system.txt").write_text(system_prompt(self.config, self.ecosystem), encoding="utf-8")
        server_config = {
            "workspace": str(self.ws.root),
            "ecosystem": self.ecosystem.key,
            "max_harnesses": self.config.max_harnesses,
            "max_attempts": self.config.max_attempts,
            "command_timeout": self.config.command_timeout,
            # The server runs in the session directory, so relative paths would break.
            "transcript": str(self.transcript.resolve()),
            "state": str(d / "state.json"),
            "warn_after_calls": max(1, self.config.max_turns - 3),
            "label": self.component.display_name,
        }
        (d / "server.json").write_text(json.dumps(server_config), encoding="utf-8")
        mcp = {"mcpServers": {SERVER_NAME: {
            "type": "stdio",
            "command": sys.executable,
            # -I: isolated mode, so modules in the working directory are never imported.
            "args": ["-I", "-m", "sbomfuzz", "mcp-server", str(d / "server.json")],
        }}}
        (d / "mcp.json").write_text(json.dumps(mcp), encoding="utf-8")

    def env(self) -> dict[str, str]:
        env = dict(os.environ)
        # An API key outranks the OAuth token in Claude Code; drop it so the subscription is used.
        env.pop("ANTHROPIC_API_KEY", None)
        env.pop("ANTHROPIC_AUTH_TOKEN", None)
        # Validation builds and runs harnesses (a native build can take a while).
        env["MCP_TOOL_TIMEOUT"] = str((self.config.command_timeout + 900) * 1000)
        env.setdefault("MCP_TIMEOUT", "60000")
        env.setdefault("DISABLE_AUTOUPDATER", "1")
        return env

    def run(self) -> GenerationOutcome:
        self.prepare()
        outcome = GenerationOutcome(status="incomplete", detail="the model did not submit harnesses")
        overall = self.config.max_turns * 600 + 1800
        try:
            # cwd is the private session directory, never the sandbox-writable workspace:
            # Claude Code loads configuration and CLAUDE.md from its working directory.
            proc = subprocess.run(self.command(), cwd=self.session_dir, env=self.env(), stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=overall)
        except FileNotFoundError:
            raise ClaudeCodeAuthError(f"Claude Code CLI not found ({CLAUDE_CMD[0]}); use the Docker image") from None
        except subprocess.TimeoutExpired:
            outcome.status, outcome.detail = "error", f"Claude Code did not finish within {overall}s"
            self._load_state(outcome)
            return outcome

        result = parse_result(proc.stdout)
        self._load_state(outcome)
        self._record_usage(outcome, result)
        text = str(result.get("result") or "")
        if text:
            with self.transcript.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"type": "text", "text": text[:4000]}, ensure_ascii=False) + "\n")

        if outcome.status == "done":
            return outcome

        problem = text or proc.stderr.strip() or f"claude exited with code {proc.returncode}"
        if result.get("is_error") or proc.returncode != 0:
            if _AUTH_ERROR.search(problem) and outcome.turns == 0:
                raise ClaudeCodeAuthError(problem.splitlines()[0][:300])
            if _USAGE_LIMIT.search(problem):
                outcome.status, outcome.detail = "usage_limit", problem.splitlines()[0][:300]
            elif result.get("subtype") == "error_max_turns":
                outcome.detail = f"turn limit ({self.config.max_turns}) reached before the harnesses were accepted"
            else:
                outcome.status, outcome.detail = "error", problem[:500]
        elif text:
            # The model ended without submitting, e.g. because the component is not native code.
            outcome.detail = text.strip().splitlines()[0][:300]
        return outcome

    def _load_state(self, outcome: GenerationOutcome) -> None:
        try:
            state = json.loads((self.session_dir / "state.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        outcome.attempts = state.get("attempts") or 0
        outcome.validation = state.get("validation") or []
        if state.get("accepted") is not None:
            outcome.status, outcome.detail = "done", ""
            outcome.harnesses = state["accepted"]

    def _record_usage(self, outcome: GenerationOutcome, result: dict) -> None:
        outcome.turns = int(result.get("num_turns") or 0)
        u = result.get("usage") or {}
        outcome.usage = Usage(
            input_tokens=int(u.get("input_tokens") or 0),
            output_tokens=int(u.get("output_tokens") or 0),
            cache_read_tokens=int(u.get("cache_read_input_tokens") or 0),
            cache_write_tokens=int(u.get("cache_creation_input_tokens") or 0),
            # Claude Code's API-equivalent estimate; a subscription is not billed per token.
            cost_usd=float(result["total_cost_usd"]) if result.get("total_cost_usd") is not None else None,
        )


def parse_result(stdout: str) -> dict:
    """The final JSON object printed by `claude -p --output-format json`."""
    stdout = stdout.strip()
    if not stdout:
        return {}
    try:
        data = json.loads(stdout)
    except ValueError:
        # Tolerate log lines before the JSON: take the last line that parses.
        for line in reversed(stdout.splitlines()):
            try:
                data = json.loads(line)
                break
            except ValueError:
                continue
        else:
            return {"result": stdout[-2000:], "is_error": True}
    if isinstance(data, list):  # some versions print the whole message list
        data = next((m for m in reversed(data) if isinstance(m, dict) and m.get("type") == "result"), {})
    return data if isinstance(data, dict) else {}
