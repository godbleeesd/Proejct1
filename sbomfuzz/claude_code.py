"""Subscription backend: drives the Claude Code CLI (`claude -p`) with the fuzzing tools served over MCP.

Authenticates with CLAUDE_CODE_OAUTH_TOKEN, the long-lived token `claude setup-token` creates
for a Claude Pro/Max/Team/Enterprise subscription. Claude Code's own tools are disabled; the
agent can only use sbomfuzz's MCP tools, which run everything in the sandbox.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

from .agent import AgentOutcome
from .ecosystems import Ecosystem
from .prompts import AgentConfig, system_prompt, task_prompt
from .sbom import Component
from .usage import BudgetTracker, Usage
from .workspace import Workspace

log = logging.getLogger(__name__)

# The CLI command; CLAUDE_BIN may include arguments (tests point it at a fake).
CLAUDE_CMD = shlex.split(os.environ.get("CLAUDE_BIN", "claude"))
SERVER_NAME = "sbomfuzz"

_USAGE_LIMIT = re.compile(r"usage limit|rate limit|limit reached|limit will reset|out of extra usage|hit your limit", re.I)
_AUTH_ERROR = re.compile(r"not logged in|invalid api key|authentication|oauth token|please run /login|unauthorized", re.I)


class ClaudeCodeAuthError(RuntimeError):
    pass


class ClaudeCodeAgent:
    def __init__(self, config: AgentConfig, ecosystem: Ecosystem, component: Component, ws: Workspace,
                 fetch_detail: str, tracker: BudgetTracker, transcript: Path, session_dir: Path):
        self.config = config
        self.ecosystem = ecosystem
        self.component = component
        self.ws = ws
        self.fetch_detail = fetch_detail
        self.tracker = tracker
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
            "fuzz_seconds": self.config.fuzz_seconds,
            "command_timeout": self.config.command_timeout,
            "transcript": str(self.transcript),
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
        if env.get("CLAUDE_CODE_OAUTH_TOKEN"):
            # An API key outranks the OAuth token in Claude Code; drop it so the subscription is used.
            env.pop("ANTHROPIC_API_KEY", None)
            env.pop("ANTHROPIC_AUTH_TOKEN", None)
        tool_timeout = max(self.config.command_timeout, self.config.fuzz_seconds + 300) + 120
        env["MCP_TOOL_TIMEOUT"] = str(tool_timeout * 1000)
        env.setdefault("MCP_TIMEOUT", "60000")
        env.setdefault("DISABLE_AUTOUPDATER", "1")
        return env

    def run(self) -> AgentOutcome:
        self.prepare()
        outcome = AgentOutcome(status="incomplete", detail="the agent did not submit a report")
        overall = self.config.max_turns * (self.config.fuzz_seconds + 180) + 1800
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
        if result.get("result"):
            outcome_log = {"type": "text", "text": text[:4000]}
            with self.transcript.open("a", encoding="utf-8") as f:
                f.write(json.dumps(outcome_log, ensure_ascii=False) + "\n")

        if outcome.report is not None:
            outcome.status, outcome.detail = "completed", ""
            return outcome

        problem = text or proc.stderr.strip() or f"claude exited with code {proc.returncode}"
        if result.get("is_error") or proc.returncode != 0:
            if _AUTH_ERROR.search(problem) and outcome.turns == 0:
                raise ClaudeCodeAuthError(problem.splitlines()[0][:300])
            if _USAGE_LIMIT.search(problem):
                outcome.status, outcome.detail = "usage_limit", problem.splitlines()[0][:300]
            elif result.get("subtype") == "error_max_turns":
                outcome.detail = f"turn limit ({self.config.max_turns}) reached without a report"
            else:
                outcome.status, outcome.detail = "error", problem[:500]
        return outcome

    def _load_state(self, outcome: AgentOutcome) -> None:
        try:
            state = json.loads((self.session_dir / "state.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        outcome.report = state.get("report")
        outcome.fuzz_runs = state.get("fuzz_runs") or []

    def _record_usage(self, outcome: AgentOutcome, result: dict) -> None:
        outcome.turns = int(result.get("num_turns") or 0)
        u = result.get("usage") or {}
        usage = Usage(
            input_tokens=int(u.get("input_tokens") or 0),
            output_tokens=int(u.get("output_tokens") or 0),
            cache_read_tokens=int(u.get("cache_read_input_tokens") or 0),
            cache_write_tokens=int(u.get("cache_creation_input_tokens") or 0),
            # Claude Code's API-equivalent estimate; a subscription is not billed per token.
            cost_usd=float(result["total_cost_usd"]) if result.get("total_cost_usd") is not None else None,
        )
        outcome.usage = usage
        self.tracker.add(usage)


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
