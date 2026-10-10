import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from sbomfuzz import claude_code
from sbomfuzz.claude_code import ClaudeCodeAgent, ClaudeCodeAuthError, parse_result
from sbomfuzz.cli import resolve_backend
from sbomfuzz.ecosystems import ECOSYSTEMS
from sbomfuzz.prompts import AgentConfig
from sbomfuzz.sandbox import child_env
from sbomfuzz.sbom import Component
from sbomfuzz.usage import BudgetTracker

FAKE = Path(__file__).parent / "fake_claude.py"
COMPONENT = Component(name="toml", version="0.10.2", group=None, purl="pkg:pypi/toml@0.10.2", purl_type="pypi",
                      ecosystem="python", download_url=None, vcs_url=None, bom_ref=None, qualifiers={})


@pytest.fixture
def session_dir():
    d = Path(tempfile.mkdtemp(prefix="sbomfuzz-session-"))
    yield d / "s"
    shutil.rmtree(d, ignore_errors=True)


def make_agent(ws, session_dir, **config):
    tracker = BudgetTracker(None)
    agent = ClaudeCodeAgent(AgentConfig(**config), ECOSYSTEMS["python"], COMPONENT, ws, "installed", tracker,
                            ws.root.parent / "transcript.jsonl", session_dir)
    return agent, tracker


def test_command_locks_claude_code_down(ws, session_dir):
    agent, _ = make_agent(ws, session_dir, max_turns=40, model="claude-sonnet-5-5")
    cmd = agent.command()

    def value(flag):
        return cmd[cmd.index(flag) + 1]

    assert value("--tools") == ""
    assert value("--allowedTools") == "mcp__sbomfuzz"
    assert value("--setting-sources") == "user"
    assert value("--permission-prompts") == "none"
    assert value("--max-turns") == "40"
    assert value("--model") == "claude-sonnet-5-5"
    assert "--strict-mcp-config" in cmd
    assert "toml@0.10.2" in value("-p")


def test_subscription_token_wins_over_api_key(ws, session_dir, monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "key")
    agent, _ = make_agent(ws, session_dir)
    env = agent.env()
    assert env["CLAUDE_CODE_OAUTH_TOKEN"] == "oauth"
    assert "ANTHROPIC_API_KEY" not in env


def test_sandboxed_commands_never_see_tokens(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "key")
    env = child_env()
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in env and "ANTHROPIC_API_KEY" not in env


def test_backend_resolution():
    assert resolve_backend("auto", {"CLAUDE_CODE_OAUTH_TOKEN": "t", "ANTHROPIC_API_KEY": "k"}) == "subscription"
    assert resolve_backend("auto", {"ANTHROPIC_API_KEY": "k"}) == "api"
    assert resolve_backend("auto", {}) is None
    assert resolve_backend("api", {}) == "api"


def test_parse_result_variants():
    assert parse_result('{"type": "result", "num_turns": 3}')["num_turns"] == 3
    assert parse_result('warning: something\n{"type": "result", "num_turns": 2}')["num_turns"] == 2
    assert parse_result('[{"type": "system"}, {"type": "result", "num_turns": 5}]')["num_turns"] == 5
    assert parse_result("") == {}
    assert parse_result("garbage")["is_error"] is True


# The scenarios below run tests/fake_claude.py, which starts the real MCP server.

@pytest.fixture
def fake_claude(monkeypatch, tmp_path):
    pytest.importorskip("mcp")
    monkeypatch.setattr(claude_code, "CLAUDE_CMD", [sys.executable, str(FAKE)])
    log = tmp_path / "fake.log"
    monkeypatch.setenv("FAKE_CLAUDE_LOG", str(log))
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-secret")
    return log


def test_full_session_through_mcp(ws, session_dir, fake_claude, monkeypatch):
    agent, tracker = make_agent(ws, session_dir)
    outcome = agent.run()

    assert outcome.status == "completed", outcome.detail
    assert outcome.report["findings"][0]["verdict"] == "likely_bug"
    assert outcome.turns == 4
    assert outcome.usage.cost_usd == 0.25 and tracker.total.cache_read_tokens == 5000
    assert (ws.harnesses / "fuzz_x.py").read_text() == "print('hi')\n"
    command_output = fake_claude.read_text()
    if os.geteuid() == 0:
        assert command_output.strip().splitlines()[-1] != "0"  # ran as the sandbox user
    transcript = (ws.root.parent / "transcript.jsonl").read_text()
    assert '"tool": "write_file"' in transcript and '"tool": "submit_report"' in transcript


def test_missing_report(ws, session_dir, fake_claude, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "no_report")
    outcome = make_agent(ws, session_dir, max_turns=7)[0].run()
    assert outcome.status == "incomplete"
    assert "turn limit (7)" in outcome.detail


def test_usage_limit(ws, session_dir, fake_claude, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "usage_limit")
    outcome = make_agent(ws, session_dir)[0].run()
    assert outcome.status == "usage_limit"


def test_auth_error_is_fatal(ws, session_dir, fake_claude, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "auth_error")
    with pytest.raises(ClaudeCodeAuthError):
        make_agent(ws, session_dir)[0].run()
