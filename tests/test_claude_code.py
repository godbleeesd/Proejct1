import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from sbomfuzz import claude_code
from sbomfuzz.claude_code import ClaudeCodeAuthError, HarnessGenerator, parse_result
from sbomfuzz.ecosystems import ECOSYSTEMS
from sbomfuzz.prompts import AgentConfig
from sbomfuzz.sandbox import child_env
from sbomfuzz.sbom import Component

FAKE = Path(__file__).parent / "fake_claude.py"
COMPONENT = Component(name="demo", version="1.0", group=None, purl="pkg:pypi/demo@1.0", purl_type="pypi",
                      ecosystem="python", download_url=None, vcs_url=None, bom_ref=None, qualifiers={})


@pytest.fixture
def session_dir():
    d = Path(tempfile.mkdtemp(prefix="sbomfuzz-session-"))
    yield d / "s"
    shutil.rmtree(d, ignore_errors=True)


def make_generator(ws, session_dir, transcript=None, **config):
    return HarnessGenerator(AgentConfig(**config), ECOSYSTEMS["python"], COMPONENT, ws, "installed",
                            transcript or ws.root.parent / "transcript.jsonl", session_dir)


def test_command_locks_claude_code_down(ws, session_dir):
    cmd = make_generator(ws, session_dir, max_turns=30, model="claude-sonnet-5-5").command()

    def value(flag):
        return cmd[cmd.index(flag) + 1]

    assert value("--tools") == ""
    assert value("--allowedTools") == "mcp__sbomfuzz"
    assert value("--setting-sources") == "user"
    assert value("--permission-prompts") == "none"
    assert value("--max-turns") == "30"
    assert value("--model") == "claude-sonnet-5-5"
    assert "--strict-mcp-config" in cmd
    assert "demo@1.0" in value("-p")
    assert value("--max-budget-usd") == "0.50"  # default cap per session
    assert "--max-budget-usd" not in make_generator(ws, session_dir, max_budget_usd=None).command()


def test_subscription_token_wins_over_api_key(ws, session_dir, monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "key")
    env = make_generator(ws, session_dir).env()
    assert env["CLAUDE_CODE_OAUTH_TOKEN"] == "oauth"
    assert "ANTHROPIC_API_KEY" not in env


def test_sandboxed_commands_never_see_tokens(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "key")
    env = child_env()
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in env and "ANTHROPIC_API_KEY" not in env


def test_parse_result_variants():
    assert parse_result('{"type": "result", "num_turns": 3}')["num_turns"] == 3
    assert parse_result('warning: something\n{"type": "result", "num_turns": 2}')["num_turns"] == 2
    assert parse_result('[{"type": "system"}, {"type": "result", "num_turns": 5}]')["num_turns"] == 5
    assert parse_result("") == {}
    assert parse_result("garbage")["is_error"] is True


# The scenarios below run tests/fake_claude.py, which starts the real MCP server and
# validates real Atheris harnesses, so they need the Docker image's toolchain.

@pytest.fixture
def fake_claude(monkeypatch, tmp_path):
    pytest.importorskip("mcp")
    pytest.importorskip("atheris")
    monkeypatch.setattr(claude_code, "CLAUDE_CMD", [sys.executable, str(FAKE)])
    log = tmp_path / "fake.log"
    monkeypatch.setenv("FAKE_CLAUDE_LOG", str(log))
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-secret")
    return log


def test_generation_with_one_fix(ws, session_dir, fake_claude):
    outcome = make_generator(ws, session_dir).run()

    assert outcome.status == "done", outcome.detail
    assert [h["name"] for h in outcome.harnesses] == ["demo"]
    assert outcome.harnesses[0]["seeds"] == ["corpus/demo/seed-1", "corpus/demo/seed-2", "corpus/demo/seed-3"]
    assert (ws.corpus / "demo" / "seed-3").read_bytes() == b"\x00\x01\x02"
    assert outcome.attempts == 2  # broken, then fixed; the malformed submission did not count
    assert [h["ok"] for v in outcome.validation for h in v["harnesses"]] == [False, True]
    assert outcome.turns == 5 and outcome.usage.cost_usd == 0.25
    if os.geteuid() == 0:
        assert fake_claude.read_text().splitlines()[-1] != "0"  # commands ran as the sandbox user
    log = [json.loads(line) for line in (ws.root.parent / "transcript.jsonl").read_text().splitlines()]
    assert sum(e.get("tool") == "submit_harnesses" and e["type"] == "tool_call" for e in log) == 3


def test_attempts_run_out(ws, session_dir, fake_claude, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "always_broken")
    outcome = make_generator(ws, session_dir, max_attempts=3).run()
    assert outcome.status == "done"
    assert outcome.harnesses == []
    assert outcome.attempts == 3


def test_relative_transcript_path(ws, session_dir, fake_claude, monkeypatch):
    # `run --out results` gives a relative path, while the MCP server runs in the session
    # directory; this broke every tool call in the first real run.
    monkeypatch.chdir(ws.root.parent)
    outcome = make_generator(ws, session_dir, transcript=Path("transcript.jsonl")).run()
    assert outcome.status == "done", outcome.detail
    assert '"tool": "write_file"' in (ws.root.parent / "transcript.jsonl").read_text()


def test_budget_stop_keeps_the_harnesses_that_passed(ws, session_dir, fake_claude, monkeypatch):
    # The session budget ran out after a validation round in which one of two harnesses passed:
    # the passing one is fuzzed instead of the whole component being lost.
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "budget_stop")
    outcome = make_generator(ws, session_dir, max_budget_usd=0.3).run()
    assert outcome.status == "done", outcome.detail
    assert [h["name"] for h in outcome.harnesses] == ["demo"]
    assert "session budget ($0.30) reached" in outcome.detail
    assert "kept 1 harness(es) that had passed validation" in outcome.detail


def test_no_submission(ws, session_dir, fake_claude, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "no_submit")
    outcome = make_generator(ws, session_dir).run()
    assert outcome.status == "incomplete"
    assert "not native code" in outcome.detail


def test_usage_limit(ws, session_dir, fake_claude, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "usage_limit")
    assert make_generator(ws, session_dir).run().status == "usage_limit"


def test_auth_error_is_fatal(ws, session_dir, fake_claude, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "auth_error")
    with pytest.raises(ClaudeCodeAuthError):
        make_generator(ws, session_dir).run()
