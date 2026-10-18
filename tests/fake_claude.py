"""Stands in for the `claude` CLI in tests.

Starts the MCP server from --mcp-config exactly as Claude Code would, plays a scripted
harness-writing session against it, and prints a result object like
`claude -p --output-format json`. FAKE_CLAUDE_MODE selects the scenario:
  fix (default)  - submit a broken harness, read the validation error, fix it, resubmit
  always_broken  - keep submitting a broken harness until attempts run out
  no_submit      - explore, then stop without submitting
  budget_stop    - one of two harnesses passes, then the session budget runs out
  usage_limit, auth_error - fail like Claude Code does in those cases
"""

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

GOOD = '''\
import sys
import atheris

def TestOneInput(data):
    if data[:1] == b"B":
        raise RuntimeError("planted bug")

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
'''
BROKEN = GOOD.replace("def TestOneInput(data):", "def TestOneInput(data)")  # syntax error

HARNESS = {
    "name": "demo",
    "source": "harnesses/fuzz_demo.py",
    "target": "harnesses/fuzz_demo.py",
    "target_api": "demo",
    "description": "planted bug on inputs starting with B",
    "seeds": [{"content": "a = 1", "encoding": "text"}, {"content": "x", "encoding": "text"},
              {"content": "AAEC", "encoding": "base64"}],
}


def result(**kw):
    base = {"type": "result", "subtype": "success", "is_error": False, "num_turns": 5, "result": "Done.",
            "total_cost_usd": 0.25,
            "usage": {"input_tokens": 1000, "output_tokens": 200, "cache_read_input_tokens": 5000,
                      "cache_creation_input_tokens": 300}}
    base.update(kw)
    return base


async def call(s, name, args):
    out = await s.call_tool(name, args)
    return out.content[0].text


async def session(server: dict, mode: str) -> None:
    params = StdioServerParameters(command=server["command"], args=server["args"], env=dict(os.environ))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as s:
            await s.initialize()
            names = sorted(t.name for t in (await s.list_tools()).tools)
            assert names == ["run_command", "submit_harnesses", "write_file"], names
            text = await call(s, "run_command", {"command": "id -u", "timeout_seconds": 30})
            with open(os.environ["FAKE_CLAUDE_LOG"], "w") as f:
                f.write(text)
            if mode == "no_submit":
                return
            if mode == "budget_stop":
                # One harness passes, the other does not; then the session budget runs out.
                await call(s, "write_file", {"path": HARNESS["source"], "content": GOOD})
                await call(s, "write_file", {"path": "harnesses/fuzz_demo2.py", "content": BROKEN})
                second = {**HARNESS, "name": "demo2", "source": "harnesses/fuzz_demo2.py",
                          "target": "harnesses/fuzz_demo2.py"}
                text = await call(s, "submit_harnesses", {"harnesses": [HARNESS, second]})
                assert "demo: OK" in text and "demo2: FAILED" in text, text
                return

            # Shape errors are rejected without using up an attempt.
            text = await call(s, "submit_harnesses", {"harnesses": [{**HARNESS, "seeds": HARNESS["seeds"][:2]}]})
            assert "not counted as an attempt" in text, text

            await call(s, "write_file", {"path": HARNESS["source"], "content": BROKEN})
            text = await call(s, "submit_harnesses", {"harnesses": [HARNESS]})
            assert "FAILED" in text and "SyntaxError" in text, text
            if mode == "always_broken":
                for _ in range(5):
                    text = await call(s, "submit_harnesses", {"harnesses": [HARNESS]})
                    if "End your turn" in text:
                        break
                assert "No attempts left" in text or "already accepted" in text, text
                return

            await call(s, "write_file", {"path": HARNESS["source"], "content": GOOD})
            text = await call(s, "submit_harnesses", {"harnesses": [HARNESS]})
            assert "accepted for fuzzing" in text, text


def main() -> None:
    args = sys.argv[1:]
    mode = os.environ.get("FAKE_CLAUDE_MODE", "fix")
    with open(args[args.index("--mcp-config") + 1]) as f:
        server = json.load(f)["mcpServers"]["sbomfuzz"]

    if mode == "auth_error":
        print(json.dumps(result(is_error=True, subtype="error_during_execution", num_turns=0,
                                result="Invalid API key · Please run /login")))
        sys.exit(1)
    if mode == "usage_limit":
        print(json.dumps(result(is_error=True, subtype="error_during_execution", num_turns=2,
                                result="Claude AI usage limit reached|1760000000")))
        sys.exit(1)

    asyncio.run(session(server, mode))
    if mode == "budget_stop":
        print(json.dumps(result(is_error=True, subtype="error_max_budget_usd", result="")))
        sys.exit(1)
    if mode == "no_submit":
        print(json.dumps(result(result="This component is not native code; no harnesses written.")))
        return
    print(json.dumps(result()))


if __name__ == "__main__":
    main()
