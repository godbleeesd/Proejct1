"""Stands in for the `claude` CLI in tests.

Starts the MCP server from --mcp-config exactly as Claude Code would, plays a short scripted
session against it, and prints a result object like `claude -p --output-format json`.
FAKE_CLAUDE_MODE selects the scenario: report (default), no_report, usage_limit, auth_error.
"""

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPORT = {
    "summary": "Fuzzed parse().",
    "harnesses": [{"path": "harnesses/fuzz_x.py", "target_api": "parse", "outcome": "ran_clean", "notes": ""}],
    "findings": [{"title": "IndexError", "verdict": "likely_bug", "severity": "low", "harness": "harnesses/fuzz_x.py",
                  "crash_file": "", "description": "d", "reproduction": "r"}],
    "limitations": "",
}


def result(**kw):
    base = {"type": "result", "subtype": "success", "is_error": False, "num_turns": 4, "result": "Done.",
            "total_cost_usd": 0.25,
            "usage": {"input_tokens": 1000, "output_tokens": 200, "cache_read_input_tokens": 5000,
                      "cache_creation_input_tokens": 300}}
    base.update(kw)
    return base


async def session(server: dict, submit: bool) -> None:
    params = StdioServerParameters(command=server["command"], args=server["args"], env=dict(os.environ))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as s:
            await s.initialize()
            names = sorted(t.name for t in (await s.list_tools()).tools)
            assert names == ["run_command", "run_fuzzer", "submit_report", "write_file"], names
            await s.call_tool("write_file", {"path": "harnesses/fuzz_x.py", "content": "print('hi')\n"})
            out = await s.call_tool("run_command", {"command": "cat harnesses/fuzz_x.py; id -u", "timeout_seconds": 30})
            text = out.content[0].text
            assert "print('hi')" in text, text
            with open(os.environ["FAKE_CLAUDE_LOG"], "w") as f:
                f.write(text)
            if submit:
                out = await s.call_tool("submit_report", REPORT)
                assert out.content[0].text == "Report received.", out.content[0].text


def main() -> None:
    args = sys.argv[1:]
    mode = os.environ.get("FAKE_CLAUDE_MODE", "report")
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

    asyncio.run(session(server, submit=mode == "report"))
    if mode == "no_report":
        print(json.dumps(result(is_error=True, subtype="error_max_turns", result="")))
        sys.exit(1)
    print(json.dumps(result()))


if __name__ == "__main__":
    main()
