import json
from types import SimpleNamespace

from sbomfuzz.agent import FALLBACK_BETA, AgentConfig, FuzzAgent
from sbomfuzz.ecosystems import ECOSYSTEMS
from sbomfuzz.sbom import Component
from sbomfuzz.usage import BudgetTracker

REPORT = {"summary": "done", "harnesses": [], "findings": [], "limitations": ""}


def tool(name, args, id_="t"):
    return SimpleNamespace(type="tool_use", id=id_, name=name, input=args)


def text(t):
    return SimpleNamespace(type="text", text=t)


def response(*content, stop_reason=None, model="claude-opus-5-5", stop_details=None):
    if stop_reason is None:
        stop_reason = "tool_use" if any(b.type == "tool_use" for b in content) else "end_turn"
    usage = SimpleNamespace(input_tokens=100, output_tokens=50, cache_read_input_tokens=0,
                            cache_creation_input_tokens=0)
    return SimpleNamespace(content=list(content), stop_reason=stop_reason, model=model, usage=usage,
                           stop_details=stop_details)


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self._stream))

    def _stream(self, **kwargs):
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})
        reply = self.responses.pop(0)

        class Stream:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def get_final_message(self):
                return reply

        return Stream()


COMPONENT = Component(name="toml", version="0.10.2", group=None, purl="pkg:pypi/toml@0.10.2", purl_type="pypi",
                      ecosystem="python", download_url=None, vcs_url=None, bom_ref=None, qualifiers={})


def make_agent(ws, responses, budget=None, **config):
    client = FakeClient(responses)
    tracker = BudgetTracker(budget)
    agent = FuzzAgent(client, AgentConfig(**config), ECOSYSTEMS["python"], COMPONENT, ws, "installed", tracker,
                      ws.root / "transcript.jsonl")
    return agent, client, tracker


def test_completes_when_report_is_submitted(ws):
    agent, client, tracker = make_agent(ws, [
        response(text("Writing a harness."), tool("write_file", {"path": "harnesses/fuzz_a.py", "content": "x = 1\n"}, "w1")),
        response(tool("submit_report", REPORT, "r1")),
    ])
    outcome = agent.run()

    assert outcome.status == "completed"
    assert outcome.report == REPORT
    assert outcome.turns == 2
    assert (ws.harnesses / "fuzz_a.py").read_text() == "x = 1\n"
    assert tracker.total.input_tokens == 200

    # The second request carries the tool result for the first call, and the whole
    # assistant turn is passed back unchanged.
    second = client.calls[1]["messages"]
    assert second[1]["content"][1].name == "write_file"
    assert second[2]["content"][0]["tool_use_id"] == "w1"
    assert "wrote 6 characters" in second[2]["content"][0]["content"]

    first = client.calls[0]
    assert first["model"] == "claude-opus-5-5"
    assert first["fallbacks"] == "default" and first["betas"] == [FALLBACK_BETA]
    assert first["thinking"] == {"type": "adaptive"}
    assert "toml@0.10.2" in first["messages"][0]["content"]

    log = [json.loads(line) for line in (ws.root / "transcript.jsonl").read_text().splitlines()]
    assert [e["type"] for e in log] == ["text", "tool_call", "tool_result", "tool_call"]


def test_write_outside_workspace_is_refused(ws):
    agent, client, _ = make_agent(ws, [
        response(tool("write_file", {"path": "../../escape.txt", "content": "x"}, "w1")),
        response(tool("submit_report", REPORT)),
    ])
    agent.run()
    result = client.calls[1]["messages"][2]["content"][0]
    assert result["is_error"] is True
    assert "escapes the workspace" in result["content"]


def test_nudges_when_the_model_stops_without_tools(ws):
    agent, client, _ = make_agent(ws, [response(text("Thinking out loud.")), response(tool("submit_report", REPORT))])
    assert agent.run().status == "completed"
    assert "call submit_report" in client.calls[1]["messages"][2]["content"][0]["text"]


def test_truncated_tool_calls_are_not_executed(ws):
    agent, client, _ = make_agent(ws, [
        response(tool("write_file", {"path": "harnesses/a.py", "content": "partial"}, "w1"), stop_reason="max_tokens"),
        response(tool("submit_report", REPORT)),
    ])
    agent.run()
    assert not (ws.harnesses / "a.py").exists()
    assert client.calls[1]["messages"][2]["content"][0]["is_error"] is True


def test_refusal_stops_the_component(ws):
    agent, _, _ = make_agent(ws, [response(text(""), stop_reason="refusal",
                                           stop_details=SimpleNamespace(category="cyber"))])
    outcome = agent.run()
    assert outcome.status == "refused"
    assert "cyber" in outcome.detail


def test_turn_limit_asks_for_a_report_then_gives_up(ws):
    busy = [response(tool("write_file", {"path": f"harnesses/{i}.py", "content": ""}, f"w{i}")) for i in range(3)]
    agent, client, _ = make_agent(ws, busy, max_turns=3)
    outcome = agent.run()
    assert outcome.status == "incomplete"
    assert outcome.turns == 3
    last_user = client.calls[2]["messages"][-1]["content"]
    assert any(b.get("type") == "text" and "submit_report now" in b["text"] for b in last_user)


def test_budget_exhaustion_requests_a_final_report(ws):
    agent, client, _ = make_agent(ws, [
        response(tool("write_file", {"path": "harnesses/a.py", "content": ""}, "w1")),
        response(tool("submit_report", REPORT)),
    ], budget=0.000001)
    outcome = agent.run()
    assert outcome.status == "budget_exhausted"
    assert outcome.report == REPORT


def test_fallbacks_only_for_supported_models(ws):
    agent, client, _ = make_agent(ws, [response(tool("submit_report", REPORT))], model="claude-haiku-5-5")
    agent.run()
    assert "fallbacks" not in client.calls[0]
