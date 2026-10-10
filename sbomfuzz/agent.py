"""API backend: a Claude Messages API agent that writes harnesses, fuzzes and triages one component."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import anthropic

from .prompts import AgentConfig, system_prompt, task_prompt
from .tools import HARNESS_OUTCOMES, SEVERITIES, VERDICTS, ToolBox
from .usage import BudgetTracker, Usage, from_response

log = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# Models that accept `fallbacks: "default"` on the Claude API.
FALLBACK_MODELS = {"claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}


@dataclass
class AgentOutcome:
    # completed | incomplete | refused | api_error | budget_exhausted | usage_limit | error
    status: str
    detail: str = ""
    report: dict | None = None
    usage: Usage = field(default_factory=Usage)
    turns: int = 0
    fuzz_runs: list[dict] = field(default_factory=list)


def _schema(properties: dict, required: list[str] | None = None) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": required if required is not None else list(properties),
        "additionalProperties": False,
    }


TOOLS = [
    {
        "name": "run_command",
        "description": (
            "Run a bash command in the component workspace (the current directory) as an "
            "unprivileged user. Use it to explore files, read sources, build code and reproduce "
            "crashes. Returns the exit code and combined stdout/stderr (long output is truncated "
            "to its beginning and end)."
        ),
        "strict": True,
        "input_schema": _schema({
            "command": {"type": "string", "description": "Bash command line."},
            "timeout_seconds": {
                "type": "integer",
                "description": "Kill the command after this many seconds (max 1800). Use 120 unless building something large.",
            },
        }),
    },
    {
        "name": "write_file",
        "description": (
            "Create or overwrite a text file in the workspace, e.g. a harness or a build script. "
            "Paths are relative to the workspace root."
        ),
        "strict": True,
        "input_schema": _schema({
            "path": {"type": "string", "description": "Relative path, e.g. harnesses/fuzz_parse.py"},
            "content": {"type": "string", "description": "Full file content."},
        }),
    },
    {
        "name": "run_fuzzer",
        "description": (
            "Fuzz one harness with the ecosystem's fuzzer (libFuzzer-compatible). Crash inputs are "
            "saved to crashes/ and the corpus to corpus/<harness name>/, which is kept between runs. "
            "Returns the status (clean, crash or error), the final coverage statistics, any new "
            "crash files and the relevant part of the fuzzer output."
        ),
        "strict": True,
        "input_schema": _schema({
            "target": {"type": "string", "description": "Harness to fuzz; what this is depends on the ecosystem (see the system prompt)."},
            "seconds": {"type": "integer", "description": "How long to fuzz. Short (10-20) for smoke tests."},
        }),
    },
    {
        "name": "submit_report",
        "description": "Submit the final report for this component. Call it exactly once, when you are done.",
        "strict": True,
        "input_schema": _schema({
            "summary": {"type": "string", "description": "What was tested and what was found, in a few sentences."},
            "harnesses": {
                "type": "array",
                "items": _schema({
                    "path": {"type": "string"},
                    "target_api": {"type": "string", "description": "Functions/classes the harness exercises."},
                    "outcome": {"type": "string", "enum": HARNESS_OUTCOMES},
                    "notes": {"type": "string", "description": "Coverage reached, problems, anything notable."},
                }),
            },
            "findings": {
                "type": "array",
                "description": "One entry per distinct crash/issue, including the ones you judged harness issues or expected behaviour.",
                "items": _schema({
                    "title": {"type": "string"},
                    "verdict": {"type": "string", "enum": VERDICTS},
                    "severity": {"type": "string", "enum": SEVERITIES, "description": "Use info for harness_issue and expected_behavior."},
                    "harness": {"type": "string"},
                    "crash_file": {"type": "string", "description": "Path in crashes/, or empty if none."},
                    "description": {"type": "string", "description": "Root cause, affected code and impact."},
                    "reproduction": {"type": "string", "description": "Command(s) that reproduce the issue."},
                }),
            },
            "limitations": {"type": "string", "description": "What was not covered and why."},
        }),
    },
]


class FuzzAgent:
    def __init__(self, client: anthropic.Anthropic, config: AgentConfig, toolbox: ToolBox, system: str, task: str,
                 tracker: BudgetTracker):
        self.client = client
        self.config = config
        self.model = config.model or DEFAULT_MODEL
        self.toolbox = toolbox
        self.system = system
        self.task = task
        self.tracker = tracker

    @classmethod
    def for_component(cls, client, config, ecosystem, component, ws, fetch_detail, tracker, toolbox):
        return cls(client, config, toolbox, system_prompt(config, ecosystem),
                   task_prompt(component, ecosystem, ws, fetch_detail), tracker)

    def run(self) -> AgentOutcome:
        outcome = AgentOutcome(status="incomplete", detail="the agent did not submit a report")
        outcome.fuzz_runs = self.toolbox.fuzz_runs
        messages: list[dict] = [{"role": "user", "content": self.task}]
        final_call = False  # the agent has been told to submit its report now

        for _ in range(self.config.max_turns):
            try:
                response = self._call(messages)
            except anthropic.AuthenticationError:
                raise
            except (anthropic.APIStatusError, anthropic.APIConnectionError) as e:
                outcome.status = "api_error"
                outcome.detail = str(e)
                return outcome

            outcome.turns += 1
            usage = from_response(response.model, response.usage)
            outcome.usage.add(usage)
            self.tracker.add(usage)
            messages.append({"role": "assistant", "content": response.content})
            self._log_assistant(outcome.turns, response)

            if response.stop_reason == "refusal":
                details = getattr(response, "stop_details", None)
                category = getattr(details, "category", None) if details else None
                outcome.status = "refused"
                outcome.detail = f"the model declined to continue (category: {category})"
                return outcome

            tool_uses = [b for b in response.content if b.type == "tool_use"]
            notes: list[str] = []
            results: list[dict] = []

            if response.stop_reason == "max_tokens":
                # Tool inputs may be cut off; ask for the calls again instead of running them.
                results = [self._result(b.id, "Not run: your response hit the output limit before this call "
                                        "was complete. Issue it again; write large files in parts.", True)
                           for b in tool_uses]
                if not tool_uses:
                    notes.append("Your response hit the output limit. Continue where you left off.")
            elif not tool_uses:
                notes.append("Continue the work using the tools. When you are done, call submit_report.")
            else:
                for block in tool_uses:
                    text, is_error = self.toolbox.call(block.name, block.input)
                    results.append(self._result(block.id, text, is_error))
                if self.toolbox.report is not None:
                    outcome.report = self.toolbox.report
                    if outcome.status != "budget_exhausted":
                        outcome.status, outcome.detail = "completed", ""
                    return outcome

            if final_call:
                return outcome  # it was told to report and did not

            remaining = self.config.max_turns - outcome.turns
            if remaining <= 1 or self.tracker.exhausted():
                final_call = True
                if self.tracker.exhausted():
                    outcome.status = "budget_exhausted"
                    outcome.detail = "the run's budget was used up before the agent finished"
                notes.append("Stop here: call submit_report now with the results you have so far.")
            elif remaining <= 5:
                notes.append(f"{remaining} turns left.")

            content = results + [{"type": "text", "text": n} for n in notes]
            messages.append({"role": "user", "content": content})
        return outcome

    def _call(self, messages: list[dict]):
        kwargs: dict = {}
        if self.config.fallbacks and self.model in FALLBACK_MODELS:
            kwargs.update(betas=[FALLBACK_BETA], fallbacks="default")
        with self.client.beta.messages.stream(
            model=self.model,
            max_tokens=64000,
            system=self.system,
            tools=TOOLS,
            messages=messages,
            thinking={"type": "adaptive"},
            output_config={"effort": self.config.effort},
            # Caches the growing conversation; tools and system are identical across
            # components of the same ecosystem, so they are reused too.
            cache_control={"type": "ephemeral"},
            **kwargs,
        ) as stream:
            return stream.get_final_message()

    @staticmethod
    def _result(tool_use_id: str, text: str, is_error: bool = False) -> dict:
        result = {"type": "tool_result", "tool_use_id": tool_use_id, "content": text or "(no output)"}
        if is_error:
            result["is_error"] = True
        return result

    def _log_assistant(self, turn: int, response) -> None:
        for block in response.content:
            if block.type == "text" and block.text.strip():
                self.toolbox.log({"turn": turn, "type": "text", "text": block.text})
            elif block.type == "fallback":
                self.toolbox.log({"turn": turn, "type": "fallback", "model": response.model})
