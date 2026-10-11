"""The model's tools for the harness-generation phase.

The model can explore and write files, and hands in its harnesses with submit_harnesses.
Every submission is validated by the program (build, then run each harness on its seeds);
failures go back to the model to fix, up to a fixed number of attempts. Fuzzing itself
happens later, without the model (see campaign.py).
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from . import sandbox
from .ecosystems import Ecosystem
from .workspace import Workspace

log = logging.getLogger(__name__)

MAX_WRITE_BYTES = 1024 * 1024
MAX_SEED_BYTES = 1024 * 1024
SEEDS_PER_HARNESS = 3
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


@dataclass
class AcceptedHarness:
    name: str
    source: str
    target: str
    target_api: str
    description: str
    seeds: list[str]

    def to_dict(self) -> dict:
        return dict(self.__dict__)


class ToolBox:
    """Executes tool calls inside one component's workspace. Thread-safe."""

    def __init__(self, ws: Workspace, ecosystem: Ecosystem, max_harnesses: int, max_attempts: int,
                 command_timeout: int, transcript: Path | None = None, label: str = ""):
        self.ws = ws
        self.ecosystem = ecosystem
        self.max_harnesses = max_harnesses
        self.max_attempts = max_attempts
        self.command_timeout = command_timeout
        self.transcript = transcript
        self.label = label
        self.attempts = 0
        self.accepted: list[AcceptedHarness] | None = None  # set when generation is over
        self.validation_log: list[dict] = []
        self._lock = threading.Lock()

    @property
    def done(self) -> bool:
        return self.accepted is not None

    def run_command(self, command: str, timeout_seconds: int) -> tuple[str, bool]:
        timeout = max(1, min(int(timeout_seconds), self.command_timeout))
        result = sandbox.run(command, cwd=self.ws.root, timeout=timeout, env=self.ecosystem.command_env(self.ws))
        status = f"timed out after {timeout}s" if result.timed_out else f"exit code {result.returncode}"
        return f"{status}\n{result.output}", False

    def write_file(self, path: str, content: str) -> tuple[str, bool]:
        if len(content.encode()) > MAX_WRITE_BYTES:
            return f"file too large (limit {MAX_WRITE_BYTES} bytes)", True
        target = self.ws.resolve(path)
        first_new = next((p for p in reversed(target.parents) if not p.exists()), None)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        sandbox.give_to_sandbox(first_new or target)
        return f"wrote {len(content)} characters to {self.ws.relative(target)}", False

    def submit_harnesses(self, harnesses: list[dict]) -> tuple[str, bool]:
        if self.done:
            return "The harnesses were already accepted; you are done. End your turn now.", True
        problems = self._check_shape(harnesses)
        if problems:
            # Malformed submissions do not use up an attempt.
            return "Submission rejected (not counted as an attempt):\n- " + "\n- ".join(problems), True

        with self._lock:
            self.attempts += 1
            attempt = self.attempts
        log.info("  %s: validating %d harness(es), attempt %d/%d", self.label, len(harnesses), attempt,
                 self.max_attempts)

        build_error = self.ecosystem.build(self.ws)
        results: list[tuple[dict, bool, str, list[str]]] = []
        for h in harnesses:
            seeds = self._write_seeds(h)
            if build_error:
                ok, text = False, "build failed (see above)"
            else:
                ok, text = self.ecosystem.validate(self.ws, h["target"], [self.ws.root / s for s in seeds])
            results.append((h, ok, text, seeds))

        self.validation_log.append({
            "attempt": attempt,
            "build_error": build_error,
            "harnesses": [{"name": h["name"], "ok": ok, "detail": sandbox.truncate(text, 2000)}
                          for h, ok, text, _ in results],
        })
        valid = [AcceptedHarness(h["name"], h["source"], h["target"], h["target_api"], h["description"], seeds)
                 for h, ok, _, seeds in results if ok]
        all_ok = len(valid) == len(harnesses)
        last_attempt = attempt >= self.max_attempts
        if all_ok or last_attempt:
            with self._lock:
                self.accepted = valid

        lines = [f"Validation, attempt {attempt} of {self.max_attempts}:"]
        if build_error:
            lines.append(build_error)
        for h, ok, text, _ in results:
            lines.append(f"- {h['name']}: {'OK' if ok else 'FAILED'}" + ("" if ok else f"\n{text}"))
        if all_ok:
            lines.append("All harnesses passed and are accepted for fuzzing. You are done: end your turn now.")
        elif last_attempt:
            lines.append(f"No attempts left. {len(valid)} working harness(es) accepted for fuzzing; "
                         "the others are dropped. End your turn now.")
        else:
            lines.append("Fix the failing harnesses (or their seeds) and call submit_harnesses again with the "
                         "complete set. A seed that crashes the harness usually means a harness mistake; if it "
                         "is a genuine bug in the component, replace that seed with valid input - the fuzzer "
                         "will find the bug again.")
        return "\n".join(lines), not all_ok

    def call(self, name: str, args: dict) -> tuple[str, bool]:
        """Dispatch a tool call by name, turning exceptions into error results."""
        self.log({"type": "tool_call", "tool": name, "input": _loggable(name, args)})
        try:
            if name == "run_command":
                text, is_error = self.run_command(args["command"], args["timeout_seconds"])
            elif name == "write_file":
                text, is_error = self.write_file(args["path"], args["content"])
            elif name == "submit_harnesses":
                text, is_error = self.submit_harnesses(args["harnesses"])
            else:
                text, is_error = f"unknown tool {name}", True
        except Exception as e:  # report tool failures to the agent instead of aborting the component
            log.debug("tool %s failed", name, exc_info=True)
            text, is_error = f"{type(e).__name__}: {e}", True
        self.log({"type": "tool_result", "tool": name, "is_error": is_error, "result": sandbox.truncate(text, 4000)})
        return text or "(no output)", is_error

    def log(self, entry: dict) -> None:
        if self.transcript is None:
            return
        entry["time"] = round(time.time(), 1)
        try:
            with self._lock, self.transcript.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        except OSError:
            # A broken transcript must never break the tool call itself.
            log.warning("cannot write transcript %s", self.transcript, exc_info=True)

    def _check_shape(self, harnesses: list[dict]) -> list[str]:
        problems = []
        if not isinstance(harnesses, list) or not harnesses:
            return ["submit at least one harness"]
        if len(harnesses) > self.max_harnesses:
            problems.append(f"at most {self.max_harnesses} harnesses, got {len(harnesses)}")
        names = set()
        for i, h in enumerate(harnesses, 1):
            if not isinstance(h, dict):
                problems.append(f"harness {i} is not an object")
                continue
            name = h.get("name", "")
            if not isinstance(name, str) or not _NAME.match(name):
                problems.append(f"harness {i}: name must match {_NAME.pattern}")
            elif name in names:
                problems.append(f"harness {i}: duplicate name {name}")
            names.add(name)
            for key in ("source", "target", "target_api", "description"):
                if not isinstance(h.get(key), str) or not h.get(key):
                    problems.append(f"harness {name or i}: {key} is required")
            for key in ("source", "target"):
                if isinstance(h.get(key), str) and h[key]:
                    try:
                        self.ws.resolve(h[key])
                    except ValueError as e:
                        problems.append(f"harness {name or i}: {e}")
            seeds = h.get("seeds")
            if not isinstance(seeds, list) or len(seeds) != SEEDS_PER_HARNESS:
                problems.append(f"harness {name or i}: exactly {SEEDS_PER_HARNESS} seeds are required")
                continue
            for j, seed in enumerate(seeds, 1):
                try:
                    data = _decode_seed(seed)
                except ValueError as e:
                    problems.append(f"harness {name or i}, seed {j}: {e}")
                    continue
                if len(data) > MAX_SEED_BYTES:
                    problems.append(f"harness {name or i}, seed {j}: larger than {MAX_SEED_BYTES} bytes")
        return problems

    def _write_seeds(self, h: dict) -> list[str]:
        corpus = self.ws.corpus / h["name"]
        corpus.mkdir(parents=True, exist_ok=True)
        for old in corpus.glob("seed-*"):
            old.unlink()
        paths = []
        for j, seed in enumerate(h["seeds"], 1):
            path = corpus / f"seed-{j}"
            path.write_bytes(_decode_seed(seed))
            paths.append(self.ws.relative(path))
        sandbox.give_to_sandbox(corpus)
        return paths


def _decode_seed(seed) -> bytes:
    if not isinstance(seed, dict) or not isinstance(seed.get("content"), str):
        raise ValueError("a seed is an object with content and encoding")
    encoding = seed.get("encoding", "text")
    if encoding == "text":
        return seed["content"].encode("utf-8")
    if encoding == "base64":
        try:
            return base64.b64decode(seed["content"], validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("content is not valid base64") from None
    raise ValueError('encoding must be "text" or "base64"')


def _loggable(name: str, args: dict) -> dict:
    args = dict(args)
    if name == "write_file":
        args["content"] = sandbox.truncate(str(args.get("content", "")), 2000)
    return args
