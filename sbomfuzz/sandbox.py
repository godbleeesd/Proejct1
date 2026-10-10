"""Running untrusted commands (package installs, builds, harnesses, fuzzers).

Everything the agent runs executes third-party code. When the orchestrator runs
as root (the default in the Docker image), commands are started as the
unprivileged sandbox user, so they cannot read the orchestrator's environment
(/proc/<pid>/environ) or files and thereby the Anthropic API key or subscription
token. ANTHROPIC_* and CLAUDE_* variables are also stripped from the environment
passed to children.
"""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

try:
    import pwd
except ImportError:  # Windows: no sandbox user, commands run as the current user.
    pwd = None

SANDBOX_USER = os.environ.get("SBOMFUZZ_SANDBOX_USER", "fuzzer")

# API keys and the subscription token (CLAUDE_CODE_OAUTH_TOKEN) never reach sandboxed code.
SECRET_ENV_PREFIXES = ("ANTHROPIC_", "CLAUDE_")

# LeakSanitizer needs ptrace, which Docker forbids by default.
SANITIZER_ENV = {
    "ASAN_OPTIONS": "detect_leaks=0:symbolize=1:allocator_may_return_null=1",
    "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
}


@dataclass
class CommandResult:
    returncode: int | None
    output: str
    timed_out: bool
    duration: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def _sandbox_ids() -> tuple[int, int, str] | None:
    if pwd is None or os.geteuid() != 0:
        return None
    try:
        entry = pwd.getpwnam(SANDBOX_USER)
    except KeyError:
        return None
    return entry.pw_uid, entry.pw_gid, entry.pw_dir


def sandbox_active() -> bool:
    return _sandbox_ids() is not None


def child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(SECRET_ENV_PREFIXES)}
    env.update(SANITIZER_ENV)
    env["GIT_TERMINAL_PROMPT"] = "0"
    ids = _sandbox_ids()
    if ids is not None:
        env["HOME"] = ids[2]
        env["USER"] = SANDBOX_USER
    env.update(extra or {})
    return env


def give_to_sandbox(path: Path) -> None:
    """Make the sandbox user the owner of a tree it needs to write to."""
    ids = _sandbox_ids()
    if ids is None or not path.exists():
        return
    uid, gid, _ = ids
    os.chown(path, uid, gid, follow_symlinks=False)
    if path.is_dir() and not path.is_symlink():
        for root, dirs, files in os.walk(path):
            for name in dirs + files:
                os.chown(os.path.join(root, name), uid, gid, follow_symlinks=False)


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    head = limit * 3 // 10
    tail = limit - head
    omitted = len(text) - head - tail
    return f"{text[:head]}\n\n... [{omitted} characters omitted] ...\n\n{text[-tail:]}"


def run(
    command: list[str] | str,
    cwd: Path,
    timeout: float,
    env: dict[str, str] | None = None,
    output_limit: int = 12_000,
) -> CommandResult:
    """Run a command (a shell string runs under bash) with merged stdout/stderr.

    Output goes to a temporary file rather than a pipe so a chatty process cannot
    exhaust memory; only `output_limit` characters (head and tail) are returned.
    """
    shell = isinstance(command, str)
    kwargs: dict = {}
    ids = _sandbox_ids()
    if ids is not None:
        kwargs.update(user=ids[0], group=ids[1], extra_groups=[])

    start = time.monotonic()
    with tempfile.TemporaryFile() as buf:
        proc = subprocess.Popen(
            command,
            cwd=cwd,
            shell=shell,
            executable="/bin/bash" if shell else None,
            stdin=subprocess.DEVNULL,
            stdout=buf,
            stderr=subprocess.STDOUT,
            env=child_env(env),
            start_new_session=True,
            **kwargs,
        )
        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        # Kill the whole process group: build tools and fuzzers fork workers.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()
        output = _read_head_tail(buf, output_limit)

    return CommandResult(
        returncode=None if timed_out else proc.returncode,
        output=output,
        timed_out=timed_out,
        duration=time.monotonic() - start,
    )


def _read_head_tail(buf, limit: int) -> str:
    size = buf.seek(0, os.SEEK_END)
    # Read a little more than needed: characters can be multi-byte.
    window = limit * 4
    if size <= window:
        buf.seek(0)
        return truncate(buf.read().decode("utf-8", "replace"), limit)
    head_chars = limit * 3 // 10
    buf.seek(0)
    head = buf.read(head_chars * 4).decode("utf-8", "replace")[:head_chars]
    buf.seek(size - (limit - head_chars) * 4)
    tail = buf.read().decode("utf-8", "replace")[-(limit - head_chars):]
    return f"{head}\n\n... [output truncated, {size} bytes in total] ...\n\n{tail}"
