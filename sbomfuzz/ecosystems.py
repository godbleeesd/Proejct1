"""Fuzzer integration and harness-writing guidance for each supported ecosystem.

All three fuzzers (Atheris, Jazzer, libFuzzer) share libFuzzer's command line: given
directories they fuzz, given files they run each file once. That makes validation
(run the seeds) and fuzzing the same command with different arguments.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import sandbox
from .workspace import Workspace

JAZZER_BIN = os.environ.get("JAZZER_BIN", "jazzer")
JAZZER_JAR = os.environ.get("JAZZER_JAR", "/opt/jazzer/jazzer_standalone.jar")

PER_INPUT_TIMEOUT = 25
LIBFUZZER_FLAGS = [f"-timeout={PER_INPUT_TIMEOUT}", "-rss_limit_mb=2560", "-print_final_stats=1"]
BUILD_SCRIPT = "harnesses/build.sh"

# Lines that mark a crash in libFuzzer / Atheris / Jazzer / sanitizer output.
_CRASH_MARKERS = re.compile(
    r"==\d+==ERROR: |ERROR: libFuzzer|=== Uncaught Python exception|== Java Exception:"
    r"|runtime error: |SUMMARY: \w+Sanitizer|ALARM: working on the last Unit|==\d+== ERROR: libFuzzer"
)
_STATS_LINE = re.compile(r"^#\d+\s+(?:DONE|pulse|NEW|REDUCE|INITED|RELOAD)\b.*$", re.MULTILINE)
_EXECS = re.compile(r"^stat::number_of_executed_units:\s*(\d+)", re.MULTILINE)


@dataclass
class FuzzRun:
    status: str  # "clean" | "crash" | "error"
    output: str
    stats: str = ""
    executions: int = 0
    crash_files: list[str] = field(default_factory=list)
    duration: float = 0.0
    new_files: list[str] = field(default_factory=list)  # everything the run added to crashes/


class Ecosystem:
    key: str
    title: str
    guidance: str
    target_hint: str  # what "target" means in submit_harnesses

    def prepare(self, ws: Workspace, target: Path) -> tuple[list[str], dict[str, str]] | str:
        """The command that runs this harness, or an error message (e.g. a compile error)."""
        raise NotImplementedError

    def build(self, ws: Workspace) -> str | None:
        """Ecosystem-wide build step before validation; returns an error message or None."""
        return None

    def validate(self, ws: Workspace, target: str, seeds: list[Path]) -> tuple[bool, str]:
        """Run the harness once on each seed. Passing means: it starts, and no seed crashes it."""
        path = ws.resolve(target)
        if not path.exists():
            return False, f"{target} does not exist"
        prepared = self.prepare(ws, path)
        if isinstance(prepared, str):
            return False, prepared
        command, env = prepared
        command = command + LIBFUZZER_FLAGS + [str(s) for s in seeds]
        result = sandbox.run(command, cwd=ws.root, timeout=180, env=env, output_limit=8000)
        if result.ok:
            return True, "ran all seeds without errors"
        if result.timed_out:
            return False, "running the seeds took longer than 180s:\n" + result.output
        return False, f"exit code {result.returncode}:\n{result.output}"

    def fuzz(self, ws: Workspace, target: str, corpus: Path, seconds: int) -> FuzzRun:
        path = ws.resolve(target)
        prepared = self.prepare(ws, path)
        if isinstance(prepared, str):
            return FuzzRun("error", prepared)
        command, env = prepared
        command = command + [f"-max_total_time={seconds}", f"-artifact_prefix={ws.crashes}/", *LIBFUZZER_FLAGS,
                             str(corpus)]
        before = set(os.listdir(ws.crashes))
        result = sandbox.run(command, cwd=ws.root, timeout=seconds + 120, env=env, output_limit=200_000)
        added = sorted(set(os.listdir(ws.crashes)) - before)
        # Jazzer also writes a Crash_*.java reproducer next to each crash input.
        run = summarize(result, [f"crashes/{n}" for n in added if not n.endswith(".java")])
        run.new_files = [f"crashes/{n}" for n in added]
        return run

    def repro_command(self, ws: Workspace, target: str, crash_file: str) -> str:
        """Shell command (run in the workspace) that replays one crash input."""
        raise NotImplementedError

    def command_env(self, ws: Workspace) -> dict[str, str]:
        """Environment for the agent's run_command calls."""
        return {}


def summarize(result: sandbox.CommandResult, new_crashes: list[str]) -> FuzzRun:
    output = result.output
    stats = _STATS_LINE.findall(output)
    execs = _EXECS.search(output)
    if new_crashes or _CRASH_MARKERS.search(output):
        status = "crash"
    elif result.timed_out or result.returncode != 0:
        status = "error"
    else:
        status = "clean"
    return FuzzRun(status, output, stats[-1] if stats else "", int(execs.group(1)) if execs else 0,
                   new_crashes, result.duration)


class PythonEcosystem(Ecosystem):
    key = "python"
    title = "Python (PyPI) with Atheris"
    target_hint = "the harness .py file (same as source)"
    guidance = """\
The package and its dependencies were installed with `pip install --target site/`; `site/` is on
PYTHONPATH. Find the public API in `site/`.

Write Atheris harnesses as `harnesses/fuzz_<name>.py`:

    import sys
    import atheris

    with atheris.instrument_imports():
        import target_module

    def TestOneInput(data: bytes) -> None:
        fdp = atheris.FuzzedDataProvider(data)
        ...

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

Catch only the exceptions the API documents for invalid input; anything else must propagate so
the fuzzer reports it. The harness runs as `python harnesses/fuzz_<name>.py <input file>`."""

    def prepare(self, ws, target):
        if target.suffix != ".py":
            return "target must be an Atheris harness (.py file)"
        return [sys.executable, str(target)], self.command_env(ws)

    def repro_command(self, ws, target, crash_file):
        return f"PYTHONPATH=site python3 {shlex.quote(target)} {shlex.quote(crash_file)}"

    def command_env(self, ws):
        return {"PYTHONPATH": str(ws.site)}


class JavaEcosystem(Ecosystem):
    key = "java"
    title = "Java (Maven) with Jazzer"
    target_hint = "the harness .java file (same as source); it is compiled automatically"
    guidance = """\
The Maven artifact and its runtime dependencies are in `libs/`; the sources jar, when the project
publishes one, is unpacked in `sources/`. Explore the API with the sources, `unzip -l libs/<jar>`
or `javap -cp "libs/*" <class>`.

Write Jazzer harnesses as `harnesses/<ClassName>.java`, in the default package (class name = file
name), with

    import com.code_intelligence.jazzer.api.FuzzedDataProvider;

    public class ClassName {
        public static void fuzzerTestOneInput(FuzzedDataProvider data) { ... }
    }

Catch only the exceptions the API documents for invalid input. To check that a harness compiles:
`javac -cp "libs/*:$JAZZER_JAR" -d build/<ClassName> harnesses/<ClassName>.java`."""

    def prepare(self, ws, target):
        if target.suffix != ".java":
            return "target must be a Jazzer harness (.java file)"
        build = ws.root / "build" / target.stem
        build.mkdir(parents=True, exist_ok=True)
        sandbox.give_to_sandbox(ws.root / "build")
        jars = self._jars(ws)
        compiled = sandbox.run(["javac", "-cp", ":".join(jars + [JAZZER_JAR]), "-d", str(build), str(target)],
                               cwd=ws.root, timeout=300)
        if not compiled.ok:
            return "javac failed:\n" + compiled.output
        command = [JAZZER_BIN, f"--cp={':'.join([str(build)] + jars)}", f"--target_class={self._class(target)}",
                   f"--reproducer_path={ws.crashes}"]
        return command, {}

    def repro_command(self, ws, target, crash_file):
        path = ws.resolve(target)
        cp = ":".join([f"build/{path.stem}"] + [ws.relative(Path(j)) for j in self._jars(ws)])
        return f"jazzer --cp={cp} --target_class={self._class(path)} {shlex.quote(crash_file)}"

    @staticmethod
    def _class(target: Path) -> str:
        package = re.search(r"^\s*package\s+([\w.]+)\s*;", target.read_text(errors="replace"), re.MULTILINE)
        return f"{package.group(1)}.{target.stem}" if package else target.stem

    @staticmethod
    def _jars(ws: Workspace) -> list[str]:
        # Listed explicitly: Jazzer starts the JVM itself and does not expand "dir/*".
        return sorted(str(p) for p in ws.libs.glob("*.jar")) if ws.libs.is_dir() else []

    def command_env(self, ws):
        return {"JAZZER_JAR": JAZZER_JAR}


class NativeEcosystem(Ecosystem):
    key = "native"
    title = "C/C++ with libFuzzer"
    target_hint = "the fuzzer binary that harnesses/build.sh produces"
    guidance = f"""\
The source code is in `src/`. It is most likely C or C++; check. If it is not native code that
libFuzzer can test, say so instead of forcing it (submit no harnesses).

Write libFuzzer harnesses as `harnesses/fuzz_<name>.c` or `.cc` with
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
(no `extern "C"` in C files), and a `{BUILD_SCRIPT}` that builds everything from scratch: the
library with sanitizers (CC=clang CXX=clang++, CFLAGS/CXXFLAGS="-g -O1 -fno-omit-frame-pointer
-fsanitize=address,undefined -fsanitize=fuzzer-no-link"; prefer a static build of just the
library, or compile the needed source files directly), then each harness linked with
`-fsanitize=fuzzer,address,undefined`. The program runs `bash {BUILD_SCRIPT}` from the workspace
root before checking the harnesses, so the script must work from a clean state."""

    def build(self, ws):
        script = ws.root / BUILD_SCRIPT
        if not script.exists():
            return f"{BUILD_SCRIPT} does not exist; native harnesses need a build script"
        result = sandbox.run(["bash", BUILD_SCRIPT], cwd=ws.root, timeout=1800, output_limit=8000)
        if not result.ok:
            status = "timed out" if result.timed_out else f"exit code {result.returncode}"
            return f"{BUILD_SCRIPT} failed ({status}):\n{result.output}"
        return None

    def prepare(self, ws, target):
        if target.is_dir() or not os.access(target, os.X_OK):
            return f"{ws.relative(target)} is not an executable; {BUILD_SCRIPT} must build it"
        return [str(target)], {}

    def repro_command(self, ws, target, crash_file):
        return f"./{shlex.quote(target)} {shlex.quote(crash_file)}"


ECOSYSTEMS: dict[str, Ecosystem] = {e.key: e for e in (PythonEcosystem(), JavaEcosystem(), NativeEcosystem())}
