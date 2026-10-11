"""Fuzzer integration and agent guidance for each supported ecosystem.

All three fuzzers (Atheris, Jazzer, libFuzzer) share libFuzzer's command line and
output format, so running and summarising them is mostly common code.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import sandbox
from .workspace import Workspace

JAZZER_BIN = os.environ.get("JAZZER_BIN", "jazzer")
JAZZER_JAR = os.environ.get("JAZZER_JAR", "/opt/jazzer/jazzer_standalone.jar")

LIBFUZZER_FLAGS = ["-timeout=25", "-rss_limit_mb=2560", "-print_final_stats=1"]

# Lines that mark a finding in libFuzzer / Atheris / Jazzer / sanitizer output.
_CRASH_MARKERS = re.compile(
    r"==\d+==ERROR: |ERROR: libFuzzer|=== Uncaught Python exception|== Java Exception:"
    r"|runtime error: |SUMMARY: \w+Sanitizer|ALARM: working on the last Unit|==\d+== ERROR: libFuzzer"
)
_STATS_LINE = re.compile(r"^#\d+\s+(?:DONE|pulse|NEW|REDUCE|INITED|RELOAD)\b.*$", re.MULTILINE)


@dataclass
class FuzzRun:
    status: str  # "clean" | "crash" | "error"
    stats: str
    crash_files: list[str] = field(default_factory=list)
    excerpt: str = ""
    duration: float = 0.0
    harness_snapshot: str = ""  # copy of the harness version that found the crashes

    def to_text(self) -> str:
        lines = [f"status: {self.status}", f"duration: {self.duration:.0f}s"]
        if self.stats:
            lines.append(f"last stats: {self.stats}")
        if self.crash_files:
            lines.append("new crash inputs: " + ", ".join(self.crash_files))
        if self.harness_snapshot:
            lines.append(f"harness snapshot: {self.harness_snapshot} (the exact harness version that found these "
                         "crashes; use it in reproduction commands, since you may change the harness later)")
        lines += ["output:", self.excerpt]
        return "\n".join(lines)


def summarize(result: sandbox.CommandResult, new_crashes: list[str]) -> FuzzRun:
    output = result.output
    stats = _STATS_LINE.findall(output)
    marker = _CRASH_MARKERS.search(output)
    if new_crashes or marker:
        status = "crash"
        start = max(0, marker.start() - 500) if marker else max(0, len(output) - 6000)
        excerpt = output[start : start + 8000]
    elif result.timed_out:
        status = "error"
        excerpt = "fuzzer did not stop in time and was killed\n" + output[-4000:]
    elif result.returncode != 0:
        status = "error"
        excerpt = output[-6000:]
    else:
        status = "clean"
        excerpt = output[-2500:]
    return FuzzRun(status, stats[-1] if stats else "", new_crashes, excerpt, result.duration)


def snapshot_harness(ws: Workspace, harness: Path) -> Path:
    """Copy the harness (source or fuzzer binary) to crashes/snapshots/, named by content hash.

    The agent keeps editing its harnesses, so without this a crash input found by an
    earlier version may no longer reproduce with the harness that is finally saved.
    """
    data = harness.read_bytes()
    digest = hashlib.sha256(data).hexdigest()[:10]
    snapshots = ws.crashes / "snapshots"
    snapshots.mkdir(exist_ok=True)
    dest = snapshots / f"{harness.stem}-{digest}{harness.suffix}"
    if not dest.exists():
        shutil.copy2(harness, dest)
        sandbox.give_to_sandbox(snapshots)
    return dest


class Ecosystem:
    key: str
    title: str
    guidance: str

    def fuzz(self, ws: Workspace, target: str, seconds: int) -> FuzzRun:
        path = ws.resolve(target)
        if not path.exists():
            return FuzzRun("error", "", excerpt=f"{target} does not exist")
        prepared = self._command(ws, path)
        if isinstance(prepared, FuzzRun):
            return prepared
        command, env = prepared
        command += [f"-max_total_time={seconds}", f"-artifact_prefix={ws.crashes}/", *LIBFUZZER_FLAGS]
        command.append(str(ws.corpus_for(path)))

        before = set(os.listdir(ws.crashes))
        result = sandbox.run(command, cwd=ws.root, timeout=seconds + 120, env=env, output_limit=200_000)
        new = sorted(set(os.listdir(ws.crashes)) - before)
        run = summarize(result, [f"crashes/{name}" for name in new])
        if new:
            run.harness_snapshot = ws.relative(snapshot_harness(ws, path))
        return run

    def _command(self, ws: Workspace, target: Path) -> tuple[list[str], dict[str, str]] | FuzzRun:
        raise NotImplementedError

    def command_env(self, ws: Workspace) -> dict[str, str]:
        """Environment for the agent's run_command calls."""
        return {}


class PythonEcosystem(Ecosystem):
    key = "python"
    title = "Python (PyPI) with Atheris"
    guidance = """\
The package and its dependencies were installed with `pip install --target site/`; `site/` is on
PYTHONPATH for run_command and run_fuzzer. Find the public API in `site/` (look for parsers,
decoders, deserializers, format converters - anything that consumes untrusted bytes or text).

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

Catch only the exceptions the API documents for invalid input. An undocumented exception type,
a hang, or runaway memory use is a finding. run_fuzzer's target is the harness path. Reproduce a
crash with `python harnesses/fuzz_<name>.py crashes/<file>`."""

    def _command(self, ws, target):
        if target.suffix != ".py":
            return FuzzRun("error", "", excerpt="target must be an Atheris harness (.py file)")
        return [sys.executable, str(target)], self.command_env(ws)

    def command_env(self, ws):
        return {"PYTHONPATH": str(ws.site)}


class JavaEcosystem(Ecosystem):
    key = "java"
    title = "Java (Maven) with Jazzer"
    guidance = """\
The Maven artifact and its runtime dependencies are in `libs/`; the sources jar, when the project
publishes one, is unpacked in `sources/`. Explore the API with the sources, `unzip -l libs/<jar>`
or `javap -cp "libs/*" <class>`. Look for parsers, decoders, deserializers and other code that
consumes untrusted input.

Write Jazzer harnesses as `harnesses/<ClassName>.java`, in the default package (class name = file
name), with

    import com.code_intelligence.jazzer.api.FuzzedDataProvider;

    public class ClassName {
        public static void fuzzerTestOneInput(FuzzedDataProvider data) { ... }
    }

Jazzer reports uncaught exceptions and its own bug detectors (unsafe deserialization, path
traversal, SSRF, regex DoS, ...). Catch only the exceptions the API documents for invalid input.
run_fuzzer's target is the .java file: it compiles and runs it. To compile by hand:
`javac -cp "libs/*:$JAZZER_JAR" -d build/<ClassName> harnesses/<ClassName>.java`. Jazzer writes a
standalone reproducer (`Crash_*.java`) next to each crash input in `crashes/`."""

    def _command(self, ws, target):
        if target.suffix != ".java":
            return FuzzRun("error", "", excerpt="target must be a Jazzer harness (.java file)")
        build = ws.root / "build" / target.stem
        build.mkdir(parents=True, exist_ok=True)
        sandbox.give_to_sandbox(ws.root / "build")
        jars = self._jars(ws)
        compiled = sandbox.run(
            ["javac", "-cp", ":".join(jars + [JAZZER_JAR]), "-d", str(build), str(target)],
            cwd=ws.root,
            timeout=300,
        )
        if not compiled.ok:
            return FuzzRun("error", "", excerpt="javac failed:\n" + compiled.output)
        package = re.search(r"^\s*package\s+([\w.]+)\s*;", target.read_text(errors="replace"), re.MULTILINE)
        cls = f"{package.group(1)}.{target.stem}" if package else target.stem
        command = [
            JAZZER_BIN,
            f"--cp={':'.join([str(build)] + jars)}",
            f"--target_class={cls}",
            f"--reproducer_path={ws.crashes}",
        ]
        return command, {}

    def _jars(self, ws: Workspace) -> list[str]:
        # Listed explicitly: Jazzer starts the JVM itself and does not expand "dir/*".
        return sorted(str(p) for p in ws.libs.glob("*.jar")) if ws.libs.is_dir() else []

    def command_env(self, ws):
        return {"JAZZER_JAR": JAZZER_JAR}


class NativeEcosystem(Ecosystem):
    key = "native"
    title = "C/C++ with libFuzzer"
    guidance = """\
The source code is in `src/`. It is most likely C or C++; check. If it is not native code that
libFuzzer can test, say so in the report instead of forcing it.

Build what you need with sanitizers, preferring a static build of just the library (the
project's own build system, or compiling the needed source files directly when that is simpler):
    CC=clang CXX=clang++
    CFLAGS/CXXFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fsanitize=fuzzer-no-link"
Write libFuzzer harnesses as `harnesses/fuzz_<name>.c` or `.cc` with
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
(no `extern "C"` in C files), link with `-fsanitize=fuzzer,address,undefined`, and put every
build step in `harnesses/build.sh` so the result can be reproduced. run_fuzzer's target is the
compiled fuzzer binary. Reproduce a crash with `./<binary> crashes/<file>`. LeakSanitizer is off
(no ptrace in the container), so leaks are not reported."""

    def _command(self, ws, target):
        if not os.access(target, os.X_OK) or target.is_dir():
            return FuzzRun("error", "", excerpt=f"{ws.relative(target)} is not an executable; build the fuzzer first")
        return [str(target)], {}


ECOSYSTEMS: dict[str, Ecosystem] = {e.key: e for e in (PythonEcosystem(), JavaEcosystem(), NativeEcosystem())}
