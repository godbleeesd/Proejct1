"""Classifying fuzzer crash output into a kind and a deduplication signature.

Atheris, Jazzer and libFuzzer (with sanitizers) print differently shaped reports; the
signature is the error type plus the innermost frame, so the same bug found twice by
different inputs collapses into one entry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

STACK_LINES = 40


@dataclass(frozen=True)
class CrashInfo:
    kind: str       # e.g. "heap-buffer-overflow", "IndexError", "java.lang.IllegalStateException", "timeout"
    signature: str  # kind + location, used to group duplicates
    summary: str    # one line for tables
    stack: str      # the relevant part of the output


_SANITIZER_SUMMARY = re.compile(r"^SUMMARY: (\w+Sanitizer): (\S+)(?: (.*))?$", re.MULTILINE)
_UBSAN = re.compile(r"^(\S+:\d+:\d+): runtime error: (.*)$", re.MULTILINE)
_PY_EXC = re.compile(r"=== Uncaught Python exception: ===\s*\n(.+)")
_PY_FRAME = re.compile(r'^\s*File "([^"]+)", line (\d+), in (\S+)', re.MULTILINE)
_JAVA_EXC = re.compile(r"== Java Exception: ([\w.$]+)(?::\s*(.*))?")
_JAVA_FRAME = re.compile(r"^\s+at ([\w.$<>]+)\(([^)]*)\)", re.MULTILINE)
_NATIVE_FRAME = re.compile(r"^\s+#\d+ 0x[0-9a-f]+ in (\S+) (\S+)", re.MULTILINE)
_DRIVER_FRAME = re.compile(r"^\s+#\d+ 0x[0-9a-f]+ (?:in (?:fuzzer::|main |_start |__libc_start)|\s*\(/lib/)")
_LIBFUZZER_ERROR = re.compile(r"==\d+== ?ERROR: libFuzzer: ([\w -]+)")


def classify(output: str) -> CrashInfo:
    if "ALARM: working on the last Unit" in output or "libFuzzer: timeout" in output:
        return _info("timeout", "timeout", "input ran longer than the per-input timeout", output, "ALARM")
    if "out-of-memory" in output:
        return _info("out-of-memory", "out-of-memory", "input exceeded the memory limit", output, "out-of-memory")

    # UBSan first: it reports (and with halt_on_error stops) before any later ASan crash, and
    # its own SUMMARY line carries no "ERROR:" header to anchor the stack excerpt on.
    m = _UBSAN.search(output)
    if m:
        where, message = _short(m.group(1)), m.group(2).strip()
        return _info("undefined-behavior", f"undefined-behavior {where}", f"{where}: {message}", output, m.group(0))

    m = _SANITIZER_SUMMARY.search(output)
    if m:
        kind = m.group(2)
        where = " ".join(_short(t) if "/" in t else t for t in (m.group(3) or "").split())
        return _info(kind, f"{kind} {where}".strip(), f"{m.group(1)}: {kind} {where}".strip(), output, "ERROR:")

    m = _PY_EXC.search(output)
    if m:
        line = m.group(1).strip()
        kind = line.split(":", 1)[0].strip()
        frames = _PY_FRAME.findall(output[m.start():])
        where = f"{_short(frames[-1][0])}:{frames[-1][1]} in {frames[-1][2]}" if frames else ""
        return _info(kind, f"{kind} {where}".strip(), f"{line[:160]} ({where})" if where else line[:160],
                     output, "=== Uncaught Python exception")

    m = _JAVA_EXC.search(output)
    if m:
        kind = m.group(1)
        # Jazzer's bug detectors throw from their own hooks; locate the finding in the
        # code under test instead, or every finding of one detector would look the same.
        frames = [f for f in _JAVA_FRAME.findall(output[m.start():])
                  if not f[0].startswith("com.code_intelligence.jazzer.")]
        where = f"{frames[0][0]}({frames[0][1]})" if frames else ""
        message = (m.group(2) or "").strip()
        summary = f"{kind}: {message[:120]}" if message else kind
        return _info(kind, f"{kind} {where}".strip(), f"{summary} ({where})" if where else summary,
                     output, "== Java Exception")

    m = _LIBFUZZER_ERROR.search(output)
    if m:
        kind = m.group(1).strip().replace(" ", "-")
        frames = [f for f in _NATIVE_FRAME.findall(output[m.start():]) if not _is_runtime_frame(f[0])]
        where = f"{frames[0][0]} {_short(frames[0][1])}" if frames else ""
        return _info(kind, f"{kind} {where}".strip(), f"libFuzzer: {kind} {where}".strip(), output, "ERROR: libFuzzer")

    return _info("crash", "crash", "unrecognised crash output", output, None)


def _info(kind: str, signature: str, summary: str, output: str, anchor: str | None) -> CrashInfo:
    start = output.find(anchor) if anchor else -1
    text = output[start:] if start >= 0 else output[-4000:]
    # Frames of the fuzzer driver and libc below the harness add nothing to a report.
    lines = [line for line in text.splitlines() if not _DRIVER_FRAME.search(line)]
    return CrashInfo(kind, signature, summary, "\n".join(lines[:STACK_LINES]))


def _short(path: str) -> str:
    """Drop machine-specific prefixes so signatures match across workspaces."""
    for marker in ("/site/", "/src/", "/harnesses/"):
        if marker in path:
            return path.split(marker, 1)[1]
    return path.rsplit("/", 1)[-1]


def _is_runtime_frame(function: str) -> bool:
    return function.startswith(("__sanitizer", "__asan", "__ubsan", "fuzzer::", "__libc", "abort", "raise"))
