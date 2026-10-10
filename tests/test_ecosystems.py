from sbomfuzz.ecosystems import summarize
from sbomfuzz.sandbox import CommandResult, truncate

CLEAN = """\
INFO: Seed: 1234
#2\tINITED cov: 12 ft: 13 corp: 1/1b exec/s: 0 rss: 40Mb
#1024\tpulse  cov: 40 ft: 60 corp: 9/120b lim: 14 exec/s: 512 rss: 41Mb
#90311\tDONE   cov: 52 ft: 88 corp: 21/600b lim: 400 exec/s: 3010 rss: 45Mb
Done 90311 runs in 31 second(s)
"""

ASAN = """\
#2\tINITED cov: 12 ft: 13 corp: 1/1b exec/s: 0 rss: 40Mb
=================================================================
==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000015
    #0 0x55 in parse src/parse.c:10
SUMMARY: AddressSanitizer: heap-buffer-overflow src/parse.c:10 in parse
artifact_prefix='crashes/'; Test unit written to crashes/crash-abc
"""

PYTHON = """\
=== Uncaught Python exception: ===
KeyError: 'x'
Traceback (most recent call last):
  File "harnesses/fuzz_x.py", line 9, in TestOneInput
"""


def result(output, code=0, timed_out=False):
    return CommandResult(returncode=code, output=output, timed_out=timed_out, duration=31.0)


def test_clean_run():
    run = summarize(result(CLEAN), [])
    assert run.status == "clean"
    assert run.stats.startswith("#90311\tDONE")


def test_sanitizer_crash():
    run = summarize(result(ASAN, code=1), ["crashes/crash-abc"])
    assert run.status == "crash"
    assert "heap-buffer-overflow" in run.excerpt
    assert run.crash_files == ["crashes/crash-abc"]
    assert "crashes/crash-abc" in run.to_text()


def test_python_exception_without_crash_file_is_still_a_crash():
    assert summarize(result(PYTHON, code=1), []).status == "crash"


def test_harness_failure_is_an_error():
    run = summarize(result("ModuleNotFoundError: No module named 'foo'", code=1), [])
    assert run.status == "error"
    assert "ModuleNotFoundError" in run.excerpt


def test_killed_run_is_an_error():
    assert summarize(result(CLEAN, code=None, timed_out=True), []).status == "error"


def test_truncate_keeps_head_and_tail():
    text = "A" * 100 + "B" * 100
    out = truncate(text, 50)
    assert out.startswith("A" * 15) and out.endswith("B" * 35)
    assert "150 characters omitted" in out
    assert truncate("short", 50) == "short"
