from sbomfuzz.crashes import classify
from sbomfuzz.ecosystems import summarize
from sbomfuzz.sandbox import CommandResult, truncate

CLEAN = """\
INFO: Seed: 1234
#2\tINITED cov: 12 ft: 13 corp: 1/1b exec/s: 0 rss: 40Mb
#90311\tDONE   cov: 52 ft: 88 corp: 21/600b lim: 400 exec/s: 3010 rss: 45Mb
Done 90311 runs in 31 second(s)
stat::number_of_executed_units: 90311
"""

ASAN = """\
#2\tINITED cov: 12 ft: 13 corp: 1/1b exec/s: 0 rss: 40Mb
=================================================================
==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000015
READ of size 1 at 0x602000000015 thread T0
    #0 0x55 in parse_value /tmp/sbomfuzz-work/cjson/ws/src/cJSON-1.7.18/cJSON.c:310:9
    #1 0x56 in LLVMFuzzerTestOneInput /tmp/sbomfuzz-work/cjson/ws/harnesses/fuzz_parse.c:8:5
SUMMARY: AddressSanitizer: heap-buffer-overflow /tmp/sbomfuzz-work/cjson/ws/src/cJSON-1.7.18/cJSON.c:310:9 in parse_value
artifact_prefix='crashes/'; Test unit written to crashes/crash-abc
"""

PYTHON = """\
=== Uncaught Python exception: ===
IndexError: list index out of range
Traceback (most recent call last):
  File "/tmp/w/ws/harnesses/fuzz_loads.py", line 9, in TestOneInput
    toml.loads(s)
  File "/tmp/w/ws/site/toml/decoder.py", line 511, in loads
    ret = decoder.load_line(line, currentlevel, multikey, multibackslash)
  File "/tmp/w/ws/site/toml/decoder.py", line 207, in load_line
    if item == '\\r' and sl[i + 1] == '\\n':
"""

JAVA = """\
== Java Exception: java.lang.IllegalStateException: planted bug
\tat DemoFuzzer.fuzzerTestOneInput(DemoFuzzer.java:6)
\tat com.code_intelligence.jazzer.driver.FuzzTargetRunner.runOne(FuzzTargetRunner.java:229)
DEDUP_TOKEN: 0123456789abcdef
"""

UBSAN = """\
#1024\tpulse  cov: 1500 ft: 9000 corp: 800/300Kb exec/s: 20000 rss: 560Mb
/tmp/sbomfuzz-work/cjson-1/src/cJSON_Utils.c:71:21: runtime error: null pointer passed as argument 1, which is declared to never be null
/usr/include/string.h:407:33: note: nonnull attribute specified here
    #0 0x5a1 in cJSONUtils_strdup /tmp/sbomfuzz-work/cjson-1/src/cJSON_Utils.c:71:14
    #1 0x5a2 in detach_path /tmp/sbomfuzz-work/cjson-1/src/cJSON_Utils.c:438:22
    #4 0x5a3 in LLVMFuzzerTestOneInput /tmp/sbomfuzz-work/cjson-1/harnesses/fuzz_patch.c:20:13
    #5 0x5a4 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/tmp/x/build/fuzz_patch+0x76cc4)
    #10 0x5a5 in main (/tmp/x/build/fuzz_patch+0x90066)
    #11 0x7b4  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9)

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/cJSON_Utils.c:71:21
"""

TIMEOUT ="ALARM: working on the last Unit for 26 seconds\n       and the timeout value is 25 (use -timeout=N to change)\n"


def result(output, code=0, timed_out=False):
    return CommandResult(returncode=code, output=output, timed_out=timed_out, duration=31.0)


def test_clean_run():
    run = summarize(result(CLEAN), [])
    assert run.status == "clean"
    assert run.stats.startswith("#90311\tDONE")
    assert run.executions == 90311


def test_crash_and_error_status():
    assert summarize(result(ASAN, code=1), ["crashes/crash-abc"]).status == "crash"
    assert summarize(result(PYTHON, code=1), []).status == "crash"
    assert summarize(result("ModuleNotFoundError: No module named 'foo'", code=1), []).status == "error"
    assert summarize(result(CLEAN, code=None, timed_out=True), []).status == "error"


def test_classify_sanitizer_crash():
    info = classify(ASAN)
    assert info.kind == "heap-buffer-overflow"
    assert info.signature == "heap-buffer-overflow cJSON-1.7.18/cJSON.c:310:9 in parse_value"
    assert info.stack.startswith("ERROR: AddressSanitizer")


def test_classify_ubsan_keeps_the_error_line():
    # Found in the first real cJSON run: the excerpt started mid-stack, without the error itself.
    info = classify(UBSAN)
    assert info.kind == "undefined-behavior"
    assert info.signature == "undefined-behavior cJSON_Utils.c:71:21"
    assert "null pointer passed as argument 1" in info.summary
    assert info.stack.splitlines()[0].endswith("runtime error: null pointer passed as argument 1, "
                                               "which is declared to never be null")
    assert "detach_path" in info.stack and "LLVMFuzzerTestOneInput" in info.stack
    assert "fuzzer::Fuzzer" not in info.stack and "libc.so" not in info.stack and " in main " not in info.stack


def test_classify_python_exception_uses_innermost_frame():
    info = classify(PYTHON)
    assert info.kind == "IndexError"
    assert info.signature == "IndexError toml/decoder.py:207 in load_line"
    # Workspace paths are stripped, so the same bug matches across runs and machines.
    assert "/tmp/w" not in info.signature


def test_classify_java_exception():
    info = classify(JAVA)
    assert info.kind == "java.lang.IllegalStateException"
    assert info.signature == "java.lang.IllegalStateException DemoFuzzer.fuzzerTestOneInput(DemoFuzzer.java:6)"
    assert "planted bug" in info.summary


def test_classify_timeout_and_unknown():
    assert classify(TIMEOUT).kind == "timeout"
    assert classify("something went wrong").kind == "crash"


def test_truncate_keeps_head_and_tail():
    text = "A" * 100 + "B" * 100
    out = truncate(text, 50)
    assert out.startswith("A" * 15) and out.endswith("B" * 35)
    assert "150 characters omitted" in out
    assert truncate("short", 50) == "short"
