"""Runs the real toolchains. Meant for the Docker image (CI runs them there)."""

import shutil

import pytest

from sbomfuzz import sandbox
from sbomfuzz.ecosystems import ECOSYSTEMS
from sbomfuzz.fetch import fetch
from sbomfuzz.sbom import Component

pytestmark = pytest.mark.integration


def needs(tool):
    return pytest.mark.skipif(shutil.which(tool) is None, reason=f"{tool} not installed")


def write(ws, relative, content):
    path = ws.root / relative
    path.write_text(content)
    sandbox.give_to_sandbox(path)


PY_HARNESS = """\
import sys
import atheris

def TestOneInput(data):
    if data[:1] == b"B":
        raise RuntimeError("planted bug")

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
"""

C_HARNESS = """\
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0 && data[0] == 'B') {
        /* libFuzzer passes a heap copy of exactly `size` bytes: one past the end
           is a heap-buffer-overflow. volatile keeps the optimizer from removing it. */
        volatile uint8_t past_end = data[size];
        (void)past_end;
    }
    return 0;
}
"""

C_CLEAN_HARNESS = """\
#include <stdint.h>
#include <stddef.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return 0; }
"""

JAVA_HARNESS = """\
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class DemoFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        if (data.consumeByte() == 66) {
            throw new IllegalStateException("planted bug");
        }
    }
}
"""


def test_atheris_finds_planted_bug(ws):
    pytest.importorskip("atheris")
    write(ws, "harnesses/fuzz_demo.py", PY_HARNESS)
    run = ECOSYSTEMS["python"].fuzz(ws, "harnesses/fuzz_demo.py", 60)
    assert run.status == "crash", run.to_text()
    assert run.crash_files
    assert "planted bug" in run.excerpt

    # The agent may now "fix" its harness; the snapshot must still reproduce the crash.
    assert run.harness_snapshot.startswith("crashes/snapshots/fuzz_demo-")
    write(ws, "harnesses/fuzz_demo.py", PY_HARNESS.replace('raise RuntimeError("planted bug")', "return"))
    replay = sandbox.run(["python3", run.harness_snapshot, run.crash_files[0]], cwd=ws.root, timeout=60)
    assert "planted bug" in replay.output, replay.output


def build_c(ws, source, binary):
    write(ws, f"harnesses/{binary}.c", source)
    built = sandbox.run(["clang", "-g", "-O1", "-fsanitize=fuzzer,address,undefined",
                         f"harnesses/{binary}.c", "-o", binary], cwd=ws.root, timeout=300)
    assert built.ok, built.output


@needs("clang")
def test_libfuzzer_finds_heap_overflow(ws):
    build_c(ws, C_HARNESS, "fuzz_demo")
    run = ECOSYSTEMS["native"].fuzz(ws, "fuzz_demo", 60)
    assert run.status == "crash", run.to_text()
    assert "heap-buffer-overflow" in run.excerpt
    assert run.crash_files


@needs("clang")
def test_libfuzzer_clean_run(ws):
    build_c(ws, C_CLEAN_HARNESS, "fuzz_clean")
    run = ECOSYSTEMS["native"].fuzz(ws, "fuzz_clean", 5)
    assert run.status == "clean", run.to_text()
    assert "DONE" in run.stats


@needs("jazzer")
def test_jazzer_finds_planted_bug(ws):
    write(ws, "harnesses/DemoFuzzer.java", JAVA_HARNESS)
    run = ECOSYSTEMS["java"].fuzz(ws, "harnesses/DemoFuzzer.java", 90)
    assert run.status == "crash", run.to_text()
    assert "IllegalStateException" in run.excerpt
    assert run.crash_files


@needs("jazzer")
def test_jazzer_reports_compile_errors(ws):
    write(ws, "harnesses/Broken.java", "public class Broken { int x = ; }")
    run = ECOSYSTEMS["java"].fuzz(ws, "harnesses/Broken.java", 10)
    assert run.status == "error"
    assert "javac failed" in run.excerpt


@pytest.mark.skipif(not sandbox.sandbox_active(), reason="needs root and the sandbox user")
def test_commands_run_unprivileged_without_api_key(ws, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-secret")
    result = sandbox.run("id -u; env; cat /proc/1/environ", cwd=ws.root, timeout=30)
    lines = result.output.splitlines()
    assert lines[0] != "0"
    assert "sk-test-secret" not in result.output
    assert "Permission denied" in result.output


def component(**kw):
    base = dict(group=None, purl=None, purl_type=None, download_url=None, vcs_url=None, bom_ref=None, qualifiers={})
    base.update(kw)
    return Component(**base)


def test_fetch_pypi(ws):
    detail = fetch(component(name="toml", version="0.10.2", ecosystem="python"), ws).detail
    assert "toml==0.10.2" in detail
    assert (ws.site / "toml" / "__init__.py").exists()


@needs("mvn")
def test_fetch_maven(ws):
    c = component(name="jsoup", version="1.17.2", group="org.jsoup", ecosystem="java", purl_type="maven")
    detail = fetch(c, ws).detail
    assert (ws.libs / "jsoup-1.17.2.jar").exists(), detail
    assert any(ws.sources.rglob("Jsoup.java")), detail


@needs("git")
def test_fetch_github_tag(ws):
    c = component(name="cJSON", version="v1.7.18", ecosystem="native", purl_type="github",
                  vcs_url="https://github.com/DaveGamble/cJSON")
    detail = fetch(c, ws).detail
    assert "at v1.7.18" in detail
    assert (ws.src / "cJSON.c").exists()


def test_fetch_download_url(ws):
    c = component(name="zlib", version="1.3.1", ecosystem="native", purl_type="generic",
                  download_url="https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz")
    fetch(c, ws)
    assert (ws.src / "zlib-1.3.1" / "inflate.c").exists()
