"""Runs the real toolchains. Meant for the Docker image (CI runs them there)."""

import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

from sbomfuzz import campaign, claude_code, sandbox
from sbomfuzz.campaign import run_campaign
from sbomfuzz.ecosystems import ECOSYSTEMS
from sbomfuzz.fetch import fetch
from sbomfuzz.sbom import Component

pytestmark = pytest.mark.integration


def needs(tool):
    return pytest.mark.skipif(shutil.which(tool) is None, reason=f"{tool} not installed")


def write(ws, relative, content):
    path = ws.root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    sandbox.give_to_sandbox(path.parent)


def seeds(ws, name, *contents):
    paths = []
    for i, content in enumerate(contents, 1):
        write(ws, f"corpus/{name}/seed-{i}", content)
        paths.append(ws.root / f"corpus/{name}/seed-{i}")
    return paths


PY_TWO_BUGS = """\
import sys
import atheris

def TestOneInput(data):
    if data[:1] == b"B":
        raise RuntimeError("first planted bug")
    if data[:1] == b"C":
        raise ValueError("second planted bug")

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

BUILD_SH = "set -e\nmkdir -p out\nclang -g -O1 -fsanitize=fuzzer,address,undefined harnesses/fuzz_demo.c -o out/fuzz_demo\n"

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


def test_python_validation_and_campaign(ws):
    pytest.importorskip("atheris")
    py = ECOSYSTEMS["python"]
    write(ws, "harnesses/fuzz_demo.py", PY_TWO_BUGS)

    ok, text = py.validate(ws, "harnesses/fuzz_demo.py", seeds(ws, "demo", "a", "x", "zz"))
    assert ok, text
    ok, text = py.validate(ws, "harnesses/fuzz_demo.py", seeds(ws, "demo", "a", "Boom", "zz"))
    assert not ok and "first planted bug" in text  # a crashing seed fails validation
    seeds(ws, "demo", "a", "x", "zz")

    # Each restart hits one of the two bugs at random; allow enough repeats to see both.
    result = run_campaign(ws, py, "demo", "harnesses/fuzz_demo.py", 60, stop_after_duplicates=30)
    kinds = sorted(c.kind for c in result.crashes)
    assert kinds == ["RuntimeError", "ValueError"], result.to_dict()  # fuzzing continued past the first crash
    assert result.status == "crashes" and result.runs >= 2
    # Inputs that only rediscovered a known crash were deleted: one file per unique crash.
    assert len(list(ws.crashes.glob("crash-*"))) == 2
    assert sum(c.count for c in result.crashes) >= result.runs - 1  # every run but maybe a short last one crashed
    crash = result.crashes[0]
    assert crash.crash_file.startswith("crashes/") and crash.reproduction.startswith("PYTHONPATH=site python3 ")
    replay = sandbox.run(crash.reproduction, cwd=ws.root, timeout=60)
    assert "planted bug" in replay.output


@needs("clang")
def test_native_build_validation_and_campaign(ws):
    native = ECOSYSTEMS["native"]
    write(ws, "harnesses/fuzz_demo.c", C_HARNESS)
    assert "does not exist" in native.build(ws)
    write(ws, "harnesses/build.sh", BUILD_SH)
    assert native.build(ws) is None

    ok, text = native.validate(ws, "out/fuzz_demo", seeds(ws, "demo", "a", "x", "zz"))
    assert ok, text
    started = time.monotonic()
    result = run_campaign(ws, native, "demo", "out/fuzz_demo", 15)
    assert [c.kind for c in result.crashes] == ["heap-buffer-overflow"], result.to_dict()
    assert "LLVMFuzzerTestOneInput" in result.crashes[0].signature
    # By default the campaign keeps restarting for the whole budget despite the recurring crash.
    assert result.runs > 1 and result.crashes[0].count == result.runs
    assert time.monotonic() - started >= 15 - campaign.MIN_RUN_SECONDS
    assert len(list(ws.crashes.glob("crash-*"))) == 1

    seeds(ws, "demo2", "a", "x", "zz")
    early = run_campaign(ws, native, "demo2", "out/fuzz_demo", 60, stop_after_duplicates=2)
    assert early.runs == 3  # one new crash, then two duplicates


@needs("clang")
def test_native_clean_campaign(ws):
    native = ECOSYSTEMS["native"]
    write(ws, "harnesses/fuzz_demo.c", "#include <stdint.h>\n#include <stddef.h>\n"
          "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }\n")
    write(ws, "harnesses/build.sh", BUILD_SH)
    assert native.build(ws) is None
    seeds(ws, "demo", "a", "b", "c")
    result = run_campaign(ws, native, "demo", "out/fuzz_demo", 6)
    assert result.status == "clean" and result.runs == 1 and result.executions > 0, result.to_dict()


@needs("jazzer")
def test_java_validation_and_campaign(ws):
    java = ECOSYSTEMS["java"]
    write(ws, "harnesses/Broken.java", "public class Broken { int x = ; }")
    ok, text = java.validate(ws, "harnesses/Broken.java", seeds(ws, "broken", "a", "b", "c"))
    assert not ok and "javac failed" in text

    write(ws, "harnesses/DemoFuzzer.java", JAVA_HARNESS)
    ok, text = java.validate(ws, "harnesses/DemoFuzzer.java", seeds(ws, "demo", "a", "x", "z"))
    assert ok, text
    result = run_campaign(ws, java, "demo", "harnesses/DemoFuzzer.java", 60, stop_after_duplicates=2)
    assert [c.kind for c in result.crashes] == ["java.lang.IllegalStateException"], result.to_dict()


@pytest.mark.skipif(not sandbox.sandbox_active(), reason="needs root and the sandbox user")
def test_commands_run_unprivileged_without_api_key(ws, monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-test-secret")
    result = sandbox.run("id -u; env; cat /proc/1/environ", cwd=ws.root, timeout=30)
    assert result.output.splitlines()[0] != "0"
    assert "sk-test-secret" not in result.output
    assert "Permission denied" in result.output


def test_full_pipeline(monkeypatch, tmp_path):
    """SBOM -> fetch from PyPI -> (fake) Claude writes and fixes a harness -> fuzzing -> report."""
    pytest.importorskip("atheris")
    from sbomfuzz.prompts import AgentConfig
    from sbomfuzz.runner import RunConfig, run

    monkeypatch.setattr(claude_code, "CLAUDE_CMD", [sys.executable, str(Path(__file__).parent / "fake_claude.py")])
    monkeypatch.setenv("FAKE_CLAUDE_LOG", str(tmp_path / "fake.log"))
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-secret")
    sbom = tmp_path / "bom.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"type": "library", "name": "toml", "version": "0.10.2", "purl": "pkg:pypi/toml@0.10.2"},
        {"type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"}]}))
    work = Path(tempfile.mkdtemp(prefix="sbomfuzz-work-"))
    work.chmod(0o755)
    out = tmp_path / "out"
    # Leftovers from an earlier run with the same --out must not end up in this report.
    from sbomfuzz.sbom import load_cyclonedx
    slug = load_cyclonedx(sbom)[0].slug
    stale = out / "fuzz" / slug / "demo" / "crashes" / "crash-stale"
    stale.parent.mkdir(parents=True)
    stale.write_text("old")
    try:
        results, _ = run(RunConfig(sbom=sbom, out=out, workdir=work, agent=AgentConfig(), fuzz_seconds=20))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    toml_result, npm_result = results
    assert npm_result.status == "skipped"
    assert toml_result.status == "completed", toml_result.detail
    assert [c["kind"] for c in toml_result.crashes] == ["RuntimeError"]
    report = (out / "report.md").read_text()
    assert "unique crashes: 1" in report and "RuntimeError in `toml@0.10.2`" in report

    # The bundle holds what the fuzz stage needs to rebuild the harness elsewhere.
    bundle = out / "bundles" / slug
    assert (bundle / "workspace" / "harnesses" / "fuzz_demo.py").exists()
    assert sorted(p.name for p in (bundle / "workspace" / "corpus" / "demo").iterdir()) == \
        ["seed-1", "seed-2", "seed-3"]
    assert json.loads((bundle / "bundle.json").read_text())["status"] == "ready"
    assert (out / "plan.json").exists()
    fuzzed = out / "fuzz" / slug / "demo"
    assert not stale.exists()
    assert len(list((fuzzed / "crashes").glob("crash-*"))) == 1  # duplicates of the one crash were dropped
    assert toml_result.crashes[0]["artifacts"] == f"fuzz/{slug}/demo"


def test_pipeline_as_separate_ci_stages(monkeypatch, tmp_path):
    """plan -> generate -> fuzz -> report as separate commands, the way CI jobs run them: the fuzz
    stage gets only the bundle and rebuilds everything in a fresh workspace."""
    pytest.importorskip("atheris")
    from sbomfuzz import cli

    monkeypatch.setattr(claude_code, "CLAUDE_CMD", [sys.executable, str(Path(__file__).parent / "fake_claude.py")])
    monkeypatch.setenv("FAKE_CLAUDE_LOG", str(tmp_path / "fake.log"))
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-secret")
    monkeypatch.chdir(tmp_path)
    Path("bom.json").write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"type": "library", "name": "toml", "version": "0.10.2", "purl": "pkg:pypi/toml@0.10.2"},
        {"type": "library", "name": "xmltodict", "version": "0.12.0", "purl": "pkg:pypi/xmltodict@0.12.0"},
        {"type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"}]}))
    work = Path(tempfile.mkdtemp(prefix="sbomfuzz-work-"))
    work.chmod(0o755)
    try:
        assert cli.main(["plan", "bom.json", "-o", "plan.json"]) == 0
        plan = json.loads(Path("plan.json").read_text())
        assert [e["component"]["name"] for e in plan["components"]] == ["toml", "xmltodict"]
        assert plan["skipped"][0]["reason"] == "unsupported ecosystem (npm)"
        toml_slug = plan["components"][0]["slug"]

        # One generate job for toml only; xmltodict's job never ran.
        assert cli.main(["generate", "plan.json", "--slug", toml_slug, "-o", "bundles", "--workdir", str(work)]) == 0
        assert cli.main(["generate", "plan.json", "--slug", "no-such-slug", "--workdir", str(work)]) == 1
        assert not any(work.iterdir())  # generate cleaned up its workspace

        assert cli.main(["fuzz", f"bundles/{toml_slug}", "--harness", "demo", "-o", "fuzz-results",
                         "--workdir", str(work), "--fuzz-seconds", "10", "--stop-after-duplicates", "2"]) == 0
        result = json.loads(Path(f"fuzz-results/{toml_slug}/demo/result.json").read_text())
        assert result["result"]["status"] == "crashes", result

        assert cli.main(["report", "plan.json", "--bundles", "bundles", "--fuzz", "fuzz-results",
                         "-o", "fuzz-report", "--fail-on-crash"]) == cli.EXIT_CRASHES
    finally:
        shutil.rmtree(work, ignore_errors=True)
    data = json.loads(Path("fuzz-report/report.json").read_text())
    statuses = {c["component"]["name"]: c["status"] for c in data["components"]}
    assert statuses == {"toml": "completed", "xmltodict": "missing", "left-pad": "skipped"}
    report = Path("fuzz-report/report.md").read_text()
    assert "RuntimeError in `toml@0.10.2`" in report
    assert f"`../fuzz-results/{toml_slug}/demo`" in report


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
