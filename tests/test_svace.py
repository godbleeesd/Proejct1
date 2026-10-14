import json
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

from sbomfuzz import cli, sandbox, svace
from sbomfuzz.fetch import FetchError, FetchResult
from sbomfuzz.svace import BuildError, captured_units, java_plan, java_release, native_plan, python_sources

FAKE = Path(__file__).parent / "fake_svace.py"


def needs(*tools):
    missing = [t for t in tools if shutil.which(t) is None]
    return pytest.mark.skipif(bool(missing), reason=f"{', '.join(missing)} not installed")


def files(root: Path, tree: dict[str, str]) -> Path:
    for name, content in tree.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


@pytest.mark.parametrize("tree, system, configure, build", [
    ({"CMakeLists.txt": "", "configure": "", "Makefile": ""}, "cmake", "cmake", "cmake --build"),
    ({"meson.build": "", "Makefile": ""}, "meson", "meson setup", "meson compile"),
    ({"configure": "", "Makefile.in": ""}, "autotools", "sh ./configure", "make -j3"),
    ({"configure.ac": "", "Makefile.am": ""}, "autotools", "autoreconf -fi && sh ./configure", "make -j3"),
    ({"Makefile": ""}, "make", None, "make -j3"),
])
def test_native_build_detection(tmp_path, tree, system, configure, build):
    plan = native_plan(files(tmp_path / "src", tree), tmp_path / "build", 3)
    assert plan.system == system and plan.cwd == tmp_path / "src"
    if configure is None:
        assert plan.configure is None
    else:
        shown = plan.configure if isinstance(plan.configure, str) else " ".join(plan.configure)
        assert shown.startswith(configure)
    assert " ".join(plan.build).startswith(build)


def test_native_plan_enters_the_tarball_directory_and_takes_overrides(tmp_path):
    src = files(tmp_path / "src", {"zlib-1.3.1/configure": "", "zlib-1.3.1/CMakeLists.txt": ""})
    plan = native_plan(src, tmp_path / "build", 2)
    assert plan.cwd == src / "zlib-1.3.1" and plan.system == "cmake"

    plan = native_plan(src, tmp_path / "build", 2, configure_cmd="./configure --static")
    assert plan.system == "cmake" and plan.configure == "./configure --static"

    plan = native_plan(src, tmp_path / "build", 2, build_cmd="make -C lib")
    assert plan.system == "custom" and plan.configure is None and plan.build == ["bash", "-c", "make -C lib"]

    with pytest.raises(BuildError, match="--build-cmd"):
        native_plan(files(tmp_path / "empty", {"README": ""}), tmp_path / "build", 2)


def test_java_plan_compiles_the_sources_jar_without_module_info(ws):
    with pytest.raises(BuildError, match="no Java sources"):
        java_plan(ws, [], ws.root / "classes")
    files(ws.sources, {"org/demo/Hello.java": "", "module-info.java": "", "META-INF/MANIFEST.MF": ""})
    plan = java_plan(ws, [ws.libs / "a.jar", ws.libs / "b.jar"], ws.root / "classes")
    assert plan.system == "javac" and plan.cwd == ws.sources
    assert plan.build[-1] == "org/demo/Hello.java" and "module-info.java" not in plan.build
    assert plan.build[plan.build.index("-cp") + 1] == f"{ws.libs / 'a.jar'}:{ws.libs / 'b.jar'}"
    assert "--release" not in plan.build

    plan = java_plan(ws, [], ws.root / "classes", release=7)  # javac no longer accepts 7
    assert plan.build[plan.build.index("--release") + 1] == "8" and "-cp" not in plan.build


def test_java_release_from_class_files(tmp_path):
    def header(major):
        return bytes.fromhex("cafebabe0000") + major.to_bytes(2, "big")

    jar = tmp_path / "lib-1.0.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr("org/demo/A.class", header(51))  # Java 7
        zf.writestr("org/demo/B.class", header(52))  # Java 8
        zf.writestr("module-info.class", header(53))
        zf.writestr("META-INF/versions/11/org/demo/A.class", header(55))
    assert java_release(jar) == 8
    (tmp_path / "broken.jar").write_text("not a zip")
    assert java_release(tmp_path / "broken.jar") is None


def test_python_sources_are_the_package_files_only(tmp_path):
    site = files(tmp_path / "site", {
        "dateutil/__init__.py": "", "dateutil/parser/_parser.py": "", "dateutil/zoneinfo/data.tar.gz": "",
        "six.py": "",
        "python_dateutil-2.8.2.dist-info/RECORD": "dateutil/__init__.py,sha256=x,1\n"
                                                  "dateutil/parser/_parser.py,sha256=x,1\n"
                                                  "dateutil/zoneinfo/data.tar.gz,sha256=x,1\n"
                                                  "../../bin/tool.py,,\n"
                                                  "python_dateutil-2.8.2.dist-info/RECORD,,\n",
        "six-1.16.0.dist-info/RECORD": "six.py,sha256=x,1\n",
    })
    assert python_sources(site, "python-dateutil") == ["dateutil/__init__.py", "dateutil/parser/_parser.py"]
    assert python_sources(site, "Six") == ["six.py"]
    assert python_sources(site, "missing") == []


def test_captured_units():
    output = "Processing source code markup data...\nAssembled build object: [BUILD]6715d4\n" \
             "  83 C/C++ units are ready.\n  1 Java unit is ready.\n"
    assert captured_units(output) == {"C/C++": 83, "Java": 1}


# --- the whole pipeline, with a fake svace and a fake download ---

PROJECTS = {
    "good": {"Makefile": "demo: a.o b.o\n\t$(CC) -o $@ a.o b.o\n",
             "a.c": "int a(void) { return 1; }\n", "b.c": "int a(void);\nint main(void) { return a() - 1; }\n"},
    # The configure step compiles a probe; only the build's compilation belongs to Svace.
    "probed": {"configure": "echo 'int main(void) { return 0; }' > probe.c && cc -c probe.c\n"
                            "printf 'all:\\n\\t$(CC) -c a.c\\n' > Makefile\n",
               "a.c": "int a(void) { return 1; }\n"},
    "broken": {"Makefile": "all:\n\t$(CC) -c broken.c\n", "broken.c": "int main(void) { return }\n"},
    "nocompiler": {"Makefile": "all:\n\techo nothing to compile\n"},
    "javademo": {"org/demo/Hello.java": "package org.demo;\npublic class Hello { int x = 1; }\n",
                 "module-info.java": "module org.demo { requires some.missing.module; }\n"},
    "toml": {"toml/__init__.py": "", "toml/decoder.py": "", "dep/__init__.py": "",
             "toml-0.10.2.dist-info/RECORD": "toml/__init__.py,,\ntoml/decoder.py,,\n",
             "dep-1.0.dist-info/RECORD": "dep/__init__.py,,\n"},
}


def fake_fetch(c, ws):
    if c.name == "unreachable":
        raise FetchError("download failed: https://example.invalid/x.tar.gz: no such host\nmore output")
    if c.ecosystem == "java":
        files(ws.sources, PROJECTS[c.name])
    elif c.ecosystem == "python":
        files(ws.site, PROJECTS[c.name])
    else:
        files(ws.src / f"{c.name}-1.0", PROJECTS[c.name])  # like a release tarball
    sandbox.give_to_sandbox(ws.root)
    return FetchResult(f"test sources of {c.name}")


def native(name):
    return {"type": "library", "name": name, "version": "1.0", "purl": f"pkg:generic/{name}@1.0",
            "externalReferences": [{"type": "distribution", "url": f"https://example.invalid/{name}-1.0.tar.gz"}]}


@pytest.fixture
def fake_svace():
    # Outside pytest's tmp_path: the sandbox user runs it.
    d = Path(tempfile.mkdtemp(prefix="fake-svace-"))
    d.chmod(0o755)
    shutil.copy(FAKE, d / "fake_svace.py")
    (d / "fake_svace.py").chmod(0o644)
    exe = d / "svace"
    exe.write_text(f'#!/bin/sh\nexec {sys.executable} {d / "fake_svace.py"} "$@"\n')
    exe.chmod(0o755)
    yield str(exe)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def workdir():
    d = Path(tempfile.mkdtemp(prefix="sbomfuzz-svace-work-"))
    d.chmod(0o755)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def svace_cli(bom: list[dict], tmp_path, fake_svace, workdir, *extra) -> tuple[int, dict]:
    sbom = tmp_path / "bom.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": bom}))
    out = tmp_path / "out"
    code = cli.main(["svace", str(sbom), "--out", str(out), "--workdir", str(workdir), "--svace", fake_svace, *extra])
    report = json.loads((out / "report.json").read_text())
    return code, {r["component"]["name"]: r for r in report["components"]}


@needs("make", "cc")
def test_pipeline_archives_the_svace_dir(tmp_path, fake_svace, workdir, monkeypatch):
    monkeypatch.setattr(svace, "fetch", fake_fetch)
    out = tmp_path / "out"
    bom = [native("good"), native("probed"), native("broken"), native("nocompiler"), native("unreachable"),
           {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}]
    code, results = svace_cli(bom, tmp_path, fake_svace, workdir, "--svace-option=--enable-ptrace")
    assert code == cli.EXIT_BUILD_FAILED

    good = results["good"]
    assert good["status"] == "built", good
    assert good["system"] == "make" and good["units"] == {"C/C++": 2}
    with tarfile.open(out / good["archive"]) as tar:
        members = {m.name: m for m in tar.getmembers()}
    assert "good-1.0/.svace-dir/bitcode/build-object" in members
    assert all(m.uid == 0 and m.uname == "" for m in members.values())
    assert "--enable-ptrace" in (out / good["log"]).read_text()

    probed = results["probed"]
    assert probed["status"] == "built" and probed["system"] == "autotools", probed
    assert probed["units"] == {"C/C++": 1}  # the configure probe ran outside Svace

    broken = results["broken"]
    assert broken["status"] == "build_failed" and broken["detail"].startswith("svace build failed (exit code")
    assert "broken.c" in broken["output"] and broken["archive"] is None
    assert not (out / broken["log"]).with_name(svace.ARCHIVE_NAME).exists()

    nocompiler = results["nocompiler"]
    assert nocompiler["status"] == "build_failed" and "captured no compilations" in nocompiler["detail"]

    unreachable = results["unreachable"]
    assert unreachable["status"] == "fetch_failed" and unreachable["output"] == "more output"
    assert results["lodash"]["status"] == "skipped"

    report = (out / "report.md").read_text()
    assert "archived: 2, failed: 3, skipped: 1" in report
    assert "### broken@1.0: build_failed" in report and "svace analyze --svace-dir" in report

    # With only buildable components selected the CI job passes.
    code, results = svace_cli([native("good")], tmp_path, fake_svace, workdir)
    assert code == 0 and results["good"]["status"] == "built"
    assert not any(workdir.iterdir())  # workspaces are removed


def test_pipeline_fails_when_nothing_is_archived(tmp_path, fake_svace, workdir, monkeypatch):
    monkeypatch.setattr(svace, "fetch", fake_fetch)
    code, results = svace_cli([native("good")], tmp_path, fake_svace, workdir, "-c", "no-such-component")
    assert code == cli.EXIT_BUILD_FAILED and results == {}


@needs("javac")
def test_pipeline_java_and_python(tmp_path, fake_svace, workdir, monkeypatch):
    monkeypatch.setattr(svace, "fetch", fake_fetch)
    bom = [{"type": "library", "group": "org.demo", "name": "javademo", "version": "1.0",
            "purl": "pkg:maven/org.demo/javademo@1.0"},
           {"type": "library", "name": "toml", "version": "0.10.2", "purl": "pkg:pypi/toml@0.10.2"}]
    code, results = svace_cli(bom, tmp_path, fake_svace, workdir)
    assert code == 0, results
    assert results["javademo"]["system"] == "javac" and results["javademo"]["units"] == {"Java": 1}
    assert results["toml"]["system"] == "python" and results["toml"]["units"] == {"Python": 2}  # not dep/


def test_missing_svace_is_a_usage_error(tmp_path, capsys):
    sbom = tmp_path / "bom.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}))
    assert cli.main(["svace", str(sbom), "--svace", str(tmp_path / "no-svace")]) == 1
    assert "Svace not found" in capsys.readouterr().err
