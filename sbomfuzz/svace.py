"""Controlled builds under Svace: download each SBOM component, build it with `svace build`
and pack the Svace project directory (.svace-dir) into an archive for `svace analyze`.

Only the compilation runs under `svace build`. Configure steps (cmake, meson setup,
./configure) run before it, so their probe compilations stay out of the analysis.
"""

from __future__ import annotations

import csv
import fnmatch
import json
import logging
import os
import re
import shlex
import shutil
import tarfile
import time
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from . import sandbox, svace_report
from .fetch import DEPENDENCY_PLUGIN, FetchError, fetch
from .sbom import Component, load_cyclonedx
from .svace_report import size
from .workspace import Workspace

log = logging.getLogger(__name__)

ECOSYSTEMS = ("python", "java", "native")
SVACE_BIN = os.environ.get("SVACE_BIN", "svace")
ARCHIVE_NAME = "svace-dir.tar.gz"
LOG_NAME = "build.log"
LOG_LIMIT = 2_000_000  # characters of each command's output kept in build.log
# `svace build` exits with this status when the build succeeded but no compilation was captured.
NOTHING_CAPTURED = 255
# The oldest --release that current JDKs accept.
MIN_JAVA_RELEASE = 8
CLASS_MAGIC = bytes.fromhex("cafebabe")
_UNITS = re.compile(r"^\s*(\d+) (\S+) units? (?:is|are) ready", re.MULTILINE)


class BuildError(RuntimeError):
    """A build step failed; `output` is the tail of what it printed."""

    def __init__(self, message: str, output: str = ""):
        super().__init__(message)
        self.output = output


@dataclass
class BuildConfig:
    sbom: Path
    out: Path
    workdir: Path
    svace: str = SVACE_BIN
    svace_options: list[str] = field(default_factory=list)  # extra `svace build` options
    ecosystems: list[str] = field(default_factory=lambda: list(ECOSYSTEMS))
    include: list[str] = field(default_factory=list)  # glob patterns on name / purl
    limit: int | None = None
    configure_cmd: str | None = None  # C/C++: replaces the detected configure step
    build_cmd: str | None = None  # C/C++: replaces the detected build (and its configure step)
    build_jobs: int = field(default_factory=lambda: os.cpu_count() or 1)
    timeout: int = 3600  # per command
    keep_workdirs: bool = False


@dataclass
class BuildPlan:
    system: str  # cmake | meson | autotools | make | custom | javac | python
    cwd: Path
    configure: list[str] | str | None  # runs first, outside Svace; a string runs under bash
    build: list[str]  # runs under `svace build`
    svace_args: list[str] = field(default_factory=list)


@dataclass
class ComponentResult:
    component: dict
    status: str  # built | skipped | fetch_failed | build_failed | error
    detail: str = ""
    output: str = ""  # tail of the failed step's output
    system: str = ""
    units: dict[str, int] = field(default_factory=dict)  # captured units by language, as svace reports them
    archive: str | None = None  # relative to the output directory
    archive_bytes: int = 0
    log: str | None = None  # relative to the output directory
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {**asdict(self), "duration_seconds": round(self.duration_seconds, 1)}


def run(config: BuildConfig) -> tuple[list[ComponentResult], dict]:
    components = select(load_cyclonedx(config.sbom), config.include)
    started = datetime.now(timezone.utc)
    config.out, config.workdir = config.out.resolve(), config.workdir.resolve()
    config.out.mkdir(parents=True, exist_ok=True)
    config.workdir.mkdir(parents=True, exist_ok=True)

    todo, skipped = triage(components, config.ecosystems, config.limit)
    results: dict[str, ComponentResult] = {
        c.key: ComponentResult(c.to_dict(), "skipped", skipped[c.key]) for c in components if c.key in skipped
    }
    log.info("%d components in SBOM, %d to build under Svace", len(components), len(todo))
    for i, c in enumerate(todo, 1):
        results[c.key] = _process(c, config, f"[{i}/{len(todo)}]")

    ordered = [results[c.key] for c in components]
    meta = {
        "tool": "sbomfuzz svace",
        "sbom": str(config.sbom),
        "started": started.isoformat(timespec="seconds"),
        "finished": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "svace": config.svace,
        "svace_options": config.svace_options,
    }
    data = {**meta, "components": [r.to_dict() for r in ordered]}
    (config.out / "report.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    (config.out / "report.md").write_text(svace_report.render_markdown(meta, ordered), encoding="utf-8")
    match_owner(config.out)
    return ordered, meta


def select(components: list[Component], include: list[str]) -> list[Component]:
    """Components whose name or purl matches one of the glob patterns (all of them if none are given)."""

    def wanted(c: Component) -> bool:
        if not include:
            return True
        return any(fnmatch.fnmatch(c.name, p) or fnmatch.fnmatch(c.purl or "", p) for p in include)

    return [c for c in components if wanted(c)]


def triage(components: list[Component], ecosystems: list[str],
           limit: int | None) -> tuple[list[Component], dict[str, str]]:
    """Split components into the ones to build and the skipped ones (key -> reason)."""
    todo: list[Component] = []
    skipped: dict[str, str] = {}
    for c in components:
        reason = c.skip_reason()
        if reason is None and c.ecosystem not in ecosystems:
            reason = f"ecosystem {c.ecosystem} not selected"
        if reason is None and limit is not None and len(todo) >= limit:
            reason = "over --limit"
        if reason:
            skipped[c.key] = reason
        else:
            todo.append(c)
    return todo, skipped


def match_owner(out: Path) -> None:
    """Give results the owner of the output directory (a bind mount owned by the host user)."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    st = out.stat()
    if st.st_uid == 0:
        return
    for root, dirs, files in os.walk(out):
        os.chown(root, st.st_uid, st.st_gid)
        for name in files:
            os.chown(os.path.join(root, name), st.st_uid, st.st_gid, follow_symlinks=False)


def _process(c: Component, config: BuildConfig, tag: str) -> ComponentResult:
    result = ComponentResult(c.to_dict(), "error")
    start = time.monotonic()
    ws_root = config.workdir / c.slug
    shutil.rmtree(ws_root, ignore_errors=True)
    ws = Workspace.create(ws_root)
    artifacts = config.out / "components" / c.slug
    artifacts.mkdir(parents=True, exist_ok=True)
    archive, log_path = artifacts / ARCHIVE_NAME, artifacts / LOG_NAME
    # A failed build must not leave the archive of an earlier run behind.
    archive.unlink(missing_ok=True)
    result.log = log_path.relative_to(config.out).as_posix()
    try:
        with log_path.open("w", encoding="utf-8") as f:
            result.system, result.units = _build(c, ws, config, _Steps(f, config.timeout), archive, tag)
        result.status = "built"
        result.archive = archive.relative_to(config.out).as_posix()
        result.archive_bytes = archive.stat().st_size
        units = ", ".join(f"{n} {lang}" for lang, n in result.units.items()) or "no unit counts"
        log.info("%s %s: archived %s (%s, %s units)", tag, c.display_name, result.archive,
                 size(result.archive_bytes), units)
    except FetchError as e:
        message, _, output = str(e).partition("\n")
        result.status, result.detail, result.output = "fetch_failed", message, output
        log.warning("%s %s: download failed: %s", tag, c.display_name, message)
    except BuildError as e:
        result.status, result.detail, result.output = "build_failed", str(e), e.output
        log.warning("%s %s: %s; log: %s", tag, c.display_name, e, log_path)
    except Exception as e:
        log.exception("%s %s: failed", tag, c.display_name)
        result.status, result.detail = "error", f"{type(e).__name__}: {e}"
    finally:
        result.duration_seconds = time.monotonic() - start
        if not config.keep_workdirs:
            shutil.rmtree(ws_root, ignore_errors=True)
    return result


def _build(c: Component, ws: Workspace, config: BuildConfig, steps: _Steps, archive: Path,
           tag: str) -> tuple[str, dict[str, int]]:
    log.info("%s %s (%s): downloading", tag, c.display_name, c.ecosystem)
    try:
        steps.note(fetch(c, ws).detail)
    except FetchError as e:
        steps.note(f"download failed: {e}")
        raise
    plan = _plan(c, ws, config, steps)

    # `svace analyze` names its results after the directory that holds .svace-dir.
    project = ws.root / "svace" / project_name(c)
    project.mkdir(parents=True)
    sandbox.give_to_sandbox(project.parent)
    steps.run([config.svace, "init", str(project)], ws.root, "svace init")
    if plan.configure:
        log.info("%s %s: configuring (%s)", tag, c.display_name, plan.system)
        steps.run(plan.configure, plan.cwd, "configure")

    log.info("%s %s: svace build (%s)", tag, c.display_name, plan.system)
    built = steps.run([config.svace, "build", "--svace-dir", str(project), *config.svace_options,
                       *plan.svace_args, *plan.build], plan.cwd)
    if built.returncode == NOTHING_CAPTURED:
        raise BuildError("svace build captured no compilations (exit code 255): the build ran no compiler "
                         "Svace supports, or the build was already up to date", _tail(built.output))
    if not built.ok:
        raise BuildError(f"svace build failed ({_status(built)})", _tail(built.output))
    if not (project / ".svace-dir").is_dir():
        raise BuildError(f"svace build left no .svace-dir in {project}", _tail(built.output))
    pack(project, archive)
    return plan.system, captured_units(built.output)


def _plan(c: Component, ws: Workspace, config: BuildConfig, steps: _Steps) -> BuildPlan:
    if c.ecosystem == "native":
        return native_plan(ws.src, ws.root / "build", config.build_jobs, config.configure_cmd, config.build_cmd)
    if c.ecosystem == "java":
        jar = next(ws.libs.glob(f"{c.name}-{c.version}*.jar"), None)
        release = java_release(jar) if jar else None
        return java_plan(ws, java_classpath(c, ws, steps), ws.root / "classes", release)
    if c.ecosystem == "python":
        return python_plan(ws, c.name, ws.root / "python-src")
    raise BuildError(f"no Svace build for ecosystem {c.ecosystem}")


def project_name(c: Component) -> str:
    base = f"{c.name}-{c.version}" if c.version else c.name
    return re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._") or "component"


def source_root(src: Path) -> Path:
    """Release tarballs unpack into one top-level directory: build from inside it."""
    entries = list(src.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return src


def native_plan(src: Path, build_dir: Path, jobs: int, configure_cmd: str | None = None,
                build_cmd: str | None = None) -> BuildPlan:
    """Pick the configure step and build command from the build files in the source root.
    `build_cmd` replaces the detection; `configure_cmd` replaces just the configure step."""
    root = source_root(src)
    if build_cmd:
        system, configure, build = "custom", None, ["bash", "-c", build_cmd]
    else:
        detected = _detect_native(root, build_dir, jobs)
        if detected is None:
            raise BuildError("found no CMakeLists.txt, meson.build, configure script or Makefile in the sources; "
                             "pass --build-cmd")
        system, configure, build = detected
    return BuildPlan(system, root, configure_cmd or configure, build)


def _detect_native(root: Path, build_dir: Path, jobs: int) -> tuple[str, list[str] | str | None, list[str]] | None:
    if (root / "CMakeLists.txt").is_file():
        generator = ["-G", "Ninja"] if shutil.which("ninja") else []
        return ("cmake", ["cmake", "-S", ".", "-B", str(build_dir), *generator],
                ["cmake", "--build", str(build_dir), "--parallel", str(jobs)])
    if (root / "meson.build").is_file():
        return ("meson", ["meson", "setup", str(build_dir)],
                ["meson", "compile", "-C", str(build_dir), "-j", str(jobs)])
    make = ["make", f"-j{jobs}"]
    if (root / "configure").is_file():
        return "autotools", ["sh", "./configure"], make
    if (root / "configure.ac").is_file() or (root / "configure.in").is_file():
        return "autotools", "autoreconf -fi && sh ./configure", make
    if any((root / name).is_file() for name in ("GNUmakefile", "makefile", "Makefile")):
        return "make", None, make
    return None


def java_classpath(c: Component, ws: Workspace, steps: _Steps) -> list[Path]:
    """The runtime jars from the download plus what only compilation needs: the artifact's
    provided and optional dependencies (annotations, optional codecs), resolved from its own
    POM. Best effort: if Maven cannot resolve them, javac gets the runtime jars only."""
    jars = sorted(ws.libs.glob("*.jar"))
    fetch_pom = ws.root / "pom.xml"
    if not fetch_pom.is_file():
        return jars
    pom_dir, extra_dir = ws.root / "artifact-pom", ws.root / "compile-libs"
    pom_dir.mkdir(exist_ok=True)
    sandbox.give_to_sandbox(pom_dir)
    coords = f"{c.group}:{c.name}:{c.version}"
    got = steps.run(["mvn", "-B", "-q", "-f", str(fetch_pom), f"{DEPENDENCY_PLUGIN}:copy",
                     f"-Dartifact={coords}:pom", f"-DoutputDirectory={pom_dir}"], ws.root)
    pom = next(pom_dir.glob("*.pom"), None)
    if got.ok and pom is not None:
        # "compile" scope: compile, provided and system dependencies, including optional ones.
        steps.run(["mvn", "-B", "-q", "-f", str(pom), f"{DEPENDENCY_PLUGIN}:copy-dependencies",
                   "-DincludeScope=compile", f"-DoutputDirectory={extra_dir}"], ws.root)
    have = {j.name for j in jars}
    return jars + sorted(j for j in extra_dir.glob("*.jar") if j.name not in have)


def java_plan(ws: Workspace, classpath: list[Path], classes: Path, release: int | None = None) -> BuildPlan:
    """Compile the published sources jar with javac, whose runs Svace captures. `release` is the Java
    version the artifact was built for: its JDK API may differ from the current one (e.g. Pack200,
    removed in Java 14)."""
    sources: list[str] = []
    if ws.sources.is_dir():
        # A module descriptor needs its dependencies on the module path, not the classpath.
        sources = sorted(p.relative_to(ws.sources).as_posix() for p in ws.sources.rglob("*.java")
                         if p.name != "module-info.java")
    if not sources:
        raise BuildError("no Java sources: the artifact publishes no sources jar, or it has no .java files")
    command = ["javac", "-d", str(classes), "-encoding", "UTF-8", "-proc:none", "-nowarn"]
    if release:
        command += ["--release", str(max(release, MIN_JAVA_RELEASE))]
    if classpath:
        command += ["-cp", ":".join(str(j) for j in classpath)]
    return BuildPlan("javac", ws.sources, None, command + sources)


def java_release(jar: Path) -> int | None:
    """The Java release a jar's classes were compiled for, from the class file major version."""
    majors = []
    try:
        with zipfile.ZipFile(jar) as zf:
            for name in zf.namelist():
                # Multi-release classes and module descriptors may target a newer release than the rest.
                if not name.endswith(".class") or name.startswith("META-INF/") or name.endswith("module-info.class"):
                    continue
                with zf.open(name) as f:
                    header = f.read(8)
                if header[:4] == CLASS_MAGIC:
                    majors.append(int.from_bytes(header[6:8], "big"))
    except (OSError, zipfile.BadZipFile):
        return None
    return max(majors) - 44 if majors else None  # major 52 is Java 8


def python_plan(ws: Workspace, name: str, dest: Path) -> BuildPlan:
    """Copy the package's own modules (not its dependencies) out of site/ for `svace build --python`."""
    files = python_sources(ws.site, name)
    if not files:
        raise BuildError(f"found no Python sources of {name} in site/ (no dist-info RECORD lists .py files)")
    for relative in files:
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ws.site / relative, target)
    sandbox.give_to_sandbox(dest)
    return BuildPlan("python", ws.root, None, [], ["--python", str(dest)])


def python_sources(site: Path, name: str) -> list[str]:
    """The .py files the distribution itself installed, from its dist-info RECORD."""
    site = site.resolve()
    wanted = _normalize(name)
    for info in site.glob("*.dist-info"):
        if _normalize(info.name.removesuffix(".dist-info").rsplit("-", 1)[0]) != wanted:
            continue
        record = info / "RECORD"
        if not record.is_file():
            return []
        files = set()
        for row in csv.reader(record.read_text(encoding="utf-8", errors="replace").splitlines()):
            if not row or not row[0].endswith(".py"):
                continue
            path = (site / row[0]).resolve()
            if site in path.parents and path.is_file():  # skips scripts installed outside site/
                files.add(path.relative_to(site).as_posix())
        return sorted(files)
    return []


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def captured_units(output: str) -> dict[str, int]:
    """The "83 C/C++ units are ready." lines of svace build, by language."""
    return {language: int(n) for n, language in _UNITS.findall(output)}


def pack(project: Path, archive: Path) -> None:
    """Archive <project>/.svace-dir; unpacked, it is analyzed with `svace analyze --svace-dir <project>`."""

    def anonymous(info: tarfile.TarInfo) -> tarfile.TarInfo:
        # Files belong to the sandbox user; whoever unpacks the archive should own them.
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        return info

    partial = archive.with_name(archive.name + ".part")
    with tarfile.open(partial, "w:gz") as tar:
        tar.add(project / ".svace-dir", arcname=f"{project.name}/.svace-dir", filter=anonymous)
    partial.replace(archive)


class _Steps:
    """Runs the build's commands in the sandbox and writes each with its output to build.log."""

    def __init__(self, file: TextIO, timeout: int):
        self.file = file
        self.timeout = timeout

    def note(self, text: str) -> None:
        self.file.write(f"# {text.rstrip()}\n\n")
        self.file.flush()

    def run(self, command: list[str] | str, cwd: Path, what: str | None = None) -> sandbox.CommandResult:
        """Run a command; if `what` names the step, a failure raises BuildError."""
        shown = command if isinstance(command, str) else shlex.join(command)
        self.file.write(f"$ cd {shlex.quote(str(cwd))} && {shown}\n")
        self.file.flush()
        result = sandbox.run(command, cwd=cwd, timeout=self.timeout, output_limit=LOG_LIMIT)
        if result.output.strip():
            self.file.write(result.output.rstrip() + "\n")
        self.file.write(f"[{_status(result)}, {result.duration:.0f}s]\n\n")
        self.file.flush()
        if what is not None and not result.ok:
            raise BuildError(f"{what} failed ({_status(result)})", _tail(result.output))
        return result


def _status(result: sandbox.CommandResult) -> str:
    return "timed out" if result.timed_out else f"exit code {result.returncode}"


def _tail(output: str, lines: int = 40) -> str:
    return "\n".join(output.rstrip().splitlines()[-lines:])


