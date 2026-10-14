"""Command line: `sbomfuzz list`, `sbomfuzz run`, `sbomfuzz svace` (and the internal `sbomfuzz mcp-server`)."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

from . import __version__
from .ecosystems import ECOSYSTEMS
from .prompts import AgentConfig
from .sbom import SbomError, load_cyclonedx

EXIT_CRASHES = 3
EXIT_BUILD_FAILED = 4


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sbomfuzz",
        description="Fuzz the components of a CycloneDX SBOM: Claude writes the harnesses, the fuzzers do the rest.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="show the SBOM's components and whether they can be fuzzed")
    p_list.add_argument("sbom", type=Path)
    p_list.add_argument("--json", action="store_true", help="machine-readable output")

    p_run = sub.add_parser("run", help="fuzz the SBOM's components")
    p_run.add_argument("sbom", type=Path)
    p_run.add_argument("-o", "--out", type=Path, default=Path("sbomfuzz-results"),
                       help="directory for report.md, report.json and per-component artifacts")
    p_run.add_argument("--workdir", type=Path, default=Path(tempfile.gettempdir()) / "sbomfuzz-work",
                       help="scratch directory for downloads and builds")
    p_run.add_argument("-e", "--ecosystem", action="append", choices=sorted(ECOSYSTEMS),
                       help="only fuzz these ecosystems (repeatable; default: all)")
    p_run.add_argument("-c", "--component", action="append", default=[], metavar="PATTERN",
                       help="only fuzz components whose name or purl matches this glob (repeatable)")
    p_run.add_argument("--limit", type=int, help="fuzz at most this many components")
    p_run.add_argument("-j", "--jobs", type=int, default=1, help="components processed in parallel (default 1)")
    p_run.add_argument("--fuzz-seconds", type=int, default=600, help="fuzzing time per harness (default 600)")
    p_run.add_argument("--stop-after-duplicates", type=int, default=0, metavar="N",
                       help="stop fuzzing a harness early after N restarts in a row that found only known "
                            "crashes (default 0: always use the full --fuzz-seconds)")
    p_run.add_argument("--max-harnesses", type=int, default=3, help="harnesses per component (default 3)")
    p_run.add_argument("--fix-attempts", type=int, default=3,
                       help="validation rounds in which Claude may fix failing harnesses (default 3)")
    p_run.add_argument("--max-turns", type=int, default=40, help="Claude turns per component (default 40)")
    p_run.add_argument("--model", help="Claude model, e.g. claude-opus-5-5 (default: your plan's default)")
    p_run.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"],
                       help="reasoning effort while writing harnesses (default high)")
    p_run.add_argument("--language", default="English", help="language for harness descriptions (default English)")
    p_run.add_argument("--fail-on-crash", action="store_true",
                       help=f"exit with code {EXIT_CRASHES} if any crash is found (for CI/CD)")
    p_run.add_argument("--keep-workdirs", action="store_true",
                       help="keep downloads and builds, e.g. to replay crashes")

    p_svace = sub.add_parser("svace", help="build the SBOM's components under Svace and archive each .svace-dir",
                             description="Static-analysis stage. For each component: download it, run its build "
                                         "under `svace build` (a controlled build) and pack the Svace project "
                                         "directory into <out>/components/<component>/svace-dir.tar.gz.")
    p_svace.add_argument("sbom", type=Path)
    p_svace.add_argument("-o", "--out", type=Path, default=Path("svace-results"),
                         help="directory for report.md, report.json, the archives and build logs")
    p_svace.add_argument("--workdir", type=Path, default=Path(tempfile.gettempdir()) / "sbomfuzz-svace-work",
                         help="scratch directory for downloads and builds")
    p_svace.add_argument("-e", "--ecosystem", action="append", choices=sorted(ECOSYSTEMS),
                         help="only build these ecosystems (repeatable; default: all)")
    p_svace.add_argument("-c", "--component", action="append", default=[], metavar="PATTERN",
                         help="only build components whose name or purl matches this glob (repeatable)")
    p_svace.add_argument("--limit", type=int, help="build at most this many components")
    p_svace.add_argument("--svace", default=None,
                         help="the svace executable (default: $SVACE_BIN, else svace on PATH)")
    p_svace.add_argument("--svace-option", action="append", default=[], metavar="OPTION",
                         help="extra option for `svace build`, e.g. --svace-option=--enable-ptrace (repeatable)")
    p_svace.add_argument("--configure-cmd",
                         help="C/C++: shell command run in the source root before the build, outside Svace "
                              "(replaces the detected configure step)")
    p_svace.add_argument("--build-cmd",
                         help="C/C++: shell command run under `svace build` in the source root "
                              "(replaces the detected build system)")
    p_svace.add_argument("--build-jobs", type=int, default=os.cpu_count() or 1,
                         help="parallel jobs for make / ninja (default: CPU count)")
    p_svace.add_argument("--timeout", type=int, default=3600, help="time limit per build command (default 3600s)")
    p_svace.add_argument("--keep-workdirs", action="store_true", help="keep downloads and builds")

    # Started by Claude Code; not meant to be run by hand.
    p_mcp = sub.add_parser("mcp-server")
    p_mcp.add_argument("config", type=Path)

    args = parser.parse_args(argv)
    if args.command == "mcp-server":
        from .mcp_server import serve

        serve(args.config)  # stdout carries the MCP protocol: no logging setup here
        return 0

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    try:
        if args.command == "list":
            return _list(args)
        if args.command == "svace":
            return _svace(args)
        return _run(args)
    except SbomError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def _list(args) -> int:
    components = load_cyclonedx(args.sbom)
    if args.json:
        rows = [{**c.to_dict(), "skip_reason": c.skip_reason()} for c in components]
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    for c in components:
        reason = c.skip_reason()
        status = "fuzzable" if reason is None else f"skip: {reason}"
        print(f"{c.display_name:<50} {c.ecosystem or '-':<8} {status}")
    fuzzable = sum(c.skip_reason() is None for c in components)
    print(f"\n{len(components)} components, {fuzzable} fuzzable")
    return 0


def _svace(args) -> int:
    import shutil

    from .sandbox import sandbox_active
    from .svace import SVACE_BIN, BuildConfig, run

    svace_bin = args.svace or SVACE_BIN
    if shutil.which(svace_bin) is None:
        print(f"error: Svace not found ({svace_bin}). Put the bin/ directory of the Svace distribution on PATH, "
              "set SVACE_BIN or pass --svace; with Docker, mount the distribution at /opt/svace.", file=sys.stderr)
        return 1
    if not sandbox_active():
        logging.warning("not running as root with a 'fuzzer' user: builds run as the current user. "
                        "Use the Docker image for isolation.")
    results, _ = run(BuildConfig(
        sbom=args.sbom,
        out=args.out,
        workdir=args.workdir,
        svace=svace_bin,
        svace_options=args.svace_option,
        ecosystems=args.ecosystem or list(ECOSYSTEMS),
        include=args.component,
        limit=args.limit,
        configure_cmd=args.configure_cmd,
        build_cmd=args.build_cmd,
        build_jobs=args.build_jobs,
        timeout=args.timeout,
        keep_workdirs=args.keep_workdirs,
    ))

    archives = [r.archive for r in results if r.archive]
    print(f"\nReport: {args.out / 'report.md'}")
    for archive in archives:
        print(f"Archive: {args.out / archive}")
    # CI gate: every selected component must yield an archive, and at least one must.
    if not archives or any(r.status not in ("built", "skipped") for r in results):
        return EXIT_BUILD_FAILED
    return 0


def _run(args) -> int:
    from .claude_code import ClaudeCodeAuthError
    from .runner import RunConfig, run
    from .sandbox import sandbox_active

    if not os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
        print("error: set CLAUDE_CODE_OAUTH_TOKEN to your Claude subscription token "
              "(create it with `claude setup-token`).", file=sys.stderr)
        return 1
    if not sandbox_active():
        logging.warning("not running as root with a 'fuzzer' user: untrusted code runs as the current user. "
                        "Use the Docker image for isolation.")
    config = RunConfig(
        sbom=args.sbom,
        out=args.out,
        workdir=args.workdir,
        agent=AgentConfig(
            model=args.model,
            effort=args.effort,
            max_turns=args.max_turns,
            max_harnesses=args.max_harnesses,
            max_attempts=args.fix_attempts,
            language=args.language,
        ),
        fuzz_seconds=args.fuzz_seconds,
        stop_after_duplicates=args.stop_after_duplicates,
        ecosystems=args.ecosystem or list(ECOSYSTEMS),
        include=args.component,
        limit=args.limit,
        jobs=args.jobs,
        keep_workdirs=args.keep_workdirs,
    )
    try:
        results, _ = run(config)
    except ClaudeCodeAuthError as e:
        print(f"error: Claude Code could not authenticate ({e}). Create a token with `claude setup-token` "
              "and pass it as CLAUDE_CODE_OAUTH_TOKEN.", file=sys.stderr)
        return 1

    print(f"\nReport: {args.out / 'report.md'}")
    if args.fail_on_crash and any(r.crashes for r in results):
        return EXIT_CRASHES
    return 0
