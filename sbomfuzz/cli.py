"""Command line.

Pipeline stages (one CI job each): `plan`, `generate`, `fuzz`, `report`; the static-analysis
stage `svace`; `run` for all fuzzing stages in one go; `list`; and the internal `mcp-server`.
"""

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
EXIT_INCOMPLETE = 5

TMP = Path(tempfile.gettempdir())


def _selection_args(p: argparse.ArgumentParser, verb: str) -> None:
    p.add_argument("-e", "--ecosystem", action="append", choices=sorted(ECOSYSTEMS),
                   help=f"only {verb} these ecosystems (repeatable; default: all)")
    p.add_argument("-c", "--component", action="append", default=[], metavar="PATTERN",
                   help=f"only {verb} components whose name or purl matches this glob (repeatable)")
    p.add_argument("--limit", type=int, help=f"{verb} at most this many components")


def _agent_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--max-harnesses", type=int, default=3, help="harnesses per component (default 3)")
    p.add_argument("--fix-attempts", type=int, default=3,
                   help="validation rounds in which Claude may fix failing harnesses (default 3)")
    p.add_argument("--max-turns", type=int, default=40, help="Claude turns per component (default 40)")
    p.add_argument("--model", help="Claude model, e.g. claude-opus-5-5 (default: your plan's default)")
    p.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"],
                   help="reasoning effort while writing harnesses (default high)")
    p.add_argument("--language", default="English", help="language for harness descriptions (default English)")


def _fuzz_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--fuzz-seconds", type=int, default=600, help="fuzzing time per harness (default 600)")
    p.add_argument("--stop-after-duplicates", type=int, default=0, metavar="N",
                   help="stop fuzzing a harness early after N restarts in a row that found only known "
                        "crashes (default 0: always use the full --fuzz-seconds)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sbomfuzz",
        description="SBOM components -> static analysis under Svace and fuzzing with harnesses written by Claude.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="show the SBOM's components and whether they can be processed")
    p_list.add_argument("sbom", type=Path)
    p_list.add_argument("--json", action="store_true", help="machine-readable output")

    p_plan = sub.add_parser("plan", help="stage 1: SBOM -> plan.json, the components to process (one job each)")
    p_plan.add_argument("sbom", type=Path)
    p_plan.add_argument("-o", "--out", type=Path, default=Path("plan.json"), help="plan file (default plan.json)")
    _selection_args(p_plan, "plan")

    p_gen = sub.add_parser("generate", help="stage 2: Claude writes validated harnesses -> one bundle per component")
    p_gen.add_argument("plan", type=Path, help="plan.json from `sbomfuzz plan`")
    p_gen.add_argument("--slug", action="append", default=[],
                       help="only this component of the plan (repeatable; default: all)")
    p_gen.add_argument("-o", "--out", type=Path, default=Path("bundles"),
                       help="directory for the bundles, one <slug>/ each (default bundles)")
    p_gen.add_argument("--workdir", type=Path, default=TMP / "sbomfuzz-work", help="scratch directory")
    p_gen.add_argument("--keep-workdirs", action="store_true", help="keep downloads and builds")
    _agent_args(p_gen)

    p_fuzz = sub.add_parser("fuzz", help="stage 3: fuzz a bundle's harnesses -> crashes and statistics")
    p_fuzz.add_argument("bundles", type=Path, nargs="+", help="bundle directories (bundles/<slug>)")
    p_fuzz.add_argument("--harness", action="append", default=[],
                        help="only this harness of the bundle (repeatable; default: all)")
    p_fuzz.add_argument("-o", "--out", type=Path, default=Path("fuzz-results"),
                        help="directory for the results, <slug>/<harness>/ each (default fuzz-results)")
    p_fuzz.add_argument("--workdir", type=Path, default=TMP / "sbomfuzz-work", help="scratch directory")
    p_fuzz.add_argument("--keep-workdirs", action="store_true", help="keep downloads and builds, e.g. to replay crashes")
    _fuzz_args(p_fuzz)

    p_rep = sub.add_parser("report", help="stage 4: plan + bundles + fuzz results -> report.md and report.json")
    p_rep.add_argument("plan", type=Path, help="plan.json from `sbomfuzz plan`")
    p_rep.add_argument("--bundles", type=Path, default=Path("bundles"), help="bundles directory (default bundles)")
    p_rep.add_argument("--fuzz", type=Path, default=Path("fuzz-results"),
                       help="fuzz results directory (default fuzz-results)")
    p_rep.add_argument("-o", "--out", type=Path, default=Path("fuzz-report"), help="output directory")
    p_rep.add_argument("--fail-on-crash", action="store_true",
                       help=f"exit with code {EXIT_CRASHES} if any crash is found")

    p_run = sub.add_parser("run", help="all fuzzing stages in one go: plan, generate, fuzz, report")
    p_run.add_argument("sbom", type=Path)
    p_run.add_argument("-o", "--out", type=Path, default=Path("sbomfuzz-results"),
                       help="output directory: plan.json, bundles/, fuzz/, report.md, report.json")
    p_run.add_argument("--workdir", type=Path, default=TMP / "sbomfuzz-work", help="scratch directory")
    _selection_args(p_run, "fuzz")
    p_run.add_argument("-j", "--jobs", type=int, default=1, help="components processed in parallel (default 1)")
    _fuzz_args(p_run)
    _agent_args(p_run)
    p_run.add_argument("--fail-on-crash", action="store_true",
                       help=f"exit with code {EXIT_CRASHES} if any crash is found (for CI/CD)")
    p_run.add_argument("--keep-workdirs", action="store_true",
                       help="keep downloads and builds, e.g. to replay crashes")

    p_svace = sub.add_parser("svace", help="static-analysis stage: build the components under Svace",
                             description="Static-analysis stage. For each component: download it, run its build "
                                         "under `svace build` (a controlled build) and pack the Svace project "
                                         "directory into <out>/components/<component>/svace-dir.tar.gz.")
    p_svace.add_argument("sbom", type=Path)
    p_svace.add_argument("-o", "--out", type=Path, default=Path("svace-results"),
                         help="directory for report.md, report.json, the archives and build logs")
    p_svace.add_argument("--workdir", type=Path, default=TMP / "sbomfuzz-svace-work",
                         help="scratch directory for downloads and builds")
    _selection_args(p_svace, "build")
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
    handlers = {"list": _list, "plan": _plan, "generate": _generate, "fuzz": _fuzz, "report": _report,
                "run": _run, "svace": _svace}
    try:
        return handlers[args.command](args)
    except SbomError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def _agent_config(args) -> AgentConfig:
    return AgentConfig(model=args.model, effort=args.effort, max_turns=args.max_turns,
                       max_harnesses=args.max_harnesses, max_attempts=args.fix_attempts, language=args.language)


def _check_claude() -> bool:
    from .sandbox import sandbox_active

    if not os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
        print("error: set CLAUDE_CODE_OAUTH_TOKEN to your Claude subscription token "
              "(create it with `claude setup-token`).", file=sys.stderr)
        return False
    if not sandbox_active():
        logging.warning("not running as root with a 'fuzzer' user: untrusted code runs as the current user. "
                        "Use the Docker image for isolation.")
    return True


def _auth_failed(e: Exception) -> int:
    print(f"error: Claude Code could not authenticate ({e}). Create a token with `claude setup-token` "
          "and pass it as CLAUDE_CODE_OAUTH_TOKEN.", file=sys.stderr)
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


def _plan(args) -> int:
    from . import stages

    plan = stages.plan(args.sbom, stages.Selection(args.ecosystem or list(ECOSYSTEMS), args.component, args.limit))
    stages.write_json(args.out, plan)
    for entry in plan["components"]:
        print(f"{entry['slug']:<60} {entry['ecosystem']}")
    print(f"\n{len(plan['components'])} to process, {len(plan['skipped'])} skipped -> {args.out}")
    return 0


def _generate(args) -> int:
    from . import stages
    from .claude_code import ClaudeCodeAuthError

    if not _check_claude():
        return 1
    plan = stages.read_json(args.plan)
    entries = [e for e in plan["components"] if not args.slug or e["slug"] in args.slug]
    unknown = set(args.slug) - {e["slug"] for e in plan["components"]}
    if unknown:
        print(f"error: not in the plan: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 1
    agent = _agent_config(args)
    statuses = []
    try:
        for entry in entries:
            c = stages.component_from(entry)
            if "usage_limit" in statuses:
                bundle = stages.skipped_bundle(c, args.out, "usage_limit",
                                               "the subscription usage limit was reached before this component")
            else:
                bundle = stages.generate(c, agent, args.out, args.workdir, args.keep_workdirs)
            statuses.append(bundle["status"])
    except ClaudeCodeAuthError as e:
        return _auth_failed(e)
    print(f"\nBundles: {args.out} ({statuses.count('ready')} of {len(entries)} ready)")
    # A usage limit means the job should be retried later rather than reported as done.
    return EXIT_INCOMPLETE if "usage_limit" in statuses else 0


def _fuzz(args) -> int:
    from . import stages

    for bundle in args.bundles:
        stages.fuzz(bundle, args.out, args.workdir, args.fuzz_seconds, args.stop_after_duplicates,
                    args.harness or None, args.keep_workdirs)
    print(f"\nFuzz results: {args.out}")
    return 0


def _report(args) -> int:
    from . import stages

    results = stages.report(stages.read_json(args.plan), args.bundles, args.fuzz, args.out)
    print(f"Report: {args.out / 'report.md'}")
    if args.fail_on_crash and any(r.crashes for r in results):
        return EXIT_CRASHES
    return 0


def _run(args) -> int:
    from .claude_code import ClaudeCodeAuthError
    from .runner import RunConfig, run

    if not _check_claude():
        return 1
    config = RunConfig(
        sbom=args.sbom,
        out=args.out,
        workdir=args.workdir,
        agent=_agent_config(args),
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
        return _auth_failed(e)
    print(f"\nReport: {args.out / 'report.md'}")
    if args.fail_on_crash and any(r.crashes for r in results):
        return EXIT_CRASHES
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
