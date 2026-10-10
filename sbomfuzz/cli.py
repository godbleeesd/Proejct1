"""Command line: `sbomfuzz list` and `sbomfuzz run`."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

from . import __version__
from .agent import SEVERITIES, AgentConfig
from .ecosystems import ECOSYSTEMS
from .report import severity_at_least
from .sbom import SbomError, load_cyclonedx

EXIT_FINDINGS = 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sbomfuzz",
        description="AI-assisted fuzz testing of the components listed in a CycloneDX SBOM.",
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
    p_run.add_argument("-j", "--jobs", type=int, default=1, help="components fuzzed in parallel (default 1)")
    p_run.add_argument("--fuzz-seconds", type=int, default=300, help="maximum length of one fuzzer run (default 300)")
    p_run.add_argument("--max-turns", type=int, default=60, help="agent turns per component (default 60)")
    p_run.add_argument("--max-harnesses", type=int, default=3, help="harnesses per component (default 3)")
    p_run.add_argument("--model", default="claude-opus-5-5", help="Claude model (default claude-opus-5-5)")
    p_run.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"],
                       help="reasoning effort (default high)")
    p_run.add_argument("--no-fallbacks", action="store_true",
                       help="do not let the API retry declined requests on a fallback model")
    p_run.add_argument("--budget-usd", type=float, help="stop starting new work once the estimated API cost reaches this")
    p_run.add_argument("--report-language", default="English", help="language for the report's free text (default English)")
    p_run.add_argument("--fail-on", default="none", choices=["none", *reversed(SEVERITIES)],
                       help=f"exit with code {EXIT_FINDINGS} if a bug of this severity or higher is found")
    p_run.add_argument("--keep-workdirs", action="store_true", help="keep downloads and builds after each component")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    if not args.verbose:
        for noisy in ("httpx", "httpx2", "anthropic"):
            logging.getLogger(noisy).setLevel(logging.WARNING)

    try:
        if args.command == "list":
            return _list(args)
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


def _run(args) -> int:
    import anthropic

    from .runner import RunConfig, run
    from .sandbox import sandbox_active

    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        logging.warning("ANTHROPIC_API_KEY is not set; API calls will fail unless an `ant auth login` profile exists")
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
            fuzz_seconds=args.fuzz_seconds,
            max_harnesses=args.max_harnesses,
            report_language=args.report_language,
            fallbacks=not args.no_fallbacks,
        ),
        ecosystems=args.ecosystem or list(ECOSYSTEMS),
        include=args.component,
        limit=args.limit,
        jobs=args.jobs,
        budget_usd=args.budget_usd,
        keep_workdirs=args.keep_workdirs,
    )
    try:
        results, _ = run(config)
    except anthropic.AuthenticationError:
        print("error: the Anthropic API rejected the credentials; set ANTHROPIC_API_KEY", file=sys.stderr)
        return 1

    print(f"\nReport: {args.out / 'report.md'}")
    if args.fail_on != "none":
        if any(severity_at_least(f.get("severity", ""), args.fail_on) for r in results for f in r.bugs):
            return EXIT_FINDINGS
    return 0
