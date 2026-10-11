"""Run results and the JSON / Markdown reports: raw fuzzer findings, no verdicts."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .usage import Usage


@dataclass
class ComponentResult:
    component: dict
    # completed | no_harness | incomplete | skipped | fetch_failed | usage_limit | error
    status: str
    detail: str = ""
    harnesses: list[dict] = field(default_factory=list)  # accepted harness + its fuzzing result
    attempts: int = 0
    validation: list[dict] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    turns: int = 0
    duration_seconds: float = 0.0
    artifacts: str | None = None

    @property
    def crashes(self) -> list[tuple[dict, dict]]:
        return [(h, c) for h in self.harnesses for c in h.get("crashes", [])]

    def to_dict(self) -> dict:
        return {
            "component": self.component,
            "status": self.status,
            "detail": self.detail,
            "harnesses": self.harnesses,
            "generation": {"attempts": self.attempts, "turns": self.turns, "validation": self.validation},
            "usage": self.usage.to_dict(),
            "duration_seconds": round(self.duration_seconds, 1),
            "artifacts": self.artifacts,
        }


def write_json(path: Path, meta: dict, results: list[ComponentResult], total: Usage) -> None:
    data = {**meta, "usage": total.to_dict(), "components": [r.to_dict() for r in results]}
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def render_markdown(meta: dict, results: list[ComponentResult], total: Usage) -> str:
    crashes = [(r, h, c) for r in results for h, c in r.crashes]
    cost = f"${total.cost_usd:.2f}" if total.cost_usd is not None else "n/a"
    out = [
        "# SBOM fuzzing report",
        "",
        f"- SBOM: `{meta['sbom']}`",
        f"- Started: {meta['started']}, finished: {meta['finished']}",
        f"- Harnesses by Claude Code, model `{meta['model']}` (effort {meta['effort']}); "
        f"fuzzing {meta['fuzz_seconds_per_harness']}s per harness",
        f"- Components: {len(results)}, fuzzed: {sum(r.status == 'completed' for r in results)}, "
        f"unique crashes: {len(crashes)}",
        f"- Tokens: {total.input_tokens + total.cache_read_tokens + total.cache_write_tokens:,} in, "
        f"{total.output_tokens:,} out (API-equivalent {cost}, covered by the subscription)",
        "",
        "Crashes are raw fuzzer findings grouped by error type and location. They have not been "
        "triaged: some may come from harness mistakes rather than bugs in the component.",
        "",
        "## Components",
        "",
        "| Component | Ecosystem | Status | Harnesses | Executions | Unique crashes | Notes |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        c = r.component
        name = c["name"] + (f"@{c['version']}" if c.get("version") else "")
        execs = sum(h.get("executions", 0) for h in r.harnesses)
        out.append(f"| `{_cell(name)}` | {c.get('ecosystem') or '-'} | {r.status} | {len(r.harnesses)} "
                   f"| {execs:,} | {len(r.crashes)} | {_cell(_shorten(r.detail, 140))} |")

    if crashes:
        out += ["", "## Crashes", ""]
        for i, (r, h, c) in enumerate(crashes, 1):
            comp = r.component
            out += [
                f"### {i}. {c['kind']} in `{comp['name']}@{comp.get('version') or '?'}`",
                "",
                f"- Summary: {c['summary']}",
                f"- Harness: `{h['name']}` (`{h['source']}`), API: {h.get('target_api', '-')}",
                f"- Input: `{c['crash_file'] or '-'}` (hit {c['count']} time(s))",
                f"- Artifacts: `{r.artifacts or '-'}`",
                f"- Reproduce in the workspace (`--keep-workdirs`): `{c['reproduction'] or '-'}`",
                "",
                "```",
                c["stack"].rstrip(),
                "```",
                "",
            ]

    out += ["", "## Details", ""]
    for r in results:
        c = r.component
        out += [f"### {c['name']}@{c.get('version') or '?'}", "",
                f"Status: {r.status}" + (f" ({r.detail})" if r.detail else "")]
        if r.attempts:
            out.append(f"Harness generation: {r.turns} turns, {r.attempts} validation attempt(s).")
        out.append("")
        for h in r.harnesses:
            line = (f"- `{h['name']}` ({h.get('target_api', '')}): {h['status']}, {h['runs']} run(s), "
                    f"{h['executions']:,} executions in {h['fuzz_seconds']:.0f}s")
            if h.get("last_stats"):
                line += f"; last: `{h['last_stats'].strip()}`"
            out.append(line)
            if h.get("error"):
                out.append(f"  - fuzzer error: `{_shorten(h['error'], 200)}`")
        dropped = _dropped(r)
        for name, detail in dropped:
            out.append(f"- `{name}`: dropped, failed validation: {_shorten(detail, 200)}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def _dropped(r: ComponentResult) -> list[tuple[str, str]]:
    """Harnesses that failed the last validation attempt."""
    if not r.validation:
        return []
    last = r.validation[-1]
    return [(h["name"], h["detail"]) for h in last.get("harnesses", []) if not h.get("ok")]


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _shorten(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
