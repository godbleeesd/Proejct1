"""Run results and the JSON / Markdown reports written at the end."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .usage import Usage

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
BUG_VERDICTS = ("confirmed_bug", "likely_bug")


@dataclass
class ComponentResult:
    component: dict
    status: str  # completed | incomplete | skipped | fetch_failed | refused | api_error | budget_exhausted | error
    detail: str = ""
    report: dict | None = None
    usage: Usage = field(default_factory=Usage)
    turns: int = 0
    duration_seconds: float = 0.0
    fuzz_runs: list[dict] = field(default_factory=list)
    artifacts: str | None = None

    @property
    def bugs(self) -> list[dict]:
        if not self.report:
            return []
        return [f for f in self.report.get("findings", []) if f.get("verdict") in BUG_VERDICTS]

    def to_dict(self) -> dict:
        return {
            "component": self.component,
            "status": self.status,
            "detail": self.detail,
            "report": self.report,
            "usage": self.usage.to_dict(),
            "turns": self.turns,
            "duration_seconds": round(self.duration_seconds, 1),
            "fuzz_runs": self.fuzz_runs,
            "artifacts": self.artifacts,
        }


def severity_at_least(severity: str, threshold: str) -> bool:
    if severity not in SEVERITY_ORDER or threshold not in SEVERITY_ORDER:
        return False
    return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(threshold)


def write_json(path: Path, meta: dict, results: list[ComponentResult], total: Usage) -> None:
    data = {**meta, "usage": total.to_dict(), "components": [r.to_dict() for r in results]}
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def render_markdown(meta: dict, results: list[ComponentResult], total: Usage) -> str:
    bugs = [(r, f) for r in results for f in r.bugs]
    cost = f"${total.cost_usd:.2f}" if total.cost_usd is not None else "n/a"
    out = [
        "# SBOM fuzzing report",
        "",
        f"- SBOM: `{meta['sbom']}`",
        f"- Started: {meta['started']}, finished: {meta['finished']}",
        f"- Model: `{meta['model']}` (effort {meta['effort']})",
        f"- Components: {len(results)}, fuzzed: {sum(r.status == 'completed' for r in results)}, "
        f"bugs found: {len(bugs)}",
        f"- Tokens: {total.input_tokens + total.cache_read_tokens + total.cache_write_tokens:,} in, "
        f"{total.output_tokens:,} out; estimated cost {cost}",
        "",
        "## Components",
        "",
        "| Component | Ecosystem | Status | Bugs | Fuzz runs | Notes |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        c = r.component
        name = c["name"] + (f"@{c['version']}" if c.get("version") else "")
        note = (r.report or {}).get("summary") or r.detail
        out.append(f"| `{_cell(name)}` | {c.get('ecosystem') or '-'} | {r.status} | {len(r.bugs)} "
                   f"| {len(r.fuzz_runs)} | {_cell(_shorten(note, 160))} |")

    if bugs:
        out += ["", "## Bugs", ""]
        bugs.sort(key=lambda rf: _severity_rank(rf[1].get("severity")), reverse=True)
        for r, f in bugs:
            c = r.component
            out += [
                f"### [{f.get('severity', '?').upper()}] {f.get('title', 'Untitled')}",
                "",
                f"- Component: `{c['name']}@{c.get('version') or '?'}` (`{c.get('purl') or '-'}`)",
                f"- Verdict: {f.get('verdict')}",
                f"- Harness: `{f.get('harness') or '-'}`, crash input: `{f.get('crash_file') or '-'}`",
                f"- Artifacts: `{r.artifacts or '-'}`",
                "",
                f.get("description", "").strip(),
                "",
                "Reproduction:",
                "",
                "```",
                f.get("reproduction", "").strip(),
                "```",
                "",
            ]

    out += ["", "## Details", ""]
    for r in results:
        c = r.component
        out += [f"### {c['name']}@{c.get('version') or '?'}", "", f"Status: {r.status}"
                + (f" ({r.detail})" if r.detail else ""), ""]
        if not r.report:
            continue
        out += [r.report.get("summary", "").strip(), ""]
        for h in r.report.get("harnesses", []):
            out.append(f"- `{h.get('path')}` -> {h.get('target_api')}: {h.get('outcome')}. {h.get('notes', '')}")
        others = [f for f in r.report.get("findings", []) if f.get("verdict") not in BUG_VERDICTS]
        for f in others:
            out.append(f"- Not a bug ({f.get('verdict')}): {f.get('title')}")
        if r.report.get("limitations"):
            out += ["", f"Limitations: {r.report['limitations'].strip()}"]
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def _severity_rank(severity: str | None) -> int:
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _shorten(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
