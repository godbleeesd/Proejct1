"""report.md: what was built, what Svace captured, where the archives are and why builds failed."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .svace import ComponentResult


def render_markdown(meta: dict, results: list[ComponentResult]) -> str:
    built = [r for r in results if r.status == "built"]
    failed = [r for r in results if r.status not in ("built", "skipped")]
    options = " ".join(meta["svace_options"])
    out = [
        "# Svace build report",
        "",
        f"- SBOM: `{meta['sbom']}`",
        f"- Started: {meta['started']}, finished: {meta['finished']}",
        f"- Svace: `{meta['svace']}`" + (f", `svace build` options: `{options}`" if options else ""),
        f"- Components: {len(results)}, archived: {len(built)}, failed: {len(failed)}, "
        f"skipped: {len(results) - len(built) - len(failed)}",
        "",
        "Each archive holds `<project>/.svace-dir` from a controlled build (`svace build`). To analyze one: "
        "`tar -xzf svace-dir.tar.gz && svace analyze --svace-dir <project>`.",
        "",
        "## Components",
        "",
        "| Component | Ecosystem | Status | Build | Captured units | Archive | Notes |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        c = r.component
        name = c["name"] + (f"@{c['version']}" if c.get("version") else "")
        units = ", ".join(f"{lang}: {n}" for lang, n in r.units.items()) or "-"
        archive = f"`{r.archive}` ({size(r.archive_bytes)})" if r.archive else "-"
        out.append(f"| `{_cell(name)}` | {c.get('ecosystem') or '-'} | {r.status} | {r.system or '-'} | {units} "
                   f"| {archive} | {_cell(_shorten(r.detail, 140))} |")

    if failed:
        out += ["", "## Failures", ""]
        for r in failed:
            c = r.component
            out += [f"### {c['name']}@{c.get('version') or '?'}: {r.status}", "", r.detail]
            if r.log:
                out += ["", f"Full log: `{r.log}`"]
            if r.output:
                out += ["", "```", r.output.rstrip(), "```"]
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def size(n: float) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _shorten(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
