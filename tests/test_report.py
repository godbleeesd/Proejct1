import json

import pytest

from sbomfuzz.report import ComponentResult, render_markdown, severity_at_least, write_json
from sbomfuzz.usage import Usage, from_response

META = {"sbom": "bom.json", "started": "s", "finished": "f", "model": "claude-opus-5-5", "effort": "high"}


def make_results():
    report = {
        "summary": "Fuzzed the parser | found one bug.",
        "harnesses": [{"path": "harnesses/fuzz_parse.py", "target_api": "parse()", "outcome": "found_crashes", "notes": ""}],
        "findings": [
            {"title": "IndexError on truncated input", "verdict": "confirmed_bug", "severity": "medium",
             "harness": "harnesses/fuzz_parse.py", "crash_file": "crashes/crash-1",
             "description": "Out-of-range read.", "reproduction": "python harnesses/fuzz_parse.py crashes/crash-1"},
            {"title": "Harness passed None", "verdict": "harness_issue", "severity": "info",
             "harness": "harnesses/fuzz_parse.py", "crash_file": "", "description": "", "reproduction": ""},
        ],
        "limitations": "Only parse() was covered.",
    }
    return [
        ComponentResult({"name": "toml", "version": "0.10.2", "ecosystem": "python", "purl": "pkg:pypi/toml@0.10.2"},
                        "completed", report=report),
        ComponentResult({"name": "lodash", "version": "4.17.21", "ecosystem": None, "purl": "pkg:npm/lodash@4.17.21"},
                        "skipped", "unsupported ecosystem (npm)"),
    ]


def test_only_bug_verdicts_count_as_bugs():
    results = make_results()
    assert [f["title"] for f in results[0].bugs] == ["IndexError on truncated input"]
    assert results[1].bugs == []


def test_markdown_report():
    md = render_markdown(META, make_results(), Usage())
    assert "bugs found: 1" in md
    assert "### [MEDIUM] IndexError on truncated input" in md
    assert "Fuzzed the parser \\| found one bug." in md  # pipes escaped inside the table
    assert "Not a bug (harness_issue): Harness passed None" in md
    assert "unsupported ecosystem (npm)" in md


def test_json_report(tmp_path):
    path = tmp_path / "report.json"
    write_json(path, META, make_results(), Usage(input_tokens=5))
    data = json.loads(path.read_text())
    assert data["usage"]["input_tokens"] == 5
    assert [c["status"] for c in data["components"]] == ["completed", "skipped"]


def test_severity_threshold():
    assert severity_at_least("high", "medium")
    assert severity_at_least("medium", "medium")
    assert not severity_at_least("low", "medium")
    assert not severity_at_least("bogus", "low")


def test_cost_estimate():
    class U:
        input_tokens = 1_000_000
        output_tokens = 100_000
        cache_read_input_tokens = 1_000_000
        cache_creation_input_tokens = 0

    assert from_response("claude-opus-5-5", U()).cost_usd == pytest.approx(4.0 + 2.0 + 0.2)
    assert from_response("some-unknown-model", U()).cost_usd is None
