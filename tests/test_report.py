import json

from sbomfuzz.report import ComponentResult, render_markdown, write_json
from sbomfuzz.usage import Usage

META = {"sbom": "bom.json", "started": "s", "finished": "f", "model": "default", "effort": "high",
        "fuzz_seconds_per_harness": 600}

CRASH = {"kind": "IndexError", "signature": "IndexError toml/decoder.py:207 in load_line",
         "summary": "IndexError: list index out of range (toml/decoder.py:207 in load_line)",
         "stack": "=== Uncaught Python exception: ===\nIndexError: list index out of range",
         "crash_file": "crashes/crash-1", "reproduction": "PYTHONPATH=site python3 harnesses/fuzz_loads.py crashes/crash-1",
         "count": 2}


def make_results():
    harness = {"name": "loads", "source": "harnesses/fuzz_loads.py", "target": "harnesses/fuzz_loads.py",
               "target_api": "toml.loads | dumps", "description": "", "seeds": [], "status": "crashes",
               "fuzz_seconds": 600.0, "runs": 4, "executions": 123456, "last_stats": "#123456 DONE cov: 787",
               "error": "", "crashes": [CRASH]}
    validation = [{"attempt": 1, "build_error": None,
                   "harnesses": [{"name": "loads", "ok": True, "detail": ""},
                                 {"name": "dumps", "ok": False, "detail": "SyntaxError: invalid syntax"}]}]
    return [
        ComponentResult({"name": "toml", "version": "0.10.2", "ecosystem": "python", "purl": "pkg:pypi/toml@0.10.2"},
                        "completed", harnesses=[harness], attempts=1, validation=validation, turns=12),
        ComponentResult({"name": "lodash", "version": "4.17.21", "ecosystem": None, "purl": "pkg:npm/lodash@4.17.21"},
                        "skipped", "unsupported ecosystem (npm)"),
    ]


def test_markdown_report():
    md = render_markdown(META, make_results(), Usage())
    assert "unique crashes: 1" in md
    assert "### 1. IndexError in `toml@0.10.2`" in md
    assert "PYTHONPATH=site python3 harnesses/fuzz_loads.py crashes/crash-1" in md
    assert "hit 2 time(s)" in md
    assert "123,456" in md
    assert "`dumps`: dropped, failed validation: SyntaxError" in md
    assert "unsupported ecosystem (npm)" in md
    assert "toml.loads \\| dumps" not in md  # pipes only need escaping inside table cells


def test_json_report(tmp_path):
    path = tmp_path / "report.json"
    write_json(path, META, make_results(), Usage(input_tokens=5))
    data = json.loads(path.read_text())
    assert data["usage"]["input_tokens"] == 5
    assert [c["status"] for c in data["components"]] == ["completed", "skipped"]
    assert data["components"][0]["harnesses"][0]["crashes"][0]["count"] == 2
    assert data["components"][0]["generation"]["attempts"] == 1
