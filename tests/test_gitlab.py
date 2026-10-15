import json
from pathlib import Path

from sbomfuzz import cli
from sbomfuzz.gitlab import child_pipeline

ROOT = Path(__file__).parent.parent


def plan_with(*slugs):
    return {"sbom": "bom.json", "created": "t", "skipped": [],
            "components": [{"slug": s, "name": s, "ecosystem": "python", "component": {}} for s in slugs]}


def test_child_pipeline_layout():
    p = child_pipeline(plan_with("toml_0.10.2-aaaa", "zlib_1.3.1-bbbb"), max_harnesses=3, fuzz_seconds=7200,
                       runner_tags=["fuzzing"])
    assert p["stages"] == ["generate", "fuzz", "report"]
    assert p["default"] == {"image": {"name": "$SBOMFUZZ_IMAGE", "entrypoint": [""]}, "tags": ["fuzzing"]}

    gen = p["generate:toml_0.10.2-aaaa"]
    assert gen["needs"] == [{"pipeline": "$PARENT_PIPELINE_ID", "job": "plan"}]
    assert gen["script"] == ["sbomfuzz generate plan.json --slug toml_0.10.2-aaaa -o bundles $GENERATE_ARGS"]
    assert gen["allow_failure"] == {"exit_codes": [5]}
    assert gen["artifacts"]["paths"] == ["plan.json", "bundles/toml_0.10.2-aaaa/"]

    fuzz = p["fuzz:toml_0.10.2-aaaa"]
    assert fuzz["needs"] == [{"job": "generate:toml_0.10.2-aaaa", "artifacts": True}]
    assert fuzz["parallel"] == 3
    assert "--harness-index ${CI_NODE_INDEX:-1}" in fuzz["script"][0]
    assert fuzz["timeout"] == "180m"  # two hours of fuzzing plus one hour of overhead
    assert fuzz["artifacts"]["paths"] == ["fuzz-results/toml_0.10.2-aaaa/"]

    report = p["report"]
    assert "needs" not in report  # gets every earlier job's artifacts; `needs` is capped at 50 jobs
    assert report["when"] == "always"
    assert set(report["artifacts"]["paths"]) == {"fuzz-report/", "bundles/", "fuzz-results/"}
    assert len([k for k in p if k.startswith(("generate:", "fuzz:"))]) == 4


def test_child_pipeline_edge_cases():
    single = child_pipeline(plan_with("a-1"), max_harnesses=1, fuzz_seconds=60)
    assert "parallel" not in single["fuzz:a-1"]  # GitLab requires parallel >= 2
    assert "tags" not in single["default"]
    empty = child_pipeline(plan_with(), max_harnesses=3, fuzz_seconds=60)
    assert list(empty) == ["default", "stages", "nothing-to-fuzz"]  # GitLab rejects a pipeline without jobs


def test_plan_command_writes_the_child_pipeline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("bom.json").write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"type": "library", "name": "toml", "version": "0.10.2", "purl": "pkg:pypi/toml@0.10.2"},
        {"type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"}]}))
    assert cli.main(["plan", "bom.json", "--gitlab-ci", "child.yml", "--max-harnesses", "2",
                     "--fuzz-seconds", "600", "--runner-tag", "fuzz"]) == 0
    child = json.loads(Path("child.yml").read_text())  # JSON is valid YAML
    slug = json.loads(Path("plan.json").read_text())["components"][0]["slug"]
    assert child[f"fuzz:{slug}"]["parallel"] == 2 and child[f"fuzz:{slug}"]["timeout"] == "70m"
    assert child["default"]["tags"] == ["fuzz"]
    assert not any("left-pad" in k for k in child)


def test_parent_pipeline_matches_the_child():
    """The parent .gitlab-ci.yml must provide what the generated child pipeline relies on."""
    text = (ROOT / ".gitlab-ci.yml").read_text()
    assert "\nplan:\n" in text and "--gitlab-ci child-pipeline.yml" in text  # the job the children `need`
    assert "artifact: child-pipeline.yml" in text and "job: plan" in text
    for variable in ("PARENT_PIPELINE_ID", "SBOMFUZZ_IMAGE", "FUZZ_SECONDS", "GENERATE_ARGS", "FUZZ_ARGS",
                     "REPORT_ARGS"):
        assert f"    {variable}: $" in text, f"the trigger job must pass {variable} to the child pipeline"
    assert "\nsvace:\n" in text and "sbomfuzz svace" in text
