"""GitLab CI child pipeline for the fuzzing stages, generated from a plan.

The parent pipeline (.gitlab-ci.yml) runs `sbomfuzz plan --gitlab-ci child-pipeline.yml` and
triggers the result. Per component the child pipeline has one generate job and one fuzz job
per harness slot (`parallel`, CI_NODE_INDEX picks the harness), then a report job.

The file is JSON, which is valid YAML: no YAML library is needed to write it safely.
Settings that may change per run (fuzzing time, extra arguments, the image) are CI variables
the parent's trigger job passes down; only the job layout is fixed when the plan is made.
"""

from __future__ import annotations

ARTIFACTS_EXPIRE = "30 days"
# Time for downloading, rebuilding and checking the seeds on top of the fuzzing itself.
FUZZ_JOB_OVERHEAD = 3600


def child_pipeline(plan: dict, max_harnesses: int, fuzz_seconds: int, runner_tags: list[str] | None = None) -> dict:
    default: dict = {"image": {"name": "$SBOMFUZZ_IMAGE", "entrypoint": [""]}}
    if runner_tags:
        default["tags"] = list(runner_tags)
    pipeline: dict = {"default": default, "stages": ["generate", "fuzz", "report"]}
    plan_needs = {"pipeline": "$PARENT_PIPELINE_ID", "job": "plan"}

    if not plan["components"]:
        # GitLab rejects a pipeline without jobs.
        pipeline["nothing-to-fuzz"] = {"stage": "report", "script": ["echo 'The plan has no components to fuzz.'"]}
        return pipeline

    for entry in plan["components"]:
        slug = entry["slug"]
        pipeline[f"generate:{slug}"] = {
            "stage": "generate",
            "needs": [plan_needs],
            "script": [f"sbomfuzz generate plan.json --slug {slug} -o bundles $GENERATE_ARGS"],
            # 5: the subscription's usage limit was reached; the report shows the component as such.
            "allow_failure": {"exit_codes": [5]},
            "artifacts": {"when": "always", "expire_in": ARTIFACTS_EXPIRE,
                          # plan.json rides along so the report job gets it with the bundles.
                          "paths": ["plan.json", f"bundles/{slug}/"]},
        }
        fuzz_job: dict = {
            "stage": "fuzz",
            "needs": [{"job": f"generate:{slug}", "artifacts": True}],
            "timeout": f"{(fuzz_seconds + FUZZ_JOB_OVERHEAD + 59) // 60}m",
            "script": [f"sbomfuzz fuzz bundles/{slug} --harness-index ${{CI_NODE_INDEX:-1}} -o fuzz-results "
                       "--fuzz-seconds $FUZZ_SECONDS $FUZZ_ARGS"],
            "artifacts": {"when": "always", "expire_in": ARTIFACTS_EXPIRE, "paths": [f"fuzz-results/{slug}/"]},
        }
        if max_harnesses > 1:
            fuzz_job["parallel"] = max_harnesses
        pipeline[f"fuzz:{slug}"] = fuzz_job

    # No `needs`: a job without it gets the artifacts of every job in the earlier stages, and
    # `needs` is capped at 50 jobs, which a large SBOM would exceed.
    pipeline["report"] = {
        "stage": "report",
        "when": "always",
        "script": ["sbomfuzz report plan.json --bundles bundles --fuzz fuzz-results -o fuzz-report $REPORT_ARGS"],
        "artifacts": {"when": "always", "expire_in": ARTIFACTS_EXPIRE, "name": "fuzzing-results",
                      "paths": ["fuzz-report/", "bundles/", "fuzz-results/"]},
    }
    return pipeline
