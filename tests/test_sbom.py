import json

import pytest

from sbomfuzz.sbom import SbomError, load_cyclonedx

from .conftest import DATA


@pytest.fixture
def components():
    return {c.name: c for c in load_cyclonedx(DATA / "bom.json")}


def test_walks_nested_components_and_skips_the_product(components):
    assert "urllib3" in components
    assert "the-product" not in components


def test_deduplicates_by_purl():
    names = [c.name for c in load_cyclonedx(DATA / "bom.json")]
    assert names.count("requests") == 1


def test_maps_purl_types_to_ecosystems(components):
    assert components["requests"].ecosystem == "python"
    assert components["jackson-databind"].ecosystem == "java"
    assert components["jackson-databind"].group == "com.fasterxml.jackson.core"
    assert components["jackson-databind"].qualifiers == {"type": "jar"}
    assert components["libpng"].ecosystem == "native"
    assert components["left-pad"].ecosystem is None


def test_source_locations(components):
    assert components["libpng"].vcs_url == "https://github.com/pnggroup/libpng"
    assert components["expat"].download_url == "https://example.org/expat-2.6.2.tar.gz"
    assert components["sqlite"].vcs_url == "git+https://github.com/sqlite/sqlite.git@version-3.45.0"


def test_skip_reasons(components):
    assert components["requests"].skip_reason() is None
    assert components["libpng"].skip_reason() is None
    assert components["unpinned"].skip_reason() == "no version in SBOM"
    assert components["mystery"].skip_reason() == "no download or VCS URL in SBOM"
    assert "npm" in components["left-pad"].skip_reason()
    assert "no purl" in components["no-purl-lib"].skip_reason()
    assert components["broken"].purl is None


def test_slug_is_safe_and_unique(components):
    slug = components["jackson-databind"].slug
    assert "/" not in slug and ":" not in slug
    assert slug.startswith("com.fasterxml.jackson.core_jackson-databind_2.15.2-")
    assert len({c.slug for c in components.values()}) == len(components)


def test_rejects_other_formats(tmp_path):
    spdx = tmp_path / "spdx.json"
    spdx.write_text(json.dumps({"spdxVersion": "SPDX-2.3"}))
    with pytest.raises(SbomError, match="CycloneDX"):
        load_cyclonedx(spdx)
    bad = tmp_path / "bad.json"
    bad.write_text("<bom/>")
    with pytest.raises(SbomError, match="JSON"):
        load_cyclonedx(bad)
    with pytest.raises(SbomError, match="not found"):
        load_cyclonedx(tmp_path / "missing.json")


def test_example_sbom_parses():
    from pathlib import Path

    example = Path(__file__).parent.parent / "examples" / "sample-bom.json"
    components = load_cyclonedx(example)
    assert [c.skip_reason() is None for c in components] == [True, True, True, True, False]
