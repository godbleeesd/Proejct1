import zipfile
from xml.etree import ElementTree

import pytest

from sbomfuzz.fetch import FetchError, _check_url, _extract_zip, maven_pom, normalize_vcs_url
from sbomfuzz.sbom import Component


def component(**kw):
    base = dict(name="lib", version="1.0", group="org.example", purl=None, purl_type="maven", ecosystem="java",
                download_url=None, vcs_url=None, bom_ref=None, qualifiers={})
    base.update(kw)
    return Component(**base)


def test_maven_pom_is_valid_xml_with_escaping():
    pom = maven_pom(component(name="a&b", qualifiers={"classifier": "linux<x86>"}))
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    dep = ElementTree.fromstring(pom).find("m:dependencies/m:dependency", ns)
    assert dep.find("m:artifactId", ns).text == "a&b"
    assert dep.find("m:classifier", ns).text == "linux<x86>"
    assert dep.find("m:groupId", ns).text == "org.example"


@pytest.mark.parametrize("url, expected", [
    ("https://github.com/a/b", ("https://github.com/a/b", None)),
    ("git+https://github.com/a/b.git@v1.2", ("https://github.com/a/b.git", "v1.2")),
    ("https://github.com/a/b.git#abc123", ("https://github.com/a/b.git", "abc123")),
])
def test_normalize_vcs_url(url, expected):
    assert normalize_vcs_url(url) == expected


def test_only_http_urls_are_fetched():
    assert _check_url("https://example.org/x.tar.gz")
    for url in ("file:///etc/passwd", "ssh://git@host/repo", "ftp://host/x"):
        with pytest.raises(FetchError):
            _check_url(url)


def test_zip_extraction_rejects_path_traversal(tmp_path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("ok.txt", "fine")
        zf.writestr("../escaped.txt", "bad")
    with pytest.raises(FetchError):
        _extract_zip(archive, tmp_path / "out")
    assert not (tmp_path / "escaped.txt").exists()


def test_zip_extraction(tmp_path):
    archive = tmp_path / "good.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("pkg/a.c", "int main(){}")
    _extract_zip(archive, tmp_path / "out")
    assert (tmp_path / "out" / "pkg" / "a.c").read_text() == "int main(){}"
