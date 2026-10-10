"""Downloading a component into its workspace so the agent can study and fuzz it."""

from __future__ import annotations

import re
import shutil
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape

from . import sandbox
from .sbom import Component
from .workspace import Workspace

MAX_DOWNLOAD_BYTES = 1024 * 1024 * 1024
DEPENDENCY_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.8.1"


class FetchError(RuntimeError):
    pass


@dataclass
class FetchResult:
    detail: str


def fetch(component: Component, ws: Workspace, timeout: int = 900) -> FetchResult:
    if component.ecosystem == "python":
        return _fetch_python(component, ws, timeout)
    if component.ecosystem == "java":
        return _fetch_java(component, ws, timeout)
    if component.ecosystem == "native":
        return _fetch_native(component, ws, timeout)
    raise FetchError(f"no fetcher for ecosystem {component.ecosystem}")


def _fetch_python(component: Component, ws: Workspace, timeout: int) -> FetchResult:
    spec = f"{component.name}=={component.version}"
    result = sandbox.run(
        [sys.executable, "-m", "pip", "install", "--no-input", "--disable-pip-version-check",
         "--no-warn-script-location", "--target", str(ws.site), spec],
        cwd=ws.root,
        timeout=timeout,
    )
    if not result.ok:
        raise FetchError(f"pip install {spec} failed:\n{result.output[-3000:]}")
    return FetchResult(f"installed {spec} (with dependencies) into site/")


def maven_pom(component: Component) -> str:
    extra = ""
    if component.qualifiers.get("type"):
        extra += f"<type>{escape(component.qualifiers['type'])}</type>"
    if component.qualifiers.get("classifier"):
        extra += f"<classifier>{escape(component.qualifiers['classifier'])}</classifier>"
    return (
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<modelVersion>4.0.0</modelVersion>"
        "<groupId>sbomfuzz</groupId><artifactId>fetch</artifactId><version>0</version>"
        "<dependencies><dependency>"
        f"<groupId>{escape(component.group or '')}</groupId>"
        f"<artifactId>{escape(component.name)}</artifactId>"
        f"<version>{escape(component.version or '')}</version>{extra}"
        "</dependency></dependencies></project>\n"
    )


def _fetch_java(component: Component, ws: Workspace, timeout: int) -> FetchResult:
    if not component.group:
        raise FetchError("Maven purl has no group (namespace)")
    pom = ws.root / "pom.xml"
    pom.write_text(maven_pom(component), encoding="utf-8")
    sandbox.give_to_sandbox(pom)
    coords = f"{component.group}:{component.name}:{component.version}"

    result = sandbox.run(
        ["mvn", "-B", "-q", "-f", str(pom), f"{DEPENDENCY_PLUGIN}:copy-dependencies",
         f"-DoutputDirectory={ws.libs}", "-DincludeScope=runtime"],
        cwd=ws.root,
        timeout=timeout,
    )
    if not result.ok or not any(ws.libs.glob("*.jar")):
        raise FetchError(f"downloading {coords} from Maven failed:\n{result.output[-3000:]}")
    jars = len(list(ws.libs.glob("*.jar")))

    with tempfile.TemporaryDirectory() as tmp:
        sandbox.give_to_sandbox(Path(tmp))
        sources = sandbox.run(
            ["mvn", "-B", "-q", "-f", str(pom), f"{DEPENDENCY_PLUGIN}:copy",
             f"-Dartifact={coords}:jar:sources", f"-DoutputDirectory={tmp}"],
            cwd=ws.root,
            timeout=timeout,
        )
        jar = next(Path(tmp).glob("*.jar"), None)
        if sources.ok and jar is not None:
            _extract_zip(jar, ws.sources)
            sandbox.give_to_sandbox(ws.sources)
            note = "sources jar unpacked into sources/"
        else:
            note = "no sources jar published"
    return FetchResult(f"downloaded {coords} and runtime dependencies ({jars} jars) into libs/; {note}")


def _fetch_native(component: Component, ws: Workspace, timeout: int) -> FetchResult:
    if component.download_url:
        try:
            detail = _download_and_extract(component.download_url, ws.src, timeout)
            sandbox.give_to_sandbox(ws.src)
            return FetchResult(detail)
        except FetchError as e:
            if not component.vcs_url:
                raise
            download_error = f"{e}; "
    else:
        download_error = ""
    detail = _git_clone(component, ws, timeout)
    return FetchResult(download_error + detail)


def _check_url(url: str) -> str:
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        raise FetchError(f"refusing non-HTTP(S) URL: {url}")
    return url


def _download_and_extract(url: str, dest: Path, timeout: int) -> str:
    _check_url(url)
    with tempfile.TemporaryDirectory() as tmp:
        name = Path(urllib.parse.urlparse(url).path).name or "download"
        archive = Path(tmp) / name
        try:
            with urllib.request.urlopen(url, timeout=60) as response, archive.open("wb") as out:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise FetchError(f"download larger than {MAX_DOWNLOAD_BYTES} bytes: {url}")
                    out.write(chunk)
        except OSError as e:
            raise FetchError(f"download failed: {url}: {e}") from None

        dest.mkdir(parents=True, exist_ok=True)
        if tarfile.is_tarfile(archive):
            with tarfile.open(archive) as tar:
                tar.extractall(dest, filter="data")
        elif zipfile.is_zipfile(archive):
            _extract_zip(archive, dest)
        else:
            shutil.copy2(archive, dest / name)
    return f"downloaded {url} and unpacked it into src/"


def _extract_zip(archive: Path, dest: Path) -> None:
    dest = dest.resolve()
    with zipfile.ZipFile(archive) as zf:
        for member in zf.infolist():
            target = (dest / member.filename).resolve()
            if target != dest and dest not in target.parents:
                raise FetchError(f"archive entry escapes the destination: {member.filename}")
        zf.extractall(dest)


def normalize_vcs_url(url: str) -> tuple[str, str | None]:
    """Split SPDX/purl-style VCS URLs ("git+https://host/repo.git@ref") into (url, ref)."""
    if url.startswith("git+"):
        url = url[4:]
    ref = None
    parsed = urllib.parse.urlparse(url)
    if "@" in parsed.path:
        path, ref = parsed.path.rsplit("@", 1)
        url = parsed._replace(path=path).geturl()
    if "#" in url:
        url, ref = url.split("#", 1)
    return url, ref or None


def _git_clone(component: Component, ws: Workspace, timeout: int) -> str:
    url, ref = normalize_vcs_url(component.vcs_url or "")
    _check_url(url)
    version = component.version
    candidates = [r for r in dict.fromkeys(
        [ref, version, f"v{version}" if version else None,
         f"{component.name}-{version}" if version else None,
         f"release-{version}" if version else None]) if r]

    for tag in candidates:
        result = sandbox.run(["git", "clone", "--quiet", "--depth", "1", "--branch", tag, url, str(ws.src)],
                             cwd=ws.root, timeout=timeout)
        if result.ok:
            return f"cloned {url} at {tag} into src/"
        shutil.rmtree(ws.src, ignore_errors=True)

    result = sandbox.run(["git", "clone", "--quiet", url, str(ws.src)], cwd=ws.root, timeout=timeout)
    if not result.ok:
        raise FetchError(f"git clone {url} failed:\n{result.output[-2000:]}")
    wanted = ref or version
    if wanted and re.fullmatch(r"[0-9a-fA-F]{7,40}", wanted):
        checkout = sandbox.run(["git", "-C", str(ws.src), "checkout", "--quiet", wanted], cwd=ws.root, timeout=120)
        if checkout.ok:
            return f"cloned {url} at commit {wanted} into src/"
    if wanted:
        return f"cloned {url} into src/ but found no tag or commit for {wanted!r}; using the default branch"
    return f"cloned {url} (default branch, the SBOM has no version) into src/"
