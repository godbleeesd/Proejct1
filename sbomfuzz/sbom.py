"""Reading CycloneDX JSON SBOMs into a flat list of components."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from packageurl import PackageURL

# purl type -> ecosystem key. Source-only purl types are treated as native
# (C/C++) code; the agent checks the language once it sees the sources.
ECOSYSTEM_BY_PURL_TYPE = {
    "pypi": "python",
    "maven": "java",
    "github": "native",
    "generic": "native",
    "conan": "native",
}


class SbomError(ValueError):
    pass


@dataclass(frozen=True)
class Component:
    name: str
    version: str | None
    group: str | None
    purl: str | None
    purl_type: str | None
    ecosystem: str | None
    download_url: str | None
    vcs_url: str | None
    bom_ref: str | None
    # purl qualifiers relevant to fetching (Maven type/classifier).
    qualifiers: dict[str, str]

    @property
    def display_name(self) -> str:
        name = f"{self.group}:{self.name}" if self.group and self.purl_type == "maven" else self.name
        return f"{name}@{self.version}" if self.version else name

    @property
    def key(self) -> str:
        return self.purl or f"{self.group or ''}/{self.name}@{self.version or ''}"

    @property
    def slug(self) -> str:
        """Filesystem-safe, unique directory name for this component."""
        base = re.sub(r"[^A-Za-z0-9._-]+", "_", self.display_name).strip("._")[:80]
        digest = hashlib.sha256(self.key.encode()).hexdigest()[:8]
        return f"{base or 'component'}-{digest}"

    def skip_reason(self) -> str | None:
        """Why this component cannot be fuzzed, or None if it can."""
        if self.ecosystem is None:
            kind = self.purl_type or "no purl"
            return f"unsupported ecosystem ({kind})"
        if self.ecosystem in ("python", "java") and not self.version:
            return "no version in SBOM"
        if self.ecosystem == "native" and not (self.download_url or self.vcs_url):
            return "no download or VCS URL in SBOM"
        return None

    def to_dict(self) -> dict:
        return asdict(self)


def load_cyclonedx(path: str | Path) -> list[Component]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        raise SbomError(f"SBOM file not found: {path}") from None
    except json.JSONDecodeError as e:
        raise SbomError(f"SBOM is not valid JSON ({e}); only CycloneDX JSON is supported") from None
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        raise SbomError('not a CycloneDX JSON SBOM (missing "bomFormat": "CycloneDX")')

    components: list[Component] = []
    seen: set[str] = set()

    def walk(items: object) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            component = _parse_component(item)
            if component is not None and component.key not in seen:
                seen.add(component.key)
                components.append(component)
            walk(item.get("components"))

    # metadata.component is the product the SBOM describes, not a dependency.
    walk(data.get("components"))
    return components


def _parse_component(item: dict) -> Component | None:
    name = item.get("name")
    if not isinstance(name, str) or not name:
        return None

    purl_str = item.get("purl") if isinstance(item.get("purl"), str) else None
    purl = None
    if purl_str:
        try:
            purl = PackageURL.from_string(purl_str)
        except ValueError:
            purl = None

    qualifiers: dict[str, str] = dict(purl.qualifiers or {}) if purl else {}
    version = (purl.version if purl and purl.version else None) or _str(item.get("version"))
    group = (purl.namespace if purl and purl.namespace else None) or _str(item.get("group"))

    download_url = qualifiers.pop("download_url", None)
    vcs_url = qualifiers.pop("vcs_url", None)
    for ref in item.get("externalReferences") or []:
        if not isinstance(ref, dict) or not isinstance(ref.get("url"), str):
            continue
        if ref.get("type") in ("distribution", "source-distribution") and not download_url:
            download_url = ref["url"]
        elif ref.get("type") == "vcs" and not vcs_url:
            vcs_url = ref["url"]
    if purl and purl.type == "github" and not vcs_url and purl.namespace:
        vcs_url = f"https://github.com/{purl.namespace}/{purl.name}"

    purl_type = purl.type if purl else None
    return Component(
        name=purl.name if purl else name,
        version=version,
        group=group,
        purl=purl_str if purl else None,
        purl_type=purl_type,
        ecosystem=ECOSYSTEM_BY_PURL_TYPE.get(purl_type or ""),
        download_url=download_url,
        vcs_url=vcs_url,
        bom_ref=_str(item.get("bom-ref")),
        qualifiers={k: v for k, v in qualifiers.items() if k in ("type", "classifier")},
    )


def _str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None
