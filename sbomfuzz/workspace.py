"""Per-component working directory shared by the fetcher, the agent and the fuzzers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .sandbox import give_to_sandbox


class WorkspaceError(ValueError):
    pass


@dataclass(frozen=True)
class Workspace:
    root: Path

    @classmethod
    def create(cls, root: Path) -> "Workspace":
        ws = cls(root.resolve())
        for d in (ws.root, ws.harnesses, ws.crashes, ws.corpus):
            d.mkdir(parents=True, exist_ok=True)
        give_to_sandbox(ws.root)
        return ws

    @property
    def harnesses(self) -> Path:
        return self.root / "harnesses"

    @property
    def crashes(self) -> Path:
        return self.root / "crashes"

    @property
    def corpus(self) -> Path:
        return self.root / "corpus"

    @property
    def site(self) -> Path:
        """Python packages installed with pip --target."""
        return self.root / "site"

    @property
    def libs(self) -> Path:
        """Java jars: the artifact and its runtime dependencies."""
        return self.root / "libs"

    @property
    def sources(self) -> Path:
        """Java sources jar contents, when published."""
        return self.root / "sources"

    @property
    def src(self) -> Path:
        """Native source tree."""
        return self.root / "src"

    def resolve(self, relative: str) -> Path:
        """Resolve a path given by the agent, refusing anything outside the workspace."""
        path = (self.root / relative).resolve()
        if path != self.root and self.root not in path.parents:
            raise WorkspaceError(f"path escapes the workspace: {relative}")
        return path

    def corpus_for(self, target: Path) -> Path:
        d = self.corpus / target.stem
        d.mkdir(parents=True, exist_ok=True)
        give_to_sandbox(d)
        return d

    def relative(self, path: Path) -> str:
        return str(path.relative_to(self.root))
