import os
import shutil
import tempfile
from pathlib import Path

import pytest

from sbomfuzz.workspace import Workspace

DATA = Path(__file__).parent / "data"


@pytest.fixture
def ws():
    # Not pytest's tmp_path: its parent directories are private to the current user,
    # and the sandbox user must be able to reach the workspace.
    root = Path(tempfile.mkdtemp(prefix="sbomfuzz-test-"))
    os.chmod(root, 0o755)
    try:
        yield Workspace.create(root / "ws")
    finally:
        shutil.rmtree(root, ignore_errors=True)
