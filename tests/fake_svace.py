"""Stands in for the `svace` CLI in tests.

  init DIR    creates DIR/.svace-dir
  build --svace-dir DIR [--python PATH] [options] [command ...]
              runs the command with compiler shims first on PATH that record every
              compilation, then prints "N <language> units are ready." per language like
              svace does and stores the counts in .svace-dir/bitcode/build-object.
              Exits with the command's status if it failed, and with 255 if nothing
              was captured.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

LANGUAGE = {"cc": "C/C++", "gcc": "C/C++", "c++": "C/C++", "g++": "C/C++", "clang": "C/C++", "clang++": "C/C++",
            "javac": "Java"}
SOURCES = (".c", ".cc", ".cpp", ".cxx", ".java")
SHIM = """#!/bin/sh
echo "$(basename "$0") $*" >> "$FAKE_SVACE_CAPTURE"
PATH="$FAKE_SVACE_REAL_PATH" exec "$(basename "$0")" "$@"
"""


def init(args: list[str]) -> None:
    (Path(args[-1] if args else ".") / ".svace-dir").mkdir(parents=True, exist_ok=True)


def build(args: list[str]) -> int:
    project, python, command = Path("."), [], []
    i = 0
    while i < len(args):
        if args[i] == "--svace-dir":
            project = Path(args[i + 1])
            i += 2
        elif args[i] == "--python":
            python.append(Path(args[i + 1]))
            i += 2
        elif args[i].startswith("-"):
            i += 1
        else:
            command = args[i:]
            break
    svace_dir = project / ".svace-dir"
    if not svace_dir.is_dir():
        print(f"fake svace: {svace_dir} does not exist, run svace init", file=sys.stderr)
        return 1

    units: dict[str, int] = {}
    if command:
        with tempfile.TemporaryDirectory() as shims:
            capture = Path(shims) / "capture.log"
            for name in LANGUAGE:
                shim = Path(shims) / name
                shim.write_text(SHIM)
                shim.chmod(0o755)
            env = {**os.environ, "PATH": f"{shims}:{os.environ['PATH']}", "FAKE_SVACE_REAL_PATH": os.environ["PATH"],
                   "FAKE_SVACE_CAPTURE": str(capture)}
            status = subprocess.call(command, env=env)
            calls = capture.read_text().splitlines() if capture.exists() else []
        if status:
            return status
        for call in calls:
            tool, *call_args = call.split()
            for arg in call_args:
                if arg.endswith(SOURCES):
                    units[LANGUAGE[tool]] = units.get(LANGUAGE[tool], 0) + 1
    for path in python:
        units["Python"] = units.get("Python", 0) + (1 if path.is_file() else len(list(path.rglob("*.py"))))

    if not any(units.values()):
        print("Svace captured nothing")
        return 255
    (svace_dir / "bitcode").mkdir(exist_ok=True)
    (svace_dir / "bitcode" / "build-object").write_text(json.dumps(units))
    print("Assembled build object: [BUILD]6715d4e4c908f8e62a54f174796282c48ce2d3a5")
    for language, n in units.items():
        print(f"  {n} {language} units are ready.")
    return 0


def main() -> int:
    tool, args = sys.argv[1], sys.argv[2:]
    if tool == "init":
        init(args)
        return 0
    if tool == "build":
        return build(args)
    print(f"fake svace: unsupported tool {tool}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
