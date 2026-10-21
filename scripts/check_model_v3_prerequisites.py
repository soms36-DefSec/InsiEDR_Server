"""Read-only deployment check for frozen Model V3 files and isolated runtime."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "model"


def verify_frozen_files() -> None:
    checks = (
        (MODEL / "run" / "frozen.json", "model_sha256", MODEL / "run" / "pipeline.joblib"),
        (MODEL / "run" / "behavior_frozen.json", "sha256", MODEL / "run" / "behavior_heads.joblib"),
    )
    for metadata_path, field, artifact_path in checks:
        expected = json.loads(metadata_path.read_text(encoding="utf-8"))[field]
        actual = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError(f"Frozen artifact hash mismatch: {artifact_path.name}")


def verify_runtime(python_bin: Path) -> None:
    if not python_bin.is_file():
        raise RuntimeError(f"Isolated Python 3.12 runtime missing: {python_bin}")
    code = """
import importlib.metadata as m, json, sys
names = ('numpy', 'pandas', 'scikit-learn', 'xgboost', 'torch', 'joblib', 'scipy')
print(json.dumps({'version': list(sys.version_info[:2]),
                  'packages': {name: m.version(name) for name in names}}))
"""
    result = subprocess.run([str(python_bin), "-c", code], capture_output=True,
                            text=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError(f"Model runtime package check failed: {result.stderr.strip()}")
    runtime = json.loads(result.stdout)
    if runtime["version"] != [3, 12]:
        raise RuntimeError(f"Model runtime must use Python 3.12; found {runtime['version']}")
    expected = {}
    for line in (MODEL / "requirements.txt").read_text(encoding="utf-8").splitlines():
        if "==" in line and not line.lstrip().startswith("#"):
            name, version = line.split("==", 1)
            expected[name.strip()] = version.strip()
    mismatches = {name: (version, runtime["packages"].get(name))
                  for name, version in expected.items()
                  if runtime["packages"].get(name) != version}
    if mismatches:
        raise RuntimeError(f"Model runtime package versions differ: {mismatches}")


def main() -> None:
    default = MODEL / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    parser = argparse.ArgumentParser(description="Check frozen Model V3 runtime prerequisites")
    parser.add_argument("--python", type=Path, default=default)
    args = parser.parse_args()
    verify_frozen_files()
    verify_runtime(args.python)
    print("Model V3 frozen files and isolated Python 3.12 runtime verified")


if __name__ == "__main__":
    main()
