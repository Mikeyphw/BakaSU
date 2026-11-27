#!/usr/bin/env python3
"""Execute the actual dependency-free Kotlin policy classes; no local Gradle."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "manager/app/src/main/java/org/bakasu/bakasu"


def main():
    compiler = shutil.which("kotlinc")
    java = shutil.which("java")
    if not compiler or not java:
        raise SystemExit("GAP02_POLICY_PROBE: Kotlin CLI and Java are required")
    paths = [
        PACKAGE / "data/module/registry/HistoricalZipPolicy.kt",
        PACKAGE / "data/file/ModuleArchiveIdentity.kt",
        PACKAGE / "data/update/ManagerReleaseProof.kt",
        PACKAGE / "domain/model/ManagerCompatibilityPolicy.kt",
        ROOT / "manager/qualification/Gap02PolicyProbe.kt",
    ]
    with tempfile.TemporaryDirectory(prefix="bakasu-gap02-") as directory:
        jar = Path(directory) / "policy.jar"
        subprocess.run([compiler, *map(str, paths), "-include-runtime", "-d", str(jar)], check=True, timeout=180)
        subprocess.run([java, "-jar", str(jar)], check=True, timeout=30)


if __name__ == "__main__":
    main()
