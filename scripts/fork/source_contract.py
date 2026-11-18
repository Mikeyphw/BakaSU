#!/usr/bin/env python3
"""Check integration seams before touching the upstream BakaSU manager.

Pure read-only static audit. No Android operations, Gradle, Git writes or network calls.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
REQUIRED = {
    "manager/app/src/main/java/org/bakasu/bakasu/ui/screen/main/ModulePage.kt": (
        "suspend fun onModuleUpdate(",
        "fun ModuleItem(",
        "module.updateJson",
        "onUpdateModule(",
        "module.takeIf { reinstall }",
        "Route.Flash.moduleReinstall(",
        "registry?.expected?.sha256",
        "registry?.expected?.size",
    ),
    "manager/app/src/main/java/org/bakasu/bakasu/ui/screen/Flash.kt": (
        "ReinstallArchiveVerifier.prepare(",
        "reinstallModuleId",
        "reinstallWasEnabled",
    ),
    "manager/app/src/main/java/org/bakasu/bakasu/ui/viewmodel/ModuleViewModel.kt": (
        "suspend fun resolveUpdate(",
        "fun isUpdateCurrent(",
    ),
    "manager/app/src/main/java/org/bakasu/bakasu/data/module/registry/RegistryUpdatePolicy.kt": (
        "sealed interface UpdateVerification",
        "data object Legacy",
        "data class Registry(",
        "data class Rejected(",
    ),
    "manager/app/src/main/java/org/bakasu/bakasu/data/update/ManagerUpdateRepository.kt": (
        "suspend fun checkStableUpdate(",
        "suspend fun checkBetaUpdate(",
        "const val REPOSITORY",
    ),
    "manager/app/src/main/java/org/bakasu/bakasu/data/kernel/KernelRepository.kt": (
        "kernelUAPIVersion",
        "managerUAPIVersion",
    ),
    ".devtool.toml": (
        "[project]",
        "runner = \"python\"",
    ),
    "manager/app/build.gradle.kts": (
        "applicationId = managerPackageName",
    ),
    ".github/workflows/build-manager.yml": (
        "name: Build Manager",
    ),
}


def check_tree(root: Path) -> list[str]:
    problems: list[str] = []
    for relative, tokens in REQUIRED.items():
        f = root / relative
        if not f.is_file():
            problems.append(f"MISSING_FILE {relative}")
            continue
        source = f.read_text(encoding="utf-8")
        for token in tokens:
            if token not in source:
                problems.append(f"MISSING_CONTRACT {relative} token={token!r}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    problems = check_tree(args.root)
    for item in problems:
        print("BK_F01_REFUSED", item, flush=True)
    if problems:
        return 2
    print(f"BK_F01_SOURCE_CONTRACT_PASS files={len(REQUIRED)}", flush=True)
    print("BK_F01_NOTE manager signing, authorized-root identity and releases NOT qualified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
