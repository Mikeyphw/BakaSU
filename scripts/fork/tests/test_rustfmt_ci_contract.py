"""Fail-closed, dependency-free coverage for the current Rust formatting CI gate."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / '.github/workflows/lints-check.yml'
MANIFESTS = (
    'userspace/ksud/Cargo.toml',
    'userspace/ksuinit/Cargo.toml',
)


def validate_gate(text: str) -> None:
    """Check provider-independent, blocking rustfmt coverage for both workspaces."""
    marker = re.search(r'(?ms)^  rustfmt:\n(?P<job>.*?)(?=^  [a-z][a-z0-9-]*:\s*$|\Z)', text)
    if marker is None:
        raise AssertionError('Rustfmt job missing')
    job = marker.group('job')
    if 'name: Rustfmt check\n' not in job:
        raise AssertionError('Required job identity changed')
    if 'dtolnay/rust-toolchain@nightly' not in job or 'components: rustfmt' not in job:
        raise AssertionError('Nightly rustfmt provisioning missing')
    if 'set -euo pipefail' not in job:
        raise AssertionError('Fail-closed shell contract missing')
    if re.search(r'(?m)^\s*continue-on-error\s*:', job) or re.search(r'\|\|\s*true\b|;\s*true\b', job):
        raise AssertionError('Rustfmt failure suppression prohibited')
    if 'LoliGothick/rustfmt-check' in text:
        raise AssertionError('Broken third-party formatter action still used')
    for manifest in MANIFESTS:
        line = 'cargo +nightly fmt --all --manifest-path ' + manifest + ' -- --check'
        if job.count(line) != 1:
            raise AssertionError('Exact blocking cargo fmt command missing or duplicated: ' + manifest)
    for text_pattern in ('\n  pull_request:\n', '\n  push:\n',
                         'name: ClangFormat check', 'name: Clippy check',
                         'name: ShellCheck', 'name: Check Line Endings',
                         'name: Check Manager Lint'):
        if text_pattern not in text:
            raise AssertionError('Existing trigger or regression gate removed: ' + text_pattern)


class RustfmtCIContract(unittest.TestCase):
    def test_current_gate(self):
        validate_gate(WORKFLOW.read_text(encoding='utf-8'))

    def test_removing_either_workspace_is_rejected(self):
        source = WORKFLOW.read_text(encoding='utf-8')
        for manifest in MANIFESTS:
            with self.subTest(manifest=manifest):
                with self.assertRaises(AssertionError):
                    validate_gate(source.replace('cargo +nightly fmt --all --manifest-path ' + manifest + ' -- --check', '# omitted'))

    def test_missing_check_is_rejected(self):
        source = WORKFLOW.read_text(encoding='utf-8')
        with self.assertRaises(AssertionError):
            validate_gate(source.replace('userspace/ksud/Cargo.toml -- --check', 'userspace/ksud/Cargo.toml'))

    def test_suppressed_failures_are_rejected(self):
        source = WORKFLOW.read_text(encoding='utf-8')
        for sample in ('continue-on-error: true', '|| true', '; true'):
            with self.subTest(sample=sample), self.assertRaises(AssertionError):
                validate_gate(source.replace('set -euo pipefail', 'set -euo pipefail\n          ' + sample))

    def test_obsolete_action_is_rejected(self):
        source = WORKFLOW.read_text(encoding='utf-8')
        with self.assertRaises(AssertionError):
            validate_gate(source + '\n# LoliGothick/rustfmt-check@master')

    def test_job_identity_and_other_gates_are_required(self):
        source = WORKFLOW.read_text(encoding='utf-8')
        for original, replacement in (('name: Rustfmt check', 'name: Ignored formatter'),
                                      ('name: Clippy check', 'name: Clippy disabled'),
                                      ('\n  pull_request:\n', '\n  workflow_dispatch:\n')):
            with self.subTest(original=original), self.assertRaises(AssertionError):
                validate_gate(source.replace(original, replacement))


if __name__ == '__main__':
    unittest.main()
