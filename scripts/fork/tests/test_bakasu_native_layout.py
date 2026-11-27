"""Host-only regression fixtures for reviewed native qualification paths.

All device, DDK, Git and privileged operations are absent or replaced by
local test doubles. No Gradle wrapper or kernel/module installation is run.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[3]
KMI = 'android17-6.18'
KMIS = ('android12-5.10', 'android13-5.10', 'android13-5.15',
        'android14-5.15', 'android14-6.1', 'android15-6.6',
        'android16-6.12', KMI)


class NativeFixtures(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bk-native-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.log = self.root / 'calls'
        self.env = {**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                    'FIXTURE': str(self.root), 'CALL_LOG': str(self.log),
                    'HOME': str(self.root), 'LC_ALL': 'C', 'CI': 'true'}
        for key in ('BASH_ENV', 'ENV', 'CDPATH', 'FAIL_MAKE', 'FAIL_DDK', 'JAVA_HOME'):
            self.env.pop(key, None)

    def run_command(self, argv, rc=0, **env):
        p = subprocess.run([str(x) for x in argv], cwd=self.root,
                           env={**self.env, **env}, text=True, errors='replace',
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        self.assertEqual(p.returncode, rc, p.stdout)
        return p.stdout

    def stub(self, name, script):
        path = self.bin / name
        path.write_text('#!/bin/bash\n' + script + '\n')
        path.chmod(0o700)
        return path

    def copy(self, name):
        out = self.root / name
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, out)
        return out

    def test_rust_toolchain_environment_exports(self):
        script = ROOT / '.github/scripts/setup-rust-build.sh'
        command = ('source "$1" aarch64-linux-android 35 aarch64-linux-android; '
                   'printf "%s\\n" "$CC_aarch64_linux_android" '
                   '"$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER" "$AR_aarch64_linux_android" '
                   '"$BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android"')
        out = self.run_command(['bash', '-c', command, 'fixture', script],
                               ANDROID_NDK_HOME=str(self.root / 'ndk'))
        base = str(self.root / 'ndk/toolchains/llvm/prebuilt/linux-x86_64')
        self.assertEqual(out.splitlines(), [base + '/bin/aarch64-linux-android35-clang'] * 2 +
                         [base + '/bin/llvm-ar', '--sysroot=' + base + '/sysroot -I' + base + '/sysroot/usr/include/aarch64-linux-android'])

    def test_setup_usage_and_missing_tree_refusal(self):
        script = ROOT / 'kernel/setup.sh'
        self.assertIn('Usage:', self.run_command(['sh', script, '--help']))
        self.assertIn('drivers/', self.run_command(['sh', script, '--submodule'], 127))
        (self.root / 'drivers').mkdir()
        self.assertIn('does not exist', self.run_command(['sh', script, '--submodule'], 127))
        (self.root / 'KernelSU').mkdir()
        self.assertIn('not a git repository', self.run_command(['sh', script, '--submodule']))

    def test_arm_build_script_dispatch_and_failure(self):
        script = self.copy('kernel/build-all.sh')
        (self.root / 'out').mkdir()
        self.stub('ddk', 'printf "%s\\n" "$@" > "$CALL_LOG"\n'
                  '[ -z "${FAIL_DDK:-}" ] || exit 17\n'
                  'for x in "$@"; do case "$x" in ODIR=*) d=${x#ODIR=};; esac; done\n'
                  'mkdir -p "$d"; printf fixture > "$d/kernelsu.ko"')
        self.stub('llvm-strip', 'test "$1" = -d && test -f "$2"')
        self.assertIn('Built kernelsu-', self.run_command(['bash', script, KMI]))
        self.assertIn(KMI, self.log.read_text().splitlines())
        self.assertEqual((self.root / f'out/kernelsu-{KMI}.ko').read_text(), 'fixture')
        shutil.rmtree(self.root / 'out'); (self.root / 'out').mkdir()
        self.assertIn('Build failed', self.run_command(['bash', script, KMI], 2, FAIL_DDK='1'))

    def install_ddk_doubles(self):
        self.stub('realpath', 'case "$1" in /opt/ddk/*) printf "%s/ddk/%s\\n" "$FIXTURE" "${1#/opt/ddk/}";; *) exec /usr/bin/realpath "$@";; esac')
        self.stub('mkdir', 'args=(); for a in "$@"; do case "$a" in /opt/ddk/*) a="$FIXTURE/ddk/${a#/opt/ddk/}";; esac; args+=("$a"); done; exec /usr/bin/mkdir "${args[@]}"')
        self.stub('make', 'printf "%s\\n" "$*" >> "$CALL_LOG"\n'
                  '[ -z "${FAIL_MAKE:-}" ] || exit 17\n'
                  'for a in "$@"; do case "$a" in MO=*|M=*) out=${a#*=};; esac; done\n'
                  'if [ -n "${out:-}" ]; then case "$out" in "$FIXTURE"/*) mkdir -p "$out"; printf fixture > "$out/kernelsu.ko";; *) exit 19;; esac; fi')

    def test_x64_build_old_and_new_layout(self):
        script = self.copy('kernel/build-all-x64.sh')
        self.install_ddk_doubles()
        self.run_command(['bash', script, 'android12-5.10 ' + KMI])
        lines = self.log.read_text().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn('src=', lines[0]); self.assertIn('MO=', lines[1])
        self.assertIn('modules', lines[0]); self.assertIn('modules', lines[1])
        self.run_command(['bash', script, KMI], 17, FAIL_MAKE='1')

    def test_ddk_preparation_dispatches_all_targets_and_stops_on_error(self):
        script = self.copy('scripts/prepare-ddk-x64.sh')
        self.install_ddk_doubles()
        for kmi in KMIS:
            path = self.root / 'ddk/src' / kmi / 'scripts'
            (path / 'mod').mkdir(parents=True)
            (path / 'mod/modpost.c').write_text('static void check_exports(\n  check_exports(mod);\n  s->module = exp->module;\n')
            config = path / 'config'
            config.write_text('#!/bin/sh\nprintf "config %s\\n" "$*" >> "$CALL_LOG"\n')
            config.chmod(0o700)
        self.run_command(['bash', script])
        lines = self.log.read_text().splitlines()
        for kmi in KMIS:
            self.assertTrue(any(kmi in x and 'modules_prepare' in x for x in lines), kmi)
            self.assertTrue(any(kmi in x and 'security/selinux/built-in.a' in x for x in lines), kmi)
        self.log.unlink()
        self.run_command(['bash', script], 17, FAIL_MAKE='1')
        self.assertEqual(len(self.log.read_text().splitlines()), 1)

    def test_installer_safe_function_behaviors_only(self):
        # No installer preset block, mount, recovery, device filesystem or flash.
        original = (ROOT / 'userspace/ksud/src/android/module/installer.sh').read_text()
        before, marker, _ = original.partition('##########\n# Presets\n##########')
        self.assertTrue(marker)
        functions = self.root / 'functions.sh'
        functions.write_text(before)
        for legacy in (False, True):
            path = self.root / ('legacy.zip' if legacy else 'modern.zip')
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('install.sh' if legacy else 'customize.sh', 'fixture\n')
            result = self.run_command(['bash', '-c', 'BOOTMODE=true; . "$1"; ZIPFILE="$2"; toupper fixture; is_legacy_script',
                                       'fixture', functions, path], 0 if legacy else 1)
            self.assertIn('FIXTURE', result)

    def test_strict_host_c_tools(self):
        # Compile actual project tools and exercise their real positive and negative paths.
        symbol = self.root / 'check_symbol'; syscall = self.root / 'syscall_no'
        for output, source in ((symbol, 'kernel/tools/check_symbol.c'),
                               (syscall, 'kernel/tools/code_generation/syscall_no/syscall_no.c')):
            self.run_command(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', ROOT / source, '-o', output])
        self.assertIn('Usage:', self.run_command([symbol], 1))
        self.assertIn('Cannot open', self.run_command([symbol, self.root / 'absent', self.root / 'absent'], 1))
        ko = self.root / 'ko.c'; ko.write_text('extern int fixture_symbol(void); int caller(void) { return fixture_symbol(); }\n__asm__(".section __versions,\\\"a\\\"\\n.previous");\n')
        vml = self.root / 'vml.c'; vml.write_text('int fixture_symbol(void) { return 1; }\n')
        for source in (ko, vml):
            self.run_command(['cc', '-c', source, '-o', source.with_suffix('.o')])
        self.run_command([symbol, ko.with_suffix('.o'), vml.with_suffix('.o')])
        vml.write_text('int other(void) { return 0; }\n')
        self.run_command(['cc', '-c', vml, '-o', vml.with_suffix('.o')])
        self.assertIn('not found or undefined', self.run_command([symbol, ko.with_suffix('.o'), vml.with_suffix('.o')], 1))
        self.assertIn('usage:', self.run_command([syscall], 1))
        source = self.root / 'unistd32.h'; source.write_text('#define __NR_fixture 42\n#define unrelated 1\n')
        out = self.root / 'out.h'
        self.run_command([syscall, out, '--arm64-compat', source])
        self.assertIn('#define __NR_compat32_fixture 42', out.read_text())
        self.assertNotIn('unrelated', out.read_text())
        self.assertIn('requires --arm64-compat', self.run_command([syscall, out, source], 1))
