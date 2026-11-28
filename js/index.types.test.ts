import { exec, spawn, listPackages, getPackagesInfo, moduleInfo,
    fullScreen, enableEdgeToEdge, toast } from './index.js';

// Compile-only public declaration contract, no native bridge invocation.
const command = 'fixture';
const result: Promise<{ errno: number; stdout: string; stderr: string }> = exec(command, {cwd: '/fixture'});
const child = spawn(command, ['a b'], {env: {FIXTURE: 'value'}});
child.stdout.on('data', (line: string) => { void line; });
child.on('exit', (code: number) => { void code; });
const names: string[] = listPackages('fixture');
const info: string = moduleInfo();
const packages = getPackagesInfo(names);
const entry = packages[0];
// @ts-expect-error Package lookup may return an error instead of metadata.
const unsafeVersion: number = entry.versionCode;
let version: number | undefined;
if ("error" in entry) {
    const error: string = entry.error;
    void error;
} else {
    version = entry.versionCode;
}
void unsafeVersion;
fullScreen(true); enableEdgeToEdge(false); toast(info);
// @ts-expect-error Boolean flags are not strings.
fullScreen('true');
// @ts-expect-error argv must be an array of strings or an options object.
spawn(command, 42);
void result; void version;
