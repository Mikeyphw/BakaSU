import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exec, spawn, listPackages, getPackagesInfo, moduleInfo, toast,
  fullScreen, enableEdgeToEdge, exit } from './index.js';

// In-process bridge double only: no native command, Android or root action.
test('callback success, error cleanup, and unique callback names', async () => {
  globalThis.window = {};
  const callbacks = [];
  globalThis.ksu = { exec(cmd, opts, id) {
    assert.equal(cmd, 'fixture');
    assert.deepEqual(JSON.parse(opts), { cwd: '/fixture' });
    callbacks.push(id);
    window[id](0, 'value', '');
  } };
  assert.deepEqual(await exec('fixture', { cwd: '/fixture' }),
    { errno: 0, stdout: 'value', stderr: '' });
  await exec('fixture', { cwd: '/fixture' });
  assert.equal(new Set(callbacks).size, 2);
  assert.deepEqual(Object.keys(window), []);
  ksu.exec = () => { throw new Error('fixture refusal'); };
  await assert.rejects(exec('fixture'), /fixture refusal/);
  assert.deepEqual(Object.keys(window), []);
});

test('spawn event forwarding and callback lifetime', () => {
  globalThis.window = {};
  let callback;
  globalThis.ksu = { spawn(cmd, args, options, id) {
    assert.equal(cmd, 'fixture');
    assert.deepEqual(JSON.parse(args), ['a b']);
    assert.deepEqual(JSON.parse(options), { cwd: '/fixture' });
    callback = id;
  } };
  const child = spawn('fixture', ['a b'], { cwd: '/fixture' });
  const seen = [];
  child.stdout.on('data', value => seen.push(value));
  child.on('exit', code => seen.push(code));
  window[callback].stdout.emit('data', 'line');
  window[callback].emit('exit', 0);
  assert.deepEqual(seen, ['line', 0]);
  assert.equal(Object.hasOwn(window, callback), false);
});

test('metadata parsing, malformed response refusal and UI delegation', () => {
  const calls = [];
  globalThis.ksu = {
    listPackages(type) { assert.equal(type, 'fixture'); return '["pkg"]'; },
    getPackagesInfo(arg) { assert.deepEqual(JSON.parse(arg), ['pkg']); return '[{"packageName":"pkg"}]'; },
    moduleInfo() { return 'fixture'; },
    toast(v) { calls.push(['toast', v]); },
    fullScreen(v) { calls.push(['fullScreen', v]); },
    enableEdgeToEdge(v) { calls.push(['edge', v]); },
    exit() { calls.push(['exit']); }
  };
  assert.deepEqual(listPackages('fixture'), ['pkg']);
  assert.deepEqual(getPackagesInfo(['pkg']), [{ packageName: 'pkg' }]);
  ksu.listPackages = () => 'not-json';
  ksu.getPackagesInfo = () => 'not-json';
  assert.deepEqual(listPackages('fixture'), []);
  assert.deepEqual(getPackagesInfo(['pkg']), []);
  assert.equal(moduleInfo(), 'fixture');
  toast('fixture'); fullScreen(true); enableEdgeToEdge(false); exit();
  assert.deepEqual(calls, [['toast', 'fixture'], ['fullScreen', true], ['edge', false], ['exit']]);
});
