import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {runInNewContext} from 'node:vm';

const source = readFileSync(new URL('../manager/app/src/main/assets/webview/download.js', import.meta.url), 'utf8');

// Model only the browser/bridge interface; no native or privileged operations.
function fixture({failChunk = false} = {}) {
    const events = [], listeners = {};
    class Anchor {
        constructor(href = '', download = '') { this.href = href; this.download = download; this.style = {}; }
        hasAttribute(name) { return name === 'download'; }
        click() { events.push(['native-click', this.href, this.download]); }
    }
    class BrowserURL extends URL {
        static createObjectURL() { return 'blob:https://mui.kernelsu.org/test'; }
        static revokeObjectURL() {}
    }
    class Reader {
        readAsDataURL(blob) {
            blob.arrayBuffer().then((bytes) => {
                this.result = 'data:application/octet-stream;base64,' + Buffer.from(bytes).toString('base64');
                this.onload();
            }, (error) => { this.error = error; this.onerror(); });
        }
    }
    const window = {}, document = {
        addEventListener(name, listener) { listeners[name] = listener; },
        createElement() { return new Anchor(); },
        body: {appendChild() {}, removeChild() {}},
    };
    const context = {
        window, document, URL: BrowserURL, HTMLAnchorElement: Anchor, Blob, FileReader: Reader,
        location: {href: 'https://mui.kernelsu.org/'}, setTimeout,
        console: {error(...args) { events.push(['error', String(args[1])]); }},
        fetch() { throw new Error('Unexpected fetch in fixture'); },
        ksu_download: {
            openExternal(url) { events.push(['external', url]); },
            save(bytes, name) { events.push(['save', bytes, name]); },
            startChunkedDownload(name, mime) { events.push(['start', name, mime]); return 'https://blob-download.kernelsu.internal/fixture'; },
            writeDownloadChunk(id, bytes) { events.push(['chunk', id, Buffer.from(bytes, 'base64').length]); return !failChunk; },
            completeChunkedDownload(id) { events.push(['complete', id]); return true; },
            cancelChunkedDownload(id) { events.push(['cancel', id]); },
        },
    };
    runInNewContext(source, context);
    const installed = Anchor.prototype.click;
    runInNewContext(source, context);
    assert.equal(Anchor.prototype.click, installed, 'installation must be idempotent');
    return {Anchor, BrowserURL, events, listeners};
}

async function settled(events, type) {
    for (let n = 0; n < 200; n++) {
        if (events.some(event => event[0] === type)) return;
        await new Promise(resolve => setTimeout(resolve, 5));
    }
    assert.fail('Expected browser event: ' + type);
}

test('external and internal routes use their intended browser bridge', () => {
    const {Anchor, events, listeners} = fixture();
    const external = new Anchor('https://example.org/file.zip', 'file.zip');
    external.click();
    assert.deepEqual(events, [['external', external.href]]);
    const internal = new Anchor('https://blob-download.kernelsu.internal/fixture', 'file.zip');
    internal.click();
    assert.deepEqual(events[1], ['native-click', internal.href, 'file.zip']);
    let blocked = false;
    listeners.click({target:{closest:() => external}, preventDefault(){blocked = true;}});
    assert.equal(blocked, true);
    assert.deepEqual(events[2], ['external', external.href]);
});

test('small object URL preserves bytes and file name', async () => {
    const {Anchor, BrowserURL, events} = fixture();
    new Anchor(BrowserURL.createObjectURL(new Blob([new Uint8Array([0, 255, 128])])), 'bytes.bin').click();
    await settled(events, 'save');
    assert.deepEqual(events, [['save', 'AP+A', 'bytes.bin']]);
});

test('large object URL completes bounded chunks, or cancels on write failure', async () => {
    const length = 10 * 1024 * 1024 + 1;
    for (const failChunk of [false, true]) {
        const {Anchor, BrowserURL, events} = fixture({failChunk});
        new Anchor(BrowserURL.createObjectURL(new Blob([new Uint8Array(length)], {type:'application/octet-stream'})), 'large.bin').click();
        await settled(events, failChunk ? 'error' : 'native-click');
        const chunks = events.filter(e => e[0] === 'chunk');
        assert.deepEqual(events[0], ['start', 'large.bin', 'application/octet-stream']);
        assert.ok(chunks.every(e => e[2] <= 512 * 1024));
        if (failChunk) {
            assert.equal(chunks.length, 1);
            assert.equal(events.filter(e => e[0] === 'cancel').length, 1);
            assert.ok(!events.some(e => e[0] === 'complete' || e[0] === 'native-click'));
        } else {
            assert.equal(chunks.reduce((n,e) => n+e[2], 0), length);
            assert.equal(chunks.length, 21);
            assert.equal(events.filter(e => e[0] === 'complete').length, 1);
            assert.equal(events.filter(e => e[0] === 'cancel').length, 0);
        }
    }
});
