import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { openStore, StoreCorruptError } from '../src/store.js';

const key = randomBytes(32);
const tmpFile = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'store-')), 'store.json');

test('missing file starts empty and is written immediately', () => {
  const file = tmpFile();
  const s = openStore({ file, key });
  assert.equal(s.read().version, 1);
  assert.deepEqual(s.read().sessions, {});
  assert.ok(fs.existsSync(file));
});

test('mutate persists, a new openStore reads the same state', async () => {
  const file = tmpFile();
  const s = openStore({ file, key });
  const r = await s.mutate((d) => { d.sessions.a = { sid: 'a' }; return 42; });
  assert.equal(r, 42);
  assert.deepEqual(openStore({ file, key }).read().sessions, { a: { sid: 'a' } });
});

test('read returns a deep copy', async () => {
  const s = openStore({ file: tmpFile(), key });
  s.read().sessions.x = 1;
  assert.deepEqual(s.read().sessions, {});
});

test('failing rename: mutate rejects, state unchanged, tmp removed', async () => {
  const file = tmpFile();
  let fail = false;
  const stub = { ...fs, renameSync: (...a) => { if (fail) throw new Error('boom'); return fs.renameSync(...a); } };
  const s = openStore({ file, key, fs: stub });
  fail = true;
  await assert.rejects(s.mutate((d) => { d.sessions.a = {}; }), /boom/);
  assert.deepEqual(s.read().sessions, {});
  assert.deepEqual(fs.readdirSync(path.dirname(file)), ['store.json']);
  assert.deepEqual(openStore({ file, key }).read().sessions, {});
});

test('a failed mutate does not break the chain', async () => {
  const s = openStore({ file: tmpFile(), key });
  await assert.rejects(s.mutate(() => { throw new Error('fn'); }), /fn/);
  await s.mutate(async (d) => { d.sessions.a = {}; });
  assert.deepEqual(s.read().sessions, { a: {} });
});

test('mutate calls run sequentially', async () => {
  const s = openStore({ file: tmpFile(), key });
  const order = [];
  await Promise.all([
    s.mutate(async (d) => { await new Promise((r) => setTimeout(r, 20)); d.uploadNonces.a = 1; order.push('a'); }),
    s.mutate((d) => { assert.ok(d.uploadNonces.a); order.push('b'); }),
  ]);
  assert.deepEqual(order, ['a', 'b']);
});

test('garbage file -> StoreCorruptError naming STORE_FILE', () => {
  const file = tmpFile();
  fs.writeFileSync(file, 'not json');
  assert.throws(() => openStore({ file, key }), (e) => e instanceof StoreCorruptError && /STORE_FILE/.test(e.message) && e.message.includes(file));
});

test('wrong key -> StoreCorruptError', () => {
  const file = tmpFile();
  openStore({ file, key });
  assert.throws(() => openStore({ file, key: randomBytes(32) }), StoreCorruptError);
});

test('sealField/openField round trip with aad', () => {
  const s = openStore({ file: tmpFile(), key });
  const c = s.sealField('tok', 'sid1');
  assert.equal(s.openField(c, 'sid1'), 'tok');
  assert.throws(() => s.openField(c, 'sid2'));
});

test('withLock serializes same key, parallel for different keys', async () => {
  const s = openStore({ file: tmpFile(), key });
  const log = [];
  const slow = (n) => async () => { log.push(`${n}+`); await new Promise((r) => setTimeout(r, 30)); log.push(`${n}-`); };
  await Promise.all([s.withLock('a', slow(1)), s.withLock('a', slow(2)), s.withLock('b', slow(3))]);
  assert.ok(log.indexOf('1-') < log.indexOf('2+'));
  assert.ok(log.indexOf('3+') < log.indexOf('1-'));
});

test('withLock releases after throw', async () => {
  const s = openStore({ file: tmpFile(), key });
  await assert.rejects(s.withLock('a', async () => { throw new Error('x'); }), /x/);
  assert.equal(await s.withLock('a', async () => 'ok'), 'ok');
});

test('file mode is 0600', { skip: process.platform === 'win32' }, () => {
  const file = tmpFile();
  openStore({ file, key });
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});

test('short write is completed in a loop', async () => {
  const file = tmpFile();
  const stub = { ...fs, writeSync: (fd, buf, off, len) => fs.writeSync(fd, buf, off, Math.min(len, 7)) };
  const s = openStore({ file, key, fs: stub });
  await s.mutate((d) => { d.sessions.a = { sid: 'a' }; });
  assert.deepEqual(openStore({ file, key }).read().sessions, { a: { sid: 'a' } });
});

test('zero-progress write fails, state unchanged, tmp removed', async () => {
  const file = tmpFile();
  let stall = false;
  const stub = { ...fs, writeSync: (...a) => (stall ? 0 : fs.writeSync(...a)) };
  const s = openStore({ file, key, fs: stub });
  stall = true;
  await assert.rejects(s.mutate((d) => { d.sessions.a = {}; }), /short write/);
  assert.deepEqual(s.read().sessions, {});
  assert.deepEqual(fs.readdirSync(path.dirname(file)), ['store.json']);
});

test('returned and closure-held references do not alias live state', async () => {
  const s = openStore({ file: tmpFile(), key });
  let held;
  const ret = await s.mutate((d) => { held = d.sessions; d.sessions.a = { sid: 'a' }; return d.sessions; });
  held.b = {}; ret.a.sid = 'x';
  assert.deepEqual(s.read().sessions, { a: { sid: 'a' } });
});

test('directory fsync on posix; its failure does not fail the write', async () => {
  const file = tmpFile();
  let dirSynced = 0;
  const stub = { ...fs, fsyncSync: (fd) => { if (fs.fstatSync(fd).isDirectory()) { dirSynced++; throw new Error('dirsync'); } return fs.fsyncSync(fd); } };
  const origWarn = console.warn; console.warn = () => {};
  try {
    const s = openStore({ file, key, fs: stub, platform: 'linux' });
    const before = dirSynced;
    await s.mutate((d) => { d.sessions.a = {}; });
    assert.ok(dirSynced > before);
    assert.deepEqual(s.read().sessions, { a: {} });
    assert.deepEqual(openStore({ file, key }).read().sessions, { a: {} });
  } finally { console.warn = origWarn; }
});

test('no directory fsync on win32', async () => {
  let dirSynced = 0;
  const stub = { ...fs, fsyncSync: (fd) => { if (fs.fstatSync(fd).isDirectory()) dirSynced++; return fs.fsyncSync(fd); } };
  const s = openStore({ file: tmpFile(), key, fs: stub, platform: 'win32' });
  await s.mutate((d) => { d.sessions.a = {}; });
  assert.equal(dirSynced, 0);
});

test('tmp file name collision (EEXIST) is retried', async () => {
  const file = tmpFile();
  let n = 0;
  const stub = { ...fs, openSync: (p, f, m) => { if (f === 'wx' && n++ < 2) { const e = new Error('x'); e.code = 'EEXIST'; throw e; } return fs.openSync(p, f, m); } };
  const s = openStore({ file, key, fs: stub });
  assert.ok(s.read());
  assert.ok(n >= 3);
});

test('malformed state collections -> StoreCorruptError', () => {
  for (const bad of [[], 'x', null, 5]) {
    const file = tmpFile();
    const s = openStore({ file, key });
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    parsed.state.sessions = bad;
    fs.writeFileSync(file, JSON.stringify(parsed));
    assert.throws(() => openStore({ file, key }), StoreCorruptError);
    assert.ok(s);
  }
  const file = tmpFile();
  openStore({ file, key });
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  parsed.state = [];
  fs.writeFileSync(file, JSON.stringify(parsed));
  assert.throws(() => openStore({ file, key }), StoreCorruptError);
});

test('missing collection is filled empty', () => {
  const file = tmpFile();
  openStore({ file, key });
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  delete parsed.state.cleanups;
  fs.writeFileSync(file, JSON.stringify(parsed));
  assert.deepEqual(openStore({ file, key }).read().cleanups, {});
});

test('after a failed write the next mutate succeeds and file has only the second change', async () => {
  const file = tmpFile();
  let fail = false;
  const stub = { ...fs, renameSync: (...a) => { if (fail) throw new Error('boom'); return fs.renameSync(...a); } };
  const s = openStore({ file, key, fs: stub });
  fail = true;
  await assert.rejects(s.mutate((d) => { d.sessions.first = {}; }), /boom/);
  fail = false;
  await s.mutate((d) => { d.sessions.second = {}; });
  assert.deepEqual(Object.keys(openStore({ file, key }).read().sessions), ['second']);
  assert.deepEqual(Object.keys(s.read().sessions), ['second']);
});

test('non-cloneable value on the draft: memory equals what is on disk', async () => {
  const file = tmpFile();
  const s = openStore({ file, key });
  await s.mutate((d) => { d.sessions.a = { sid: 'a', fn: () => 1 }; });
  assert.deepEqual(s.read(), openStore({ file, key }).read());
  assert.deepEqual(s.read().sessions, { a: { sid: 'a' } });
});

test('dir fsync failure logs a warning', async () => {
  const stubFile = tmpFile();
  const stub = { ...fs, fsyncSync: (fd) => { if (fs.fstatSync(fd).isDirectory()) throw new Error('dirsync'); return fs.fsyncSync(fd); } };
  const origWarn = console.warn; const msgs = []; console.warn = (m) => msgs.push(String(m));
  try {
    const s = openStore({ file: stubFile, key, fs: stub, platform: 'linux' });
    await s.mutate((d) => { d.sessions.a = { marker: 'SECRET-MARKER-123' }; });
    assert.ok(msgs.length >= 1);
    const file = JSON.parse(fs.readFileSync(stubFile, 'utf8'));
    for (const m of msgs) {
      assert.ok(!m.includes('SECRET-MARKER-123'));
      assert.ok(!m.includes(file.check));
      assert.ok(!m.includes(key.toString('base64')));
      assert.ok(!m.includes(key.toString('base64url')));
      assert.ok(!m.includes(key.toString('hex')));
    }
  } finally { console.warn = origWarn; }
});

test('EEXIST retries are bounded', async () => {
  const file = tmpFile();
  let eexist = false; let n = 0;
  const stub = { ...fs, openSync: (p, f, m) => { if (eexist && f === 'wx') { n++; const e = new Error('x'); e.code = 'EEXIST'; throw e; } return fs.openSync(p, f, m); } };
  const s = openStore({ file, key, fs: stub });
  eexist = true;
  await assert.rejects(s.mutate((d) => { d.sessions.a = {}; }), /temporary store file/);
  assert.ok(n >= 1 && n <= 10);
  assert.deepEqual(s.read().sessions, {});
});
