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
