import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { seal, open } from '../src/crypto-box.js';

const key = randomBytes(32);

test('round trip returns the plaintext', () => {
  const s = seal('geheim', key, 'aad');
  assert.match(s, /^v1\.[\w-]+\.[\w-]*\.[\w-]+$/);
  assert.equal(open(s, key, 'aad'), 'geheim');
});

test('empty plaintext round-trips', () => {
  assert.equal(open(seal('', key, 'a'), key, 'a'), '');
});

test('two seals of the same text differ', () => {
  assert.notEqual(seal('x', key, 'a'), seal('x', key, 'a'));
});

test('open with different aad throws', () => {
  assert.throws(() => open(seal('x', key, 'a'), key, 'b'));
});

test('open with different key throws', () => {
  assert.throws(() => open(seal('x', key, 'a'), randomBytes(32), 'a'));
});

test('open throws on malformed input without leaking secrets', () => {
  const good = seal('plain-secret', key, 'a');
  const [, iv, ct, tag] = good.split('.');
  const bad = [
    'garbage',
    `v2.${iv}.${ct}.${tag}`,
    `v1.${iv}.${ct}`,
    `v1.${iv}.${ct}.${tag}.extra`,
    `v1.${iv}.${ct}.${Buffer.alloc(4).toString('base64url')}`,
    `v1.${Buffer.alloc(8).toString('base64url')}.${ct}.${tag}`,
    '',
  ];
  for (const b of bad) {
    assert.throws(() => open(b, key, 'a'), (e) => {
      assert.ok(!e.message.includes('plain-secret'));
      assert.ok(!e.message.includes(key.toString('hex')));
      return true;
    });
  }
});
