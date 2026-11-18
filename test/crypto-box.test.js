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

test('open rejects non-canonical base64url in any part', () => {
  const [p, iv, ct, tag] = seal('plain-secret', key, 'a').split('.');
  const variants = [
    [p, iv + '!!', ct, tag],
    [p, iv, ct + '!', tag],
    [p, iv, ct, tag + '=='],
    [p, iv + '==', ct, tag],
    [p, iv, ct + ' ', tag],
  ];
  for (const v of variants) {
    assert.throws(() => open(v.join('.'), key, 'a'), /invalid sealed value/);
  }
});

test('open rejects truncated tag, flipped ciphertext and tag bytes', () => {
  const [p, iv, ct, tag] = seal('plain-secret', key, 'a').split('.');
  const flip = (s) => {
    const b = Buffer.from(s, 'base64url');
    b[0] ^= 1;
    return b.toString('base64url');
  };
  const short = Buffer.from(tag, 'base64url').subarray(0, 12).toString('base64url');
  assert.throws(() => open([p, iv, ct, short].join('.'), key, 'a'), /invalid sealed value/);
  assert.throws(() => open([p, iv, flip(ct), tag].join('.'), key, 'a'), /decryption failed/);
  assert.throws(() => open([p, iv, ct, flip(tag)].join('.'), key, 'a'), /decryption failed/);
});

test('open rejects non-string sealed values', () => {
  for (const v of [undefined, null, 42, {}, Buffer.from('v1.a.b.c')]) {
    assert.throws(() => open(v, key, 'a'), /invalid sealed value/);
  }
});

test('wrong key/aad errors are generic', () => {
  const s = seal('plain-secret', key, 'a');
  assert.throws(() => open(s, key, 'b'), (e) => e.message === 'decryption failed');
  assert.throws(() => open(s, randomBytes(32), 'a'), (e) => e.message === 'decryption failed');
});

test('non-string aad fails with generic error', () => {
  assert.throws(() => seal('x', key, undefined), /invalid aad/);
  const s = seal('x', key, 'a');
  assert.throws(() => open(s, key, 5), /invalid aad/);
});
