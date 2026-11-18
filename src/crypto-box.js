import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const PREFIX = 'v1';
const IV_LEN = 12;
const TAG_LEN = 16;

const b64 = (buf) => buf.toString('base64url');

const ALPHABET = /^[A-Za-z0-9_-]*$/;

function decodeStrict(part) {
  if (!ALPHABET.test(part)) throw new Error('invalid sealed value');
  const buf = Buffer.from(part, 'base64url');
  if (buf.toString('base64url') !== part) throw new Error('invalid sealed value');
  return buf;
}

function checkAad(aad) {
  if (typeof aad !== 'string') throw new Error('invalid aad');
}

export function seal(plaintext, key, aad) {
  checkAad(aad);
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_LEN });
  cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return [PREFIX, b64(iv), b64(ct), b64(cipher.getAuthTag())].join('.');
}

export function open(sealed, key, aad) {
  checkAad(aad);
  const parts = typeof sealed === 'string' ? sealed.split('.') : [];
  if (parts.length !== 4 || parts[0] !== PREFIX) throw new Error('invalid sealed value');
  const iv = decodeStrict(parts[1]);
  const ct = decodeStrict(parts[2]);
  const tag = decodeStrict(parts[3]);
  if (iv.length !== IV_LEN || tag.length !== TAG_LEN) throw new Error('invalid sealed value');
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_LEN });
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  } catch {
    throw new Error('decryption failed');
  }
}
