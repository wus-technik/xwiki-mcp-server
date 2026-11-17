import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const PREFIX = 'v1';
const IV_LEN = 12;
const TAG_LEN = 16;

const b64 = (buf) => buf.toString('base64url');

export function seal(plaintext, key, aad) {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_LEN });
  cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return [PREFIX, b64(iv), b64(ct), b64(cipher.getAuthTag())].join('.');
}

export function open(sealed, key, aad) {
  const parts = typeof sealed === 'string' ? sealed.split('.') : [];
  if (parts.length !== 4 || parts[0] !== PREFIX) throw new Error('invalid sealed value');
  const iv = Buffer.from(parts[1], 'base64url');
  const ct = Buffer.from(parts[2], 'base64url');
  const tag = Buffer.from(parts[3], 'base64url');
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
