import nodeFs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { seal, open } from './crypto-box.js';

const CHECK_AAD = 'store-check';

export class StoreCorruptError extends Error {
  constructor(file) {
    super(`Store file ${file} is unreadable or cannot be decrypted; check STORE_FILE and TOKEN_ENC_KEY (no automatic fresh start)`);
    this.name = 'StoreCorruptError';
  }
}

function emptyState() {
  return { version: 1, clients: {}, grants: {}, sessions: {}, families: {}, cleanups: {}, uploadNonces: {} };
}

export function openStore({ file, key, fs = nodeFs }) {
  function write(state) {
    const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${randomBytes(6).toString('hex')}.tmp`);
    try {
      const data = JSON.stringify({ check: seal('ok', key, CHECK_AAD), state });
      const fd = fs.openSync(tmp, 'w', 0o600);
      try {
        fs.writeSync(fd, data);
        if (typeof fs.fsyncSync === 'function') fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(tmp, file);
    } catch (err) {
      try { fs.rmSync(tmp, { force: true }); } catch { /* ignore */ }
      throw err;
    }
  }

  function load() {
    let raw;
    try {
      raw = fs.readFileSync(file, 'utf8');
    } catch (err) {
      if (err && err.code === 'ENOENT') return null;
      throw new StoreCorruptError(file);
    }
    try {
      const parsed = JSON.parse(raw);
      if (open(parsed.check, key, CHECK_AAD) !== 'ok') throw new Error('check');
      if (!parsed.state || parsed.state.version !== 1) throw new Error('state');
      return { ...emptyState(), ...parsed.state };
    } catch {
      throw new StoreCorruptError(file);
    }
  }

  let state = load();
  if (state === null) {
    state = emptyState();
    write(state);
  }

  let chain = Promise.resolve();
  const locks = new Map();

  return {
    read: () => structuredClone(state),

    mutate(fn) {
      const run = async () => {
        const draft = structuredClone(state);
        const result = await fn(draft);
        write(draft);
        state = draft;
        return result;
      };
      const p = chain.then(run);
      chain = p.catch(() => {});
      return p;
    },

    withLock(lockKey, fn) {
      const prev = locks.get(lockKey) ?? Promise.resolve();
      const p = prev.then(fn);
      const tail = p.catch(() => {});
      locks.set(lockKey, tail);
      tail.then(() => { if (locks.get(lockKey) === tail) locks.delete(lockKey); });
      return p;
    },

    sealField: (value, aad) => seal(value, key, aad),
    openField: (sealed, aad) => open(sealed, key, aad),
  };
}
