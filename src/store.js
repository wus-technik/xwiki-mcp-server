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

const COLLECTIONS = ['clients', 'grants', 'sessions', 'families', 'cleanups', 'uploadNonces'];
const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

export function openStore({ file, key, fs = nodeFs, platform = process.platform }) {
  function openTmp() {
    const dir = path.dirname(file);
    for (let i = 0; i < 5; i++) {
      const tmp = path.join(dir, `.${path.basename(file)}.${randomBytes(6).toString('hex')}.tmp`);
      try {
        return { tmp, fd: fs.openSync(tmp, 'wx', 0o600) };
      } catch (err) {
        if (!err || err.code !== 'EEXIST') throw err;
      }
    }
    throw new Error('could not create temporary store file');
  }

  function writeAll(fd, buf) {
    let off = 0;
    while (off < buf.length) {
      const n = fs.writeSync(fd, buf, off, buf.length - off);
      if (!(n > 0)) throw new Error('short write to store file');
      off += n;
    }
  }

  function syncDir() {
    if (platform === 'win32') return;
    try {
      const dfd = fs.openSync(path.dirname(file), 'r');
      try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
    } catch {
      console.warn(`store: directory fsync for ${file} failed; write was renamed but may not be durable`);
    }
  }

  function write(state) {
    const buf = Buffer.from(JSON.stringify({ check: seal('ok', key, CHECK_AAD), state }), 'utf8');
    let tmp;
    try {
      let fd;
      ({ tmp, fd } = openTmp());
      try {
        writeAll(fd, buf);
        if (typeof fs.fsyncSync === 'function') fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(tmp, file);
    } catch (err) {
      if (tmp) { try { fs.rmSync(tmp, { force: true }); } catch { /* ignore */ } }
      throw err;
    }
    syncDir();
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
      if (!isPlainObject(parsed.state) || parsed.state.version !== 1) throw new Error('state');
      for (const c of COLLECTIONS) {
        if (c in parsed.state && !isPlainObject(parsed.state[c])) throw new Error('collection');
      }
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
        state = structuredClone(draft);
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
