// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
// noqtis for JavaScript: the C library built to WebAssembly (dist/), with
// Uint8Array in and out. Call `await init()` once; every other function is
// synchronous. Every buffer the wrapper places in WebAssembly memory is
// wiped (nqwipe) before it is freed, on every path.

import nqload from '../dist/noqtis.js';

const CODES = Object.freeze({
  OK: 0, EARG: -1, EBUF: -2, EVRFY: -3, EDEC: -4, ERNG: -5, EMEM: -6,
  EIO: -7, ENOSUP: -8, ELIM: -9, ESTATE: -10,
});

const HASHES = [
  'sha224', 'sha256', 'sha384', 'sha512', 'sha512-224', 'sha512-256',
  'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'shake128', 'shake256',
];

let M = null; // the emscripten module
let pending = null;
let sigs = null; // name (upper case) -> {id, name, pk, sk, sig}
let kems = null; // name (upper case) -> {id, name, pk, sk, ct, ss}
let fsn = 0;

/** A noqtis error: `code` is the library's NQE* value (negative). */
export class NoqtisError extends Error {
  constructor(code, detail) {
    const base = M ? M.UTF8ToString(M._nqerr(code)) : `noqtis error ${code}`;
    super(detail ? `${base}: ${detail}` : base);
    this.name = 'NoqtisError';
    this.code = code;
  }
}

export const codes = CODES;

/** The library's message for an NQE* code. */
export function errmsg(code) {
  need();
  return M.UTF8ToString(M._nqerr(code));
}

function need() {
  if (M === null) {
    throw new Error('noqtis: call `await init()` first');
  }
}

async function cryptoSource() {
  const g = globalThis.crypto;
  if (g && typeof g.getRandomValues === 'function') {
    return g;
  }
  // Node 18 has no global WebCrypto; its node:crypto webcrypto is the same
  // getRandomValues. The specifier is a variable so bundlers leave it.
  const pv = typeof process === 'object' ? process.versions : undefined;
  if (pv && pv.node) {
    const spec = 'node:crypto';
    const c = await import(/* webpackIgnore: true */ /* @vite-ignore */ spec);
    return c.webcrypto;
  }
  throw new Error('noqtis: crypto.getRandomValues is not available');
}

/**
 * Loads the WebAssembly module. `opts.wasm` may be the module's bytes, a
 * compiled WebAssembly.Module, or a URL/path to noqtis.wasm; by default it
 * is found next to dist/noqtis.js. Safe to call more than once.
 */
export function init(opts = {}) {
  if (M !== null) {
    return Promise.resolve();
  }
  if (pending === null) {
    pending = (async () => {
      const arg = { nqcrypto: await cryptoSource(), print() {}, printErr() {} };
      const w = opts.wasm;
      if (w instanceof WebAssembly.Module) {
        arg.instantiateWasm = (imports, done) => {
          WebAssembly.instantiate(w, imports).then((inst) => done(inst, w));
          return {};
        };
      } else if (w instanceof ArrayBuffer || ArrayBuffer.isView(w)) {
        arg.wasmBinary = w instanceof ArrayBuffer ? new Uint8Array(w) : w;
      } else if (typeof w === 'string' || w instanceof URL) {
        const s = String(w);
        arg.locateFile = (p) => (p.endsWith('.wasm') ? s : p);
      }
      const m = await nqload(arg);
      M = m;
      tables();
    })();
    pending.catch(() => {
      pending = null;
    });
  }
  return pending;
}

// ---- memory -------------------------------------------------------------

const enc = new TextEncoder();

function bytes(x, what) {
  if (x instanceof Uint8Array) return x;
  if (typeof x === 'string') return enc.encode(x);
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  if (ArrayBuffer.isView(x)) {
    return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
  }
  throw new TypeError(`noqtis: ${what} must be a Uint8Array or string`);
}

function key(x, what) {
  if (!(x instanceof Uint8Array)) {
    throw new TypeError(`noqtis: ${what} must be a Uint8Array`);
  }
  return x;
}

// A scope of WebAssembly allocations, all wiped and freed by done().
class Heap {
  constructor() {
    this.bufs = [];
  }
  alloc(n) {
    const p = M._malloc(n > 0 ? n : 1);
    if (p === 0) throw new NoqtisError(CODES.EMEM);
    this.bufs.push([p, n > 0 ? n : 1]);
    return p;
  }
  put(u8) {
    const p = this.alloc(u8.length);
    M.HEAPU8.set(u8, p);
    return p;
  }
  str(s) {
    const b = enc.encode(s);
    const p = this.alloc(b.length + 1);
    M.HEAPU8.set(b, p);
    M.HEAPU8[p + b.length] = 0;
    return p;
  }
  get(p, n) {
    return M.HEAPU8.slice(p, p + n);
  }
  u32(p) {
    return M.HEAPU32[p >>> 2];
  }
  done() {
    for (const [p, n] of this.bufs) {
      M._nqwipe(p, n);
      M._free(p);
    }
    this.bufs = [];
  }
}

function run(fn) {
  need();
  const h = new Heap();
  try {
    return fn(h);
  } finally {
    h.done();
  }
}

function check(rc, detail) {
  if (rc !== CODES.OK) throw new NoqtisError(rc, detail);
}

// ---- algorithms ---------------------------------------------------------

function tables() {
  sigs = new Map();
  kems = new Map();
  run((h) => {
    const sz = h.alloc(16);
    for (let id = 1; ; id++) {
      const np = M._nqsname(id);
      if (np === 0) break;
      check(M._nqssize(id, sz));
      const name = M.UTF8ToString(np);
      sigs.set(name.toUpperCase(), {
        id, name, pk: h.u32(sz), sk: h.u32(sz + 4), sig: h.u32(sz + 8),
      });
    }
    for (let id = 1; ; id++) {
      const np = M._nqkname(id);
      if (np === 0) break;
      check(M._nqksize(id, sz));
      const name = M.UTF8ToString(np);
      kems.set(name.toUpperCase(), {
        id, name, pk: h.u32(sz), sk: h.u32(sz + 4), ct: h.u32(sz + 8),
        ss: h.u32(sz + 12),
      });
    }
  });
}

function salg(alg) {
  need();
  const a = typeof alg === 'string' ? sigs.get(alg.toUpperCase()) : undefined;
  if (!a) throw new NoqtisError(CODES.ENOSUP, `signature algorithm ${alg}`);
  return a;
}

function kalg(alg) {
  need();
  const a = typeof alg === 'string' ? kems.get(alg.toUpperCase()) : undefined;
  if (!a) throw new NoqtisError(CODES.ENOSUP, `KEM algorithm ${alg}`);
  return a;
}

function halg(alg) {
  const i = typeof alg === 'string' ? HASHES.indexOf(alg.toLowerCase()) : -1;
  if (i < 0) throw new NoqtisError(CODES.ENOSUP, `hash ${alg}`);
  return i + 1;
}

/** Every algorithm with its sizes in bytes. */
export function algs() {
  need();
  const out = [];
  for (const a of sigs.values()) {
    out.push({
      name: a.name, kind: 'sign', publicKey: a.pk, secretKey: a.sk,
      signature: a.sig,
    });
  }
  for (const a of kems.values()) {
    out.push({
      name: a.name, kind: 'kem', publicKey: a.pk, secretKey: a.sk,
      ciphertext: a.ct, sharedSecret: a.ss,
    });
  }
  for (const n of HASHES) {
    out.push({ name: n, kind: 'hash', digest: M._nqhlen(halg(n)) });
  }
  return out;
}

/** The library version, "0.1.1". */
export function version() {
  need();
  return M.UTF8ToString(M._nqver());
}

/** n bytes from crypto.getRandomValues, through the library's nqrand. */
export function random(n) {
  if (!Number.isInteger(n) || n < 0) throw new RangeError('noqtis: bad length');
  return run((h) => {
    const p = h.alloc(n);
    check(M._nqrand(p, n));
    return h.get(p, n);
  });
}

// ---- hashes -------------------------------------------------------------

/**
 * The digest of data. SHAKE takes `opts.length` (default 32 for
 * shake128, 64 for shake256).
 */
export function hash(alg, data, opts = {}) {
  const id = halg(alg);
  const d = bytes(data, 'data');
  return run((h) => {
    let n = M._nqhlen(id);
    if (opts.length !== undefined) {
      if (id < 11 && opts.length !== n) {
        throw new NoqtisError(CODES.EARG, 'length applies to SHAKE only');
      }
      n = opts.length;
    }
    const pi = h.put(d);
    const po = h.alloc(n);
    check(M._nqhash(id, pi, d.length, po, n));
    return h.get(po, n);
  });
}

/** HMAC (RFC 2104) with a SHA-2 or SHA-3 hash. */
export function hmac(alg, keyBytes, data) {
  const id = halg(alg);
  const k = bytes(keyBytes, 'key');
  const d = bytes(data, 'data');
  return run((h) => {
    const n = M._nqhlen(id);
    const pk = h.put(k);
    const pi = h.put(d);
    const po = h.alloc(n);
    check(M._nqhmac(id, pk, k.length, pi, d.length, po, n));
    return h.get(po, n);
  });
}

// ---- signatures ---------------------------------------------------------

function phid(ph) {
  return ph === undefined || ph === null || ph === false ? 0 : halg(ph);
}

function ctxof(opts) {
  return opts.ctx === undefined ? new Uint8Array(0) : bytes(opts.ctx, 'ctx');
}

export const sign = Object.freeze({
  /**
   * A key pair. `opts.seed` is the standard's seed (32 bytes, xi, for
   * ML-DSA; 3n bytes for SLH-DSA) for deterministic keys.
   */
  keygen(alg, opts = {}) {
    const a = salg(alg);
    return run((h) => {
      const pk = h.alloc(a.pk);
      const sk = h.alloc(a.sk);
      if (opts.seed !== undefined) {
        const s = key(opts.seed, 'seed');
        const ps = h.put(s);
        check(M._nqskgd(a.id, ps, s.length, pk, a.pk, sk, a.sk));
      } else {
        check(M._nqskg(a.id, pk, a.pk, sk, a.sk));
      }
      return { publicKey: h.get(pk, a.pk), secretKey: h.get(sk, a.sk) };
    });
  },

  /**
   * The signature of msg. Options: `ctx` (at most 255 bytes),
   * `deterministic` (all-zero per-signature randomness), `rnd` (that
   * randomness, explicitly), `prehash` (a hash name: HashML-DSA /
   * HashSLH-DSA; msg is hashed inside).
   */
  sign(alg, secretKey, msg, opts = {}) {
    const a = salg(alg);
    const sk = key(secretKey, 'secretKey');
    const m = bytes(msg, 'msg');
    const c = ctxof(opts);
    const ph = phid(opts.prehash);
    return run((h) => {
      const psk = h.put(sk);
      const pm = h.put(m);
      const pc = h.put(c);
      const ps = h.alloc(a.sig);
      const pn = h.alloc(4);
      let rc;
      if (opts.rnd !== undefined || opts.deterministic) {
        // 32 for ML-DSA and the hybrids, none for Ed25519, n for SLH-DSA
        const n = a.name === 'Ed25519' ? 0
          : a.name.startsWith('ML-DSA') ? 32 : a.pk / 2;
        const r = opts.rnd !== undefined ? key(opts.rnd, 'rnd')
          : new Uint8Array(n);
        const pr = h.put(r);
        rc = M._nqsignd(a.id, psk, sk.length, pm, m.length, pc, c.length, ph,
          pr, r.length, ps, a.sig, pn);
      } else {
        rc = M._nqsign(a.id, psk, sk.length, pm, m.length, pc, c.length, ph,
          ps, a.sig, pn);
      }
      check(rc);
      return h.get(ps, h.u32(pn));
    });
  },

  /**
   * true when sig is a valid signature of msg under publicKey (with the
   * same `ctx` and `prehash`); false when it does not verify or is not a
   * well-formed signature. Bad arguments throw.
   */
  verify(alg, publicKey, msg, sig, opts = {}) {
    const a = salg(alg);
    const pk = key(publicKey, 'publicKey');
    const m = bytes(msg, 'msg');
    const s = key(sig, 'sig');
    const c = ctxof(opts);
    const ph = phid(opts.prehash);
    return run((h) => {
      const rc = M._nqvrfy(a.id, h.put(pk), pk.length, h.put(m), m.length,
        h.put(c), c.length, ph, h.put(s), s.length);
      if (rc === CODES.OK) return true;
      if (rc === CODES.EVRFY || rc === CODES.EDEC) return false;
      throw new NoqtisError(rc);
    });
  },
});

// ---- key encapsulation --------------------------------------------------

export const kem = Object.freeze({
  /** A key pair; `opts.seed` (d || z for ML-KEM) for deterministic keys. */
  keygen(alg, opts = {}) {
    const a = kalg(alg);
    return run((h) => {
      const pk = h.alloc(a.pk);
      const sk = h.alloc(a.sk);
      if (opts.seed !== undefined) {
        const s = key(opts.seed, 'seed');
        check(M._nqkkgd(a.id, h.put(s), s.length, pk, a.pk, sk, a.sk));
      } else {
        check(M._nqkkg(a.id, pk, a.pk, sk, a.sk));
      }
      return { publicKey: h.get(pk, a.pk), secretKey: h.get(sk, a.sk) };
    });
  },

  /** { ciphertext, sharedSecret } for publicKey; `opts.seed` for tests. */
  encap(alg, publicKey, opts = {}) {
    const a = kalg(alg);
    const pk = key(publicKey, 'publicKey');
    return run((h) => {
      const ppk = h.put(pk);
      const ct = h.alloc(a.ct);
      const ss = h.alloc(a.ss);
      if (opts.seed !== undefined) {
        const s = key(opts.seed, 'seed');
        check(M._nqencd(a.id, ppk, pk.length, h.put(s), s.length, ct, a.ct,
          ss, a.ss));
      } else {
        check(M._nqenc(a.id, ppk, pk.length, ct, a.ct, ss, a.ss));
      }
      return { ciphertext: h.get(ct, a.ct), sharedSecret: h.get(ss, a.ss) };
    });
  },

  /**
   * The shared secret. A tampered ciphertext gives an unrelated secret,
   * not an error (implicit rejection); only malformed sizes throw.
   */
  decap(alg, secretKey, ciphertext) {
    const a = kalg(alg);
    const sk = key(secretKey, 'secretKey');
    const c = key(ciphertext, 'ciphertext');
    return run((h) => {
      const ss = h.alloc(a.ss);
      check(M._nqdec(a.id, h.put(sk), sk.length, h.put(c), c.length, ss,
        a.ss));
      return h.get(ss, a.ss);
    });
  },
});

// ---- capsules (in-memory file system) -----------------------------------

function entries(files) {
  let it;
  if (files instanceof Map) it = files.entries();
  else if (Array.isArray(files)) it = files;
  else if (files && typeof files === 'object') it = Object.entries(files);
  else throw new TypeError('noqtis: files must be a Map or an object');
  const out = [];
  for (const [p, data] of it) {
    if (typeof p !== 'string') throw new TypeError('noqtis: bad file name');
    const parts = p.split('/');
    if (p.includes('\0') ||
        parts.some((s) => s === '' || s === '.' || s === '..')) {
      throw new NoqtisError(CODES.EARG, `file name ${JSON.stringify(p)}`);
    }
    out.push([parts, bytes(data, p)]);
  }
  return out;
}

function rmtree(path) {
  const st = M.FS.lstat(path);
  if (M.FS.isDir(st.mode)) {
    for (const n of M.FS.readdir(path)) {
      if (n !== '.' && n !== '..') rmtree(`${path}/${n}`);
    }
    M.FS.rmdir(path);
  } else {
    M.FS.unlink(path);
  }
}

// Writes files under a fresh folder, runs fn(dir), removes the folder.
function withdir(files, fn) {
  need();
  const list = entries(files);
  const dir = `/nq${++fsn}`;
  M.FS.mkdir(dir);
  try {
    for (const [parts, data] of list) {
      let d = dir;
      for (let i = 0; i < parts.length - 1; i++) {
        d += `/${parts[i]}`;
        const st = M.FS.analyzePath(d);
        if (!st.exists) M.FS.mkdir(d);
        else if (!M.FS.isDir(st.object.mode)) {
          throw new NoqtisError(CODES.EARG,
            `${parts.join('/')} is under a file`);
        }
      }
      const f = `${dir}/${parts.join('/')}`;
      if (M.FS.analyzePath(f).exists) {
        throw new NoqtisError(CODES.EARG, `${parts.join('/')} given twice`);
      }
      M.FS.writeFile(f, data);
    }
    return fn(dir);
  } finally {
    rmtree(dir);
  }
}

function report(h, rp) {
  const r = h.u32(rp);
  const checks = [];
  if (r === 0) return checks;
  try {
    const n = M._nqrepn(r);
    const pc = h.alloc(4);
    const po = h.alloc(4);
    const pd = h.alloc(4);
    for (let i = 0; i < n; i++) {
      check(M._nqrepi(r, i, pc, po, pd));
      const d = h.u32(pd);
      checks.push({
        check: M.UTF8ToString(h.u32(pc)),
        ok: h.u32(po) !== 0,
        detail: d === 0 ? '' : M.UTF8ToString(d),
      });
    }
  } finally {
    M._nqrepfree(r);
  }
  return checks;
}

export const capsule = Object.freeze({
  /**
   * Checks a capsule given as its files (a Map, an object or [path, bytes]
   * pairs, with '/' between folders), including noqtis.json and
   * noqtis.sig. Options: `trust` (the public key the seal must carry;
   * without it the seal's own key is accepted and the report says so),
   * `anchors` (DER certificates of TSA trust anchors, at most 32).
   * Returns { ok, code, checks: [{ check, ok, detail }] }.
   */
  check(files, opts = {}) {
    return withdir(files, (dir) => run((h) => {
      const t = opts.trust === undefined ? null : key(opts.trust, 'trust');
      const anc = opts.anchors === undefined ? [] : opts.anchors;
      const pa = h.alloc(4 * anc.length);
      const pl = h.alloc(4 * anc.length);
      anc.forEach((c, i) => {
        const b = key(c, 'anchor');
        M.HEAPU32[(pa >>> 2) + i] = h.put(b);
        M.HEAPU32[(pl >>> 2) + i] = b.length;
      });
      const rp = h.alloc(4);
      M.HEAPU32[rp >>> 2] = 0;
      const rc = M._nqchkt(h.str(dir), t ? h.put(t) : 0, t ? t.length : 0,
        anc.length ? pa : 0, anc.length ? pl : 0, anc.length, rp);
      const checks = report(h, rp);
      if (rc !== CODES.OK && rc !== CODES.EVRFY) throw new NoqtisError(rc);
      return { ok: rc === CODES.OK, code: rc, checks };
    }));
  },

  /**
   * Seals the files: returns { 'noqtis.json', 'noqtis.sig' } as bytes, to
   * store beside them. Options: `meta` (a JSON value or JSON text, kept in
   * the manifest), `time` (creation time in seconds since 1970; default
   * the clock).
   */
  seal(files, alg, secretKey, publicKey, opts = {}) {
    const a = salg(alg);
    const sk = key(secretKey, 'secretKey');
    const pk = key(publicKey, 'publicKey');
    let meta = null;
    if (opts.meta !== undefined) {
      meta = typeof opts.meta === 'string' ? opts.meta
        : JSON.stringify(opts.meta);
    }
    return withdir(files, (dir) => run((h) => {
      const ev = h.str('SOURCE_DATE_EPOCH');
      if (opts.time !== undefined) {
        if (!Number.isSafeInteger(opts.time) || opts.time < 0) {
          throw new NoqtisError(CODES.EARG, 'time');
        }
        M._setenv(ev, h.str(String(opts.time)), 1);
      } else {
        M._unsetenv(ev);
      }
      try {
        check(M._nqseal(h.str(dir), a.id, h.put(sk), sk.length, h.put(pk),
          pk.length, meta === null ? 0 : h.str(meta), 0));
      } finally {
        M._unsetenv(ev);
      }
      return {
        'noqtis.json': M.FS.readFile(`${dir}/noqtis.json`),
        'noqtis.sig': M.FS.readFile(`${dir}/noqtis.sig`),
      };
    }));
  },
});

// ---- key files (the CLI's text format) ----------------------------------

// Base64 (RFC 4648) without table lookups or branches on the data, as the
// CLI's coder; JavaScript engines promise nothing about timing, so this
// is best effort.
function b64e(u8) {
  const ch = (x) => {
    // 0-25 'A'.., 26-51 'a'.., 52-61 '0'.., 62 '+', 63 '/'
    let c = x + 65;
    c += ((25 - x) >> 8) & 6;
    c -= ((51 - x) >> 8) & 75;
    c -= ((61 - x) >> 8) & 15;
    c += ((62 - x) >> 8) & 3;
    return c;
  };
  let s = '';
  for (let i = 0; i < u8.length; i += 3) {
    const n = u8.length - i;
    const v = (u8[i] << 16) | ((n > 1 ? u8[i + 1] : 0) << 8) |
      (n > 2 ? u8[i + 2] : 0);
    s += String.fromCharCode(ch((v >> 18) & 63), ch((v >> 12) & 63));
    s += n > 1 ? String.fromCharCode(ch((v >> 6) & 63)) : '=';
    s += n > 2 ? String.fromCharCode(ch(v & 63)) : '=';
  }
  return s;
}

function b64d(s) {
  const val = (c) => {
    // -1 for a character outside the alphabet
    const ge = (a) => ((a - c - 1) >> 8) & 1; // c >= a
    const le = (b) => ((c - b - 1) >> 8) & 1; // c <= b
    const up = ge(65) & le(90);
    const lo = ge(97) & le(122);
    const di = ge(48) & le(57);
    const pl = ((c ^ 43) - 1) >> 8 & 1;
    const sl = ((c ^ 47) - 1) >> 8 & 1;
    const v = (-up & (c - 65)) | (-lo & (c - 71)) | (-di & (c + 4)) |
      (-pl & 62) | (-sl & 63);
    return v | (-(1 - (up | lo | di | pl | sl)) & -1);
  };
  if (s.length % 4 !== 0) throw new NoqtisError(CODES.EDEC, 'base64 length');
  let pad = 0;
  if (s.endsWith('==')) pad = 2;
  else if (s.endsWith('=')) pad = 1;
  const out = new Uint8Array((s.length / 4) * 3 - pad);
  let bad = 0;
  let o = 0;
  for (let i = 0; i < s.length; i += 4) {
    const last = i + 4 === s.length;
    const q = [0, 1, 2, 3].map((j) => {
      const c = s.charCodeAt(i + j);
      if (last && j >= 4 - pad) {
        bad |= c ^ 61;
        return 0;
      }
      const v = val(c);
      bad |= v >> 31;
      return v & 63;
    });
    const v = (q[0] << 18) | (q[1] << 12) | (q[2] << 6) | q[3];
    const k = last ? 3 - pad : 3;
    out[o++] = (v >> 16) & 255;
    if (k > 1) out[o++] = (v >> 8) & 255;
    if (k > 2) out[o++] = v & 255;
    // canonical padding: the unused bits are zero
    if (last && pad === 1) bad |= v & 0xff;
    if (last && pad === 2) bad |= v & 0xffff;
  }
  if (bad !== 0) {
    out.fill(0);
    throw new NoqtisError(CODES.EDEC, 'not canonical base64');
  }
  return out;
}

export const keyfile = Object.freeze({
  /** The CLI's key file text for a key: kind is 'pub' or 'sec'. */
  encode(alg, kind, keyBytes) {
    need();
    const a = sigs.get(String(alg).toUpperCase()) ||
      kems.get(String(alg).toUpperCase());
    if (!a) throw new NoqtisError(CODES.ENOSUP, `algorithm ${alg}`);
    if (kind !== 'pub' && kind !== 'sec') {
      throw new NoqtisError(CODES.EARG, 'kind must be pub or sec');
    }
    const k = key(keyBytes, 'key');
    if (k.length !== (kind === 'pub' ? a.pk : a.sk)) {
      throw new NoqtisError(CODES.EARG, 'key length');
    }
    const b = b64e(k);
    let s = `noqtis-key-1 ${a.name} ${kind}\n`;
    for (let i = 0; i < b.length; i += 64) s += `${b.slice(i, i + 64)}\n`;
    return s;
  },

  /** { alg, kind, key } from key file text, strictly as the CLI reads it. */
  decode(text) {
    need();
    if (typeof text !== 'string') text = new TextDecoder().decode(bytes(text));
    const lines = text.split('\n').map((l) => (l.endsWith('\r')
      ? l.slice(0, -1) : l));
    if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop();
    const head = lines.shift() || '';
    const f = head.split(' ');
    if (f.length !== 3 || f[0] !== 'noqtis-key-1' ||
        (f[2] !== 'pub' && f[2] !== 'sec')) {
      throw new NoqtisError(CODES.EDEC, 'not a noqtis key file');
    }
    const a = sigs.get(f[1].toUpperCase()) || kems.get(f[1].toUpperCase());
    if (!a || a.name !== f[1]) {
      throw new NoqtisError(CODES.ENOSUP, `algorithm ${f[1]}`);
    }
    const body = lines.join('');
    const k = b64d(body);
    if (k.length !== (f[2] === 'pub' ? a.pk : a.sk)) {
      k.fill(0);
      throw new NoqtisError(CODES.EDEC, 'key length');
    }
    return { alg: a.name, kind: f[2], key: k };
  },
});

// For the package's own tests: the WebAssembly memory, to check that no
// secret is left in it. Not part of the API.
export function _heap() {
  need();
  return M.HEAPU8;
}

export default {
  init, version, algs, random, hash, hmac, sign, kem, capsule, keyfile,
  NoqtisError, codes, errmsg,
};
