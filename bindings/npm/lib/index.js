// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
// noqtis for JavaScript: the C library built to WebAssembly (dist/), with
// Uint8Array in and out. Call `await init()` once; every other function is
// synchronous. Every buffer the wrapper places in WebAssembly memory is
// wiped (nqwipe) before it is freed, on every path.

import { instance } from './wasm.js';

const CODES = Object.freeze({
  OK: 0, EARG: -1, EBUF: -2, EVRFY: -3, EDEC: -4, ERNG: -5, EMEM: -6,
  EIO: -7, ENOSUP: -8, ELIM: -9, ESTATE: -10, EFLT: -11, EKAT: -12,
});

const HASHES = [
  'sha224', 'sha256', 'sha384', 'sha512', 'sha512-224', 'sha512-256',
  'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'shake128', 'shake256',
];

let M = null; // the WebAssembly module (wasm.js)
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

/**
 * Loads the WebAssembly module. `opts.wasm` is noqtis.wasm: its bytes, a
 * compiled WebAssembly.Module or a Response. This entry (the browser one)
 * reads no file and makes no request, so in a browser pass it; on Node,
 * Deno and Bun the package's main entry (main.js) finds the package's own
 * file and also takes a path. Randomness comes from crypto.getRandomValues
 * (WebCrypto) and from nothing else: without it init() fails. Safe to call
 * more than once.
 */
export function init(opts = {}) {
  if (M !== null) {
    return Promise.resolve();
  }
  if (pending === null) {
    pending = (async () => {
      const w = opts.wasm;
      if (w === undefined || typeof w === 'string' || w instanceof URL) {
        throw new TypeError('noqtis: pass the WebAssembly module to init(): '
          + '`await init({ wasm })` with the bytes of noqtis.wasm, a '
          + 'WebAssembly.Module or a Response (the package exports the file '
          + 'as noqtis/noqtis.wasm)');
      }
      M = await instance(w, globalThis.crypto);
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

/** The library version, "0.3.0". */
export function version() {
  need();
  return M.UTF8ToString(M._nqver());
}

/**
 * Runs the library's known-answer self-test (every family, about a tenth
 * of a second); throws a NoqtisError with code EKAT when an answer
 * differs.
 */
export function selftest() {
  need();
  check(M._nqselftest(), 'self-test');
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
  /**
   * The 64-byte message representative mu of FIPS 204 for msg under
   * publicKey, as sign() computes it (ML-DSA; opts ctx and prehash), so
   * the message can be hashed away from the key.
   */
  mu(alg, publicKey, msg, opts = {}) {
    const a = salg(alg);
    const pk = key(publicKey, 'publicKey');
    const m = bytes(msg, 'msg');
    const c = ctxof(opts);
    return run((h) => {
      const o = h.alloc(64);
      check(M._nqsmu(a.id, h.put(pk), pk.length, h.put(m), m.length, h.put(c),
        c.length, phid(opts.prehash), o, 64));
      return h.get(o, 64);
    });
  },

  /**
   * The signature of the message whose mu is mu: the bytes sign() gives for
   * it with the same randomness (opts rnd or deterministic).
   */
  signmu(alg, secretKey, mu, opts = {}) {
    const a = salg(alg);
    const sk = key(secretKey, 'secretKey');
    const u = key(mu, 'mu');
    return run((h) => {
      const r = opts.rnd !== undefined ? key(opts.rnd, 'rnd')
        : opts.deterministic ? new Uint8Array(32) : null;
      const ps = h.alloc(a.sig);
      const pn = h.alloc(4);
      check(M._nqsignmu(a.id, h.put(sk), sk.length, h.put(u), u.length,
        r === null ? 0 : h.put(r), r === null ? 0 : r.length, ps, a.sig, pn));
      return h.get(ps, h.u32(pn));
    });
  },

  /** true when sig verifies for the message whose mu is mu. */
  verifymu(alg, publicKey, mu, sig) {
    const a = salg(alg);
    const pk = key(publicKey, 'publicKey');
    const u = key(mu, 'mu');
    const s = key(sig, 'sig');
    return run((h) => {
      const rc = M._nqvrfymu(a.id, h.put(pk), pk.length, h.put(u), u.length,
        h.put(s), s.length);
      if (rc === CODES.OK) return true;
      if (rc === CODES.EVRFY || rc === CODES.EDEC) return false;
      throw new NoqtisError(rc);
    });
  },

  /**
   * A signature over a message given in pieces: update() any number of
   * times, then sign(), the bytes sign() gives for the whole message with
   * the same randomness. Only the piece at hand is held; secretKey is the
   * caller's array, not a copy. ML-DSA (pure and pre-hash), and
   * HashSLH-DSA, Ed25519ph and the hybrids with prehash 'sha512'; the
   * others throw ENOSUP. One use: then ESTATE.
   */
  signer(alg, secretKey, opts = {}) {
    const a = salg(alg);
    const sk = key(secretKey, 'secretKey');
    const c = new Ctx(160 * 8);
    try {
      run((h) => {
        const x = ctxof(opts);
        check(M._nqsini(c.p, a.id, h.put(sk), sk.length, h.put(x), x.length,
          phid(opts.prehash)));
      });
    } catch (e) {
      c.end();
      throw e;
    }
    return Object.freeze({
      update(data) {
        const d = bytes(data, 'data');
        run((h) => check(M._nqsupd(c.live(), h.put(d), d.length)));
        return this;
      },
      sign(o = {}) {
        try {
          return run((h) => {
            const n = a.name === 'Ed25519' ? 0
              : a.name.startsWith('ML-DSA') ? 32 : a.pk / 2;
            const r = o.rnd !== undefined ? key(o.rnd, 'rnd')
              : o.deterministic ? new Uint8Array(n) : null;
            const ps = h.alloc(a.sig);
            const pn = h.alloc(4);
            // a present but empty rnd: a pointer that is not NULL
            const pr = r === null ? 0 : r.length === 0 ? h.alloc(1) : h.put(r);
            check(M._nqsfin(c.live(), h.put(sk), sk.length, pr,
              r === null ? 0 : r.length, ps, a.sig, pn));
            return h.get(ps, h.u32(pn));
          });
        } finally {
          c.end();
        }
      },
      /** Wipes and frees the context without signing. */
      end() {
        c.end();
      },
    });
  },

  /** verify() over a message given in pieces: update(), then verify(sig). */
  verifier(alg, publicKey, opts = {}) {
    const a = salg(alg);
    const pk = key(publicKey, 'publicKey');
    const c = new Ctx(160 * 8);
    try {
      run((h) => {
        const x = ctxof(opts);
        check(M._nqvini(c.p, a.id, h.put(pk), pk.length, h.put(x), x.length,
          phid(opts.prehash)));
      });
    } catch (e) {
      c.end();
      throw e;
    }
    return Object.freeze({
      update(data) {
        const d = bytes(data, 'data');
        run((h) => check(M._nqsupd(c.live(), h.put(d), d.length)));
        return this;
      },
      verify(sig) {
        const s = key(sig, 'sig');
        try {
          return run((h) => {
            const rc = M._nqvfin(c.live(), h.put(pk), pk.length, h.put(s),
              s.length);
            if (rc === CODES.OK) return true;
            if (rc === CODES.EVRFY || rc === CODES.EDEC) return false;
            throw new NoqtisError(rc);
          });
        } finally {
          c.end();
        }
      },
      end() {
        c.end();
      },
    });
  },
});

// ---- contexts, BLAKE2b, Argon2id, streaming hashes -----------------------

// A context in WebAssembly memory that outlives one call: wiped and freed
// by end(), or by the garbage collector when it is dropped unfinished.
const lost = typeof FinalizationRegistry === 'function'
  ? new FinalizationRegistry(([p, n]) => {
    if (M !== null) {
      M._nqwipe(p, n);
      M._free(p);
    }
  }) : null;

class Ctx {
  constructor(n) {
    need();
    this.n = n;
    this.p = M._malloc(n);
    if (this.p === 0) throw new NoqtisError(CODES.EMEM);
    M.HEAPU8.fill(0, this.p, this.p + n);
    if (lost) lost.register(this, [this.p, n], this);
  }
  live() {
    if (this.p === 0) throw new NoqtisError(CODES.ESTATE);
    return this.p;
  }
  end() {
    if (this.p !== 0) {
      M._nqwipe(this.p, this.n);
      M._free(this.p);
      if (lost) lost.unregister(this);
      this.p = 0;
    }
  }
}

/** true when a and b are equal, in time that depends only on their length. */
export function cteq(a, b) {
  const x = bytes(a, 'a');
  const y = bytes(b, 'b');
  if (x.length !== y.length) return false;
  return run((h) => M._nqcteq(h.put(x), h.put(y), x.length) === 1);
}

/**
 * BLAKE2b (RFC 7693): an `opts.length`-byte digest (1 to 64, default 64)
 * of data, keyed (a MAC) with `opts.key` (up to 64 bytes).
 */
export function blake2b(data, opts = {}) {
  const d = bytes(data, 'data');
  const k = opts.key === undefined ? new Uint8Array(0) : bytes(opts.key, 'key');
  const n = opts.length === undefined ? 64 : opts.length;
  if (!Number.isInteger(n) || n < 1 || n > 64) {
    throw new NoqtisError(CODES.EARG, 'length: 1 to 64');
  }
  return run((h) => {
    const o = h.alloc(n);
    check(M._nqb2b(h.put(k), k.length, h.put(d), d.length, o, n));
    return h.get(o, n);
  });
}

function kt(bits, def, data, opts) {
  const d = bytes(data, 'data');
  const c = opts.custom === undefined ? new Uint8Array(0) : bytes(opts.custom, 'custom');
  const n = opts.length === undefined ? def : opts.length;
  if (!Number.isInteger(n) || n < 1) {
    throw new NoqtisError(CODES.EARG, 'length: 1 or more');
  }
  return run((h) => {
    const o = h.alloc(n);
    check(M._nqkt(bits, h.put(d), d.length, h.put(c), c.length, o, n));
    return h.get(o, n);
  });
}

/**
 * KangarooTwelve KT128 (RFC 9861): `opts.length` bytes (default 32) of
 * the tree hash and extendable-output function, with an optional
 * customization string `opts.custom` (a secret key there makes it a MAC).
 */
export function kt128(data, opts = {}) {
  return kt(128, 32, data, opts);
}

/** KangarooTwelve KT256 (RFC 9861): as kt128, at 256 bits (default 64 bytes). */
export function kt256(data, opts = {}) {
  return kt(256, 64, data, opts);
}

/**
 * The ChaCha20 stream cipher (RFC 8439): data XORed with the key stream
 * of the 32-byte key and the 12-byte nonce, from block `opts.counter`
 * (default 0). The same call decrypts.
 *
 * NOT AUTHENTICATED: a changed ciphertext decrypts to a changed plaintext
 * with no error, and a key and nonce used for two messages give away
 * their XOR. To encrypt, use sivenc or gsivenc.
 */
export function chacha20(key, nonce, data, opts = {}) {
  const k = bytes(key, 'key');
  const nc = bytes(nonce, 'nonce');
  const d = bytes(data, 'data');
  const ctr = opts.counter === undefined ? 0 : opts.counter;
  if (!Number.isInteger(ctr) || ctr < 0 || ctr > 0xffffffff) {
    throw new NoqtisError(CODES.EARG, 'counter: 0 to 2^32 - 1');
  }
  return run((h) => {
    const o = h.alloc(d.length);
    check(M._nqcha20(h.put(k), k.length, h.put(nc), nc.length, ctr | 0, h.put(d), d.length, o));
    return h.get(o, d.length);
  });
}

function siv(dec, key, data, ad) {
  const k = bytes(key, 'key');
  const d = bytes(data, 'data');
  if (ad === undefined) ad = [];
  if (!Array.isArray(ad)) {
    throw new NoqtisError(CODES.EARG, 'ad: an array of byte strings');
  }
  const a = ad.map((x) => bytes(x, 'ad'));
  if (a.length > 126 || (dec && d.length < 16)) throw new NoqtisError(CODES.EARG);
  const n = dec ? d.length - 16 : d.length + 16;
  return run((h) => {
    const p = h.alloc(4 * a.length);
    const l = h.alloc(4 * a.length);
    for (let i = 0; i < a.length; i++) {
      M.HEAPU32[(p >>> 2) + i] = h.put(a[i]);
      M.HEAPU32[(l >>> 2) + i] = a[i].length;
    }
    const o = h.alloc(n);
    const f = dec ? M._nqsivdec : M._nqsivenc;
    check(f(h.put(k), k.length, p, l, a.length, h.put(d), d.length, o, n));
    return h.get(o, n);
  });
}

/**
 * AES-SIV (RFC 5297), deterministic authenticated encryption: the 16-byte
 * synthetic IV, then the ciphertext. key is 32, 48 or 64 bytes; ad is an
 * array of up to 126 associated strings, authenticated and not encrypted
 * (a nonce, where there is one, is by convention the last). The same
 * input always gives the same output.
 */
export function sivenc(key, data, ad) {
  return siv(false, key, data, ad);
}

/** The plaintext of sivenc; NoqtisError (EVRFY) when it does not verify. */
export function sivdec(key, data, ad) {
  return siv(true, key, data, ad);
}

function gsiv(dec, key, nonce, data, ad) {
  const k = bytes(key, 'key');
  const nc = bytes(nonce, 'nonce');
  const d = bytes(data, 'data');
  const a = ad === undefined ? new Uint8Array(0) : bytes(ad, 'ad');
  if (dec && d.length < 16) throw new NoqtisError(CODES.EARG);
  const n = dec ? d.length - 16 : d.length + 16;
  return run((h) => {
    const o = h.alloc(n);
    const f = dec ? M._nqgsivdec : M._nqgsivenc;
    check(f(h.put(k), k.length, h.put(nc), nc.length, h.put(a), a.length, h.put(d), d.length, o, n));
    return h.get(o, n);
  });
}

/**
 * AES-GCM-SIV (RFC 8452), authenticated encryption that resists a nonce
 * used twice: the ciphertext, then the 16-byte tag. key is 16 or 32
 * bytes, nonce 12; ad is the associated data.
 */
export function gsivenc(key, nonce, data, ad) {
  return gsiv(false, key, nonce, data, ad);
}

/** The plaintext of gsivenc; NoqtisError (EVRFY) when it does not verify. */
export function gsivdec(key, nonce, data, ad) {
  return gsiv(true, key, nonce, data, ad);
}

/**
 * Argon2id (RFC 9106, version 0x13): `opts.length` bytes (4 to 1024,
 * default 32) from the password and the salt (8 bytes or more), `opts.t`
 * passes (3) over `opts.m` KiB (65536) in `opts.p` lanes (4), with an
 * optional secret `opts.key` and associated data `opts.ad`.
 */
export function argon2id(pw, salt, opts = {}) {
  const p = bytes(pw, 'pw');
  const s = bytes(salt, 'salt');
  const k = opts.key === undefined ? new Uint8Array(0) : bytes(opts.key, 'key');
  const a = opts.ad === undefined ? new Uint8Array(0) : bytes(opts.ad, 'ad');
  const n = opts.length === undefined ? 32 : opts.length;
  const num = (x, d) => (x === undefined ? d : x);
  const t = num(opts.t, 3);
  const m = num(opts.m, 65536);
  const l = num(opts.p, 4);
  for (const v of [n, t, m, l]) {
    if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) {
      throw new NoqtisError(CODES.EARG, 'a cost or length');
    }
  }
  return run((h) => {
    const o = h.alloc(n);
    check(M._nqa2id(h.put(p), p.length, h.put(s), s.length, h.put(k),
      k.length, h.put(a), a.length, t, m, l, o, n));
    return h.get(o, n);
  });
}

/**
 * A digest of data given in pieces, as hash() gives it for the whole:
 * update() any number of times, then digest(); for SHAKE, digest(n) may
 * be called again to squeeze more output.
 */
export function hasher(alg) {
  const i = halg(alg);
  const c = new Ctx(52 * 8);
  check(M._nqhini(c.p, i));
  const n = M._nqhlen(i);
  const shake = i >= 11;
  return Object.freeze({
    update(data) {
      const d = bytes(data, 'data');
      run((h) => check(M._nqhupd(c.live(), h.put(d), d.length)));
      return this;
    },
    digest(len) {
      if (len !== undefined && !shake) {
        throw new NoqtisError(CODES.EARG, 'a length is for SHAKE');
      }
      const k = len === undefined ? n : len;
      return run((h) => {
        const o = h.alloc(k);
        check(M._nqhfin(c.live(), o, k));
        return h.get(o, k);
      });
    },
    /** Wipes and frees the context. */
    end() {
      c.end();
    },
  });
}

// ---- sealed streams: a chunk at a time, from an (async) iterable ---------

// Re-chunks src into pieces of n bytes and gives each to f with a flag
// true for the last (the one no byte follows), holding at most one piece
// and the incoming one.
async function* rechunk(src, n, f) {
  let b = new Uint8Array(n);
  let have = 0;
  for await (const x of src) {
    let d = bytes(x, 'chunk');
    while (d.length > 0) {
      if (have === n) {
        yield f(b, false);
        have = 0;
      }
      const k = Math.min(n - have, d.length);
      b.set(d.subarray(0, k), have);
      have += k;
      d = d.subarray(k);
    }
  }
  const out = f(b.subarray(0, have), true);
  b.fill(0);
  b = null;
  yield out;
}

// the chunk calls of a sealed stream's context c
function kfstep(c, header, chunk, cap, upd, fin) {
  const step = (data, f, last) => {
    const d = bytes(data, 'chunk');
    try {
      return run((h) => {
        const o = h.alloc(cap);
        const pn = h.alloc(4);
        const rc = f(c.live(), h.put(d), d.length, o, cap, pn);
        if (rc !== CODES.OK && rc !== CODES.EBUF) c.end();
        check(rc);
        return h.get(o, h.u32(pn));
      });
    } finally {
      if (last) c.end();
    }
  };
  const o = {
    chunk,
    update: (d) => step(d, upd, false),
    last: (d) => step(d, fin, true),
    end: () => c.end(),
  };
  if (header !== null) o.header = header;
  return Object.freeze(o);
}

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
  /**
   * msg sealed to the ML-KEM public key (noqtis-kseal-1): only the holder
   * of the secret key opens it, with the same `opts.ctx`.
   */
  seal(alg, publicKey, msg, opts = {}) {
    const a = kalg(alg);
    const pk = key(publicKey, 'publicKey');
    const m = bytes(msg, 'msg');
    const c = ctxof(opts);
    return run((h) => sized(h, (o, cap, n) => M._nqkseal(a.id, h.put(pk),
      pk.length, h.put(c), c.length, h.put(m), m.length, o, cap, n),
    22 + a.ct + m.length));
  },

  /**
   * The message seal() sealed: EVRFY for a changed byte, another key or
   * another ctx, EDEC for bytes that are not a sealed message of alg.
   */
  open(alg, secretKey, data, opts = {}) {
    const a = kalg(alg);
    const sk = key(secretKey, 'secretKey');
    const d = bytes(data, 'data');
    const c = ctxof(opts);
    return run((h) => sized(h, (o, cap, n) => M._nqkopen(a.id, h.put(sk),
      sk.length, h.put(c), c.length, h.put(d), d.length, o, cap, n),
    Math.max(d.length, 1)));
  },

  /**
   * A stream sealed to an ML-KEM public key (noqtis-kstream-1), the format
   * of `noqtis box`: { header, chunk, update(full chunk), last(0 to chunk
   * bytes) }. `opts.ctx`, `opts.chunk` (1024 to 16777216; 65536).
   */
  sealer(alg, publicKey, opts = {}) {
    const a = kalg(alg);
    const pk = key(publicKey, 'publicKey');
    const chunk = opts.chunk === undefined ? 65536 : opts.chunk;
    if (!Number.isInteger(chunk) || chunk < 0 || chunk > 0xffffffff) {
      throw new NoqtisError(CODES.EARG, 'chunk');
    }
    const c = new Ctx(128);
    let header;
    try {
      header = run((h) => {
        const x = ctxof(opts);
        const hd = h.alloc(17 + a.ct);
        const pn = h.alloc(4);
        check(M._nqkfeini(c.p, a.id, h.put(pk), pk.length, h.put(x), x.length,
          chunk, hd, 17 + a.ct, pn));
        return h.get(hd, h.u32(pn));
      });
    } catch (e) {
      c.end();
      throw e;
    }
    return kfstep(c, header, chunk, chunk + 16, M._nqkfeupd, M._nqkfefin);
  },

  /**
   * Opens what sealer() wrote: { chunk, update(chunk + 16 bytes), last(16
   * to chunk + 16 bytes) }; a chunk comes back only when its tag verifies
   * (EVRFY otherwise: a changed, moved, dropped or cut chunk).
   */
  opener(alg, secretKey, header, opts = {}) {
    const a = kalg(alg);
    const sk = key(secretKey, 'secretKey');
    const hd = key(header, 'header');
    const c = new Ctx(128);
    let chunk;
    try {
      chunk = run((h) => {
        const x = ctxof(opts);
        const pc = h.alloc(4);
        check(M._nqkfdini(c.p, a.id, h.put(sk), sk.length, h.put(x), x.length,
          h.put(hd), hd.length, pc));
        return h.u32(pc);
      });
    } catch (e) {
      c.end();
      throw e;
    }
    return kfstep(c, null, chunk, chunk, M._nqkfdupd, M._nqkfdfin);
  },

  /**
   * Seals source, an iterable or async iterable of byte pieces (a Node
   * readable stream, a ReadableStream, an array), to an async iterable of
   * the sealed stream's pieces: the header, then each sealed chunk. One
   * chunk is held at a time.
   */
  async* box(alg, publicKey, source, opts = {}) {
    const s = kem.sealer(alg, publicKey, opts);
    try {
      yield s.header;
      yield* rechunk(source, s.chunk, (b, last) => (last ? s.last(b)
        : s.update(b)));
    } finally {
      s.end();
    }
  },

  /**
   * Opens a sealed stream from source (as box()) to an async iterable of
   * plaintext pieces, each given only once it verified; on an error what
   * came before had verified, but the stream is incomplete.
   */
  async* unbox(alg, secretKey, source, opts = {}) {
    const a = kalg(alg);
    const hn = 17 + a.ct;
    let hd = new Uint8Array(0);
    let u = null;
    async function* rest() {
      for await (const x of source) {
        let d = bytes(x, 'chunk');
        if (u === null) {
          const k = Math.min(hn - hd.length, d.length);
          const t = new Uint8Array(hd.length + k);
          t.set(hd);
          t.set(d.subarray(0, k), hd.length);
          hd = t;
          d = d.subarray(k);
          if (hd.length < hn) continue;
          u = kem.opener(alg, secretKey, hd, opts);
        }
        if (d.length > 0) yield d;
      }
      if (u === null) u = kem.opener(alg, secretKey, hd, opts);
    }
    const it = rest();
    // the header first, so the chunk size is known
    const first = await it.next();
    if (u === null) u = kem.opener(alg, secretKey, hd, opts);
    async function* again() {
      if (!first.done) yield first.value;
      yield* it;
    }
    try {
      yield* rechunk(again(), u.chunk + 16, (b, last) => (last ? u.last(b)
        : u.update(b)));
    } finally {
      u.end();
    }
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

// Writes the parsed files under a fresh folder and returns its path.
function mkcap(list) {
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
  } catch (e) {
    rmtree(dir);
    throw e;
  }
  return dir;
}

// Writes each capsule under a fresh folder, runs fn(dirs), removes them.
function withdirs(caps, fn) {
  need();
  const lists = caps.map(entries);
  const dirs = [];
  try {
    for (const l of lists) dirs.push(mkcap(l));
    return fn(dirs);
  } finally {
    for (const d of dirs) rmtree(d);
  }
}

function withdir(files, fn) {
  return withdirs([files], (d) => fn(d[0]));
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

// An array of byte strings in WebAssembly memory: { p, l, n }, the
// pointer and length arrays (0 when empty) and the count.
function blist(h, xs, what, str) {
  if (!Array.isArray(xs)) {
    throw new TypeError(`noqtis: ${what} must be an array`);
  }
  const p = h.alloc(4 * xs.length);
  const l = h.alloc(4 * xs.length);
  xs.forEach((x, i) => {
    let b;
    if (str) {
      if (typeof x !== 'string' || x.includes('\0')) {
        throw new TypeError(`noqtis: ${what} must be strings`);
      }
      b = enc.encode(x);
      const q = h.alloc(b.length + 1);
      M.HEAPU8.set(b, q);
      M.HEAPU8[q + b.length] = 0;
      M.HEAPU32[(p >>> 2) + i] = q;
    } else {
      b = bytes(x, what);
      M.HEAPU32[(p >>> 2) + i] = h.put(b);
    }
    M.HEAPU32[(l >>> 2) + i] = b.length;
  });
  const n = xs.length;
  return { p: n ? p : 0, l: n ? l : 0, n };
}

// A call that sets *outlen also with NQEBUF: once for the size, then
// again with that much room.
function sized(h, fn, guess) {
  const pn = h.alloc(4);
  let cap = guess;
  for (let k = 0; k < 2; k++) {
    const po = h.alloc(cap);
    const rc = fn(po, cap, pn);
    const n = h.u32(pn);
    if (rc === CODES.EBUF && n > cap && k === 0) {
      cap = n;
      continue;
    }
    check(rc);
    return h.get(po, n);
  }
  throw new NoqtisError(CODES.EBUF);
}

function capsrc(x) {
  if (x === null || x === undefined) return null;
  return x;
}

function epoch(at) {
  if (at === undefined) return BigInt(Math.floor(Date.now() / 1000));
  if (at instanceof Date) return BigInt(Math.floor(at.getTime() / 1000));
  if (!Number.isSafeInteger(at)) throw new NoqtisError(CODES.EARG, 'at');
  return BigInt(at);
}

function kstmt(alg, secretKey, publicKey, nalg, nsk, npk, opts, exp = false) {
  const a = salg(alg);
  const b = nalg === null ? a : salg(nalg);
  const sk = key(secretKey, 'secretKey');
  const pk = key(publicKey, 'publicKey');
  const at = epoch(opts.at);
  if (opts.reason !== undefined && typeof opts.reason !== 'string') {
    throw new TypeError('noqtis: reason must be a string');
  }
  return run((h) => {
    const ns = nsk === null ? null : key(nsk, 'newSecretKey');
    const np = npk === null ? null : key(npk, 'newPublicKey');
    const pns = ns ? h.put(ns) : 0;
    const pnp = np ? h.put(np) : 0;
    const psk = h.put(sk);
    const ppk = h.put(pk);
    const why = opts.reason === undefined ? 0 : h.str(opts.reason);
    if (exp) {
      return sized(h, (po, cap, pn) => M._nqkexp(a.id, psk, sk.length, ppk,
        pk.length, at, why, po, cap, pn), 4 * pk.length + 16384);
    }
    return sized(h, (po, cap, pn) => M._nqkstmt(a.id, psk, sk.length, ppk,
      pk.length, b.id, pns, ns ? ns.length : 0, pnp, np ? np.length : 0, at,
      why, po, cap, pn), 4 * (pk.length + (np ? np.length : 0)) + 16384);
  });
}

export const capsule = Object.freeze({
  /**
   * Checks a capsule given as its files (a Map, an object or [path, bytes]
   * pairs, with '/' between folders), including noqtis.json and
   * noqtis.sig. Options: `trust` (the public key the seal must carry;
   * without it the seal's own key is accepted and the report says so),
   * `anchors` (DER certificates of TSA trust anchors, at most 32),
   * `only` (check just these paths; "partial" rows say what was left out),
   * `lineage` (capsules, as files, among which a format 2 capsule's inputs
   * are found by id and checked, to 64 levels), `keys` (key statements
   * from capsule.rotate / capsule.revoke, at most 32; they need `trust`),
   * `proof` (a proof from capsule.prove: checked instead of the files,
   * which may then be null; given, the proven files are checked too).
   * Returns { ok, code, checks: [{ check, ok, detail }], partial }: ok when
   * every check made passed, partial when they left files out (only, a
   * proof), so the capsule passed as a whole only when ok && !partial.
   */
  check(files, opts = {}) {
    const pf = opts.proof === undefined ? null : bytes(opts.proof, 'proof');
    if (pf !== null && (opts.only !== undefined ||
        opts.lineage !== undefined || opts.keys !== undefined)) {
      throw new NoqtisError(CODES.EARG,
        'only, lineage and keys do not apply to a proof');
    }
    if (opts.keys !== undefined && opts.trust === undefined) {
      throw new NoqtisError(CODES.EARG, 'keys need trust');
    }
    const lin = opts.lineage === undefined ? [] : opts.lineage;
    if (!Array.isArray(lin)) {
      throw new TypeError('noqtis: lineage must be an array of capsules');
    }
    const f = capsrc(files);
    if (f === null && pf === null) {
      throw new TypeError('noqtis: files (or opts.proof) are needed');
    }
    const caps = f === null ? lin : [f, ...lin];
    return withdirs(caps, (dirs) => run((h) => {
      const t = opts.trust === undefined ? null : key(opts.trust, 'trust');
      const anc = blist(h, opts.anchors === undefined ? [] : opts.anchors,
        'anchors', false);
      const only = blist(h, opts.only === undefined ? [] : opts.only,
        'only', true);
      const ld = blist(h, f === null ? dirs : dirs.slice(1), 'lineage', true);
      const st = blist(h, opts.keys === undefined ? [] : opts.keys, 'keys',
        false);
      const o = h.alloc(48); // nqcopt: twelve 32-bit members
      const w = [t ? h.put(t) : 0, t ? t.length : 0, anc.p, anc.l, anc.n,
        only.p, only.n, ld.p, ld.n, st.p, st.l, st.n];
      w.forEach((v, i) => {
        M.HEAPU32[(o >>> 2) + i] = v;
      });
      const rp = h.alloc(4);
      M.HEAPU32[rp >>> 2] = 0;
      const dir = f === null ? 0 : h.str(dirs[0]);
      const rc = pf === null ? M._nqchkx(dir, o, rp)
        : M._nqchkp(h.put(pf), pf.length, o, dir, rp);
      const checks = report(h, rp);
      if (rc !== CODES.OK && rc !== CODES.EVRFY) throw new NoqtisError(rc);
      // a pass of some files only (opts.only, a proof) is not a pass of
      // the capsule: partial says so
      return { ok: rc === CODES.OK, code: rc, checks,
        partial: checks.some((r) => r.check === 'partial') };
    }));
  },

  /**
   * Seals the files: returns { 'noqtis.json', 'noqtis.sig' } as bytes, to
   * store beside them. Options: `meta` (a JSON value or JSON text, kept in
   * the manifest), `time` (creation time in seconds since 1970; default
   * the clock), `format` (1, the default, or 2: a Merkle tree over the
   * files, for capsule.prove), `inputs` (format 2, the default with it:
   * [{ name, id }], the capsules this one was made from, each id the
   * 32 bytes capsule.id gives).
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
    const ins = opts.inputs;
    const fmt = opts.format === undefined ? (ins === undefined ? 1 : 2)
      : opts.format;
    if (fmt !== 1 && fmt !== 2) throw new NoqtisError(CODES.EARG, 'format');
    if (fmt === 1 && ins !== undefined) {
      throw new NoqtisError(CODES.EARG, 'inputs need format 2');
    }
    if (ins !== undefined && !Array.isArray(ins)) {
      throw new TypeError('noqtis: inputs must be an array');
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
        const pd = h.str(dir);
        const psk = h.put(sk);
        const ppk = h.put(pk);
        const pm = meta === null ? 0 : h.str(meta);
        if (fmt === 1) {
          check(M._nqseal(pd, a.id, psk, sk.length, ppk, pk.length, pm, 0));
        } else {
          const list = ins === undefined ? [] : ins;
          const pi = h.alloc(36 * list.length); // nqcin: id[32], name
          list.forEach((x, i) => {
            const id = key(x && x.id, 'inputs[].id');
            if (id.length !== 32 || typeof x.name !== 'string' ||
                x.name.includes('\0')) {
              throw new NoqtisError(CODES.EARG, 'inputs: { name, id }');
            }
            M.HEAPU8.set(id, pi + 36 * i);
            M.HEAPU32[(pi + 36 * i + 32) >>> 2] = h.str(x.name);
          });
          check(M._nqseal2(pd, a.id, psk, sk.length, ppk, pk.length, pm,
            list.length ? pi : 0, list.length));
        }
      } finally {
        M._unsetenv(ev);
      }
      return {
        'noqtis.json': M.FS.readFile(`${dir}/noqtis.json`),
        'noqtis.sig': M.FS.readFile(`${dir}/noqtis.sig`),
      };
    }));
  },

  /**
   * The capsule's id, 32 bytes: the SHA-256 of what its seal signs, as
   * seal's `inputs` take it. Only noqtis.sig is read; nothing is checked.
   */
  id(files) {
    return withdir(files, (dir) => run((h) => {
      const pi = h.alloc(32);
      check(M._nqcapid(h.str(dir), pi));
      return h.get(pi, 32);
    }));
  },

  /**
   * A proof (noqtis-proof-1, JSON bytes) that the paths are files of the
   * format 2 capsule: its seal, the manifest's head and each file's entry
   * and Merkle audit path, and nothing of the other files. Check the
   * capsule first; capsule.check(null, { proof }) checks the proof.
   */
  prove(files, paths) {
    const ps = typeof paths === 'string' ? [paths] : paths;
    return withdir(files, (dir) => run((h) => {
      const l = blist(h, ps, 'paths', true);
      if (l.n === 0) throw new NoqtisError(CODES.EARG, 'paths');
      const pd = h.str(dir);
      return sized(h, (po, cap, pn) => M._nqprove(pd, l.p, l.n, po, cap,
        pn), 65536);
    }));
  },

  /**
   * The files the manifest lists, [{ path, size, sha256 }] in manifest
   * order, read with nothing checked (only noqtis.json and noqtis.sig are
   * needed).
   */
  files(files) {
    return withdir(files, (dir) => run((h) => {
      const rp = h.alloc(4);
      M.HEAPU32[rp >>> 2] = 0;
      const rc = M._nqfiles(h.str(dir), rp);
      const rows = report(h, rp);
      const bad = rows.find((r) => !r.ok);
      if (rc !== CODES.OK || bad) {
        throw new NoqtisError(rc === CODES.OK ? CODES.EDEC : rc,
          bad ? bad.detail : undefined);
      }
      return rows.filter((r) => r.check === 'info.file').map((r) => {
        const a = r.detail.indexOf(' ');
        const b = r.detail.indexOf(' ', a + 1);
        return {
          path: r.detail.slice(b + 1),
          size: Number(r.detail.slice(0, a)),
          sha256: r.detail.slice(a + 1, b),
        };
      });
    }));
  },

  /**
   * A key statement (noqtis-keys-1, JSON bytes): the key pair of alg is
   * replaced by the new pair of newAlg from `opts.at` (seconds since
   * 1970 or a Date; default now), signed by both. `opts.reason`: up to
   * 255 bytes of text. Both must be post-quantum (Ed25519 alone is
   * refused). capsule.check takes it in `keys`.
   */
  rotate(alg, secretKey, publicKey, newAlg, newSecretKey, newPublicKey,
    opts = {}) {
    return kstmt(alg, secretKey, publicKey, newAlg, newSecretKey,
      newPublicKey, opts);
  },

  /** A key statement that the key pair is revoked from `opts.at`. */
  revoke(alg, secretKey, publicKey, opts = {}) {
    return kstmt(alg, secretKey, publicKey, null, null, null, opts);
  },

  /**
   * A key statement that the key pair seals until `opts.at` (required)
   * and not after. capsule.check accepts its seals as before until that
   * time has come, and from then on only with a verified timestamp from
   * before it.
   */
  expire(alg, secretKey, publicKey, opts = {}) {
    if (opts.at === undefined) {
      throw new TypeError('noqtis: at is needed: when the key expires');
    }
    return kstmt(alg, secretKey, publicKey, null, null, null, opts, true);
  },
  /**
   * What the capsule says, with nothing checked: { ok, code, checks } whose
   * "info.*" rows give its format, algorithm, key, time, files, bytes,
   * timestamp and meta.
   */
  inspect(files) {
    return withdir(files, (dir) => run((h) => {
      const rp = h.alloc(4);
      M.HEAPU32[rp >>> 2] = 0;
      const rc = M._nqinsp(h.str(dir), rp);
      const checks = report(h, rp);
      if (rc !== CODES.OK && rc !== CODES.EDEC) throw new NoqtisError(rc);
      return { ok: rc === CODES.OK, code: rc, checks, partial: false };
    }));
  },

  /**
   * Why seal() refused the files (EARG): { why: 'name' | 'case' | 'key' |
   * ..., path }, or null when nothing in them stops a seal (the keys given
   * were then not one pair).
   */
  sealWhy(files) {
    const n = ['', 'link', 'odd', 'name', 'case', 'key'];
    return withdir(files, (dir) => run((h) => {
      const pw = h.alloc(4);
      const pp = h.alloc(4200);
      check(M._nqsealwhy(h.str(dir), pw, pp, 4200));
      const w = h.u32(pw);
      return w === 0 ? null : { why: n[w] || String(w),
        path: M.UTF8ToString(pp) };
    }));
  },

  /**
   * The RFC 3161 TimeStampReq for the sealed files' seal: send it to a TSA
   * and give its reply to tsput(). `opts.nonce` (at most 32 bytes).
   */
  tsreq(files, opts = {}) {
    const nc = opts.nonce === undefined ? null : key(opts.nonce, 'nonce');
    return withdir(files, (dir) => run((h) => {
      const q = h.alloc(256);
      const pn = h.alloc(4);
      check(M._nqtsreq(h.str(dir), nc ? h.put(nc) : 0, nc ? nc.length : 0, q,
        256, pn));
      return h.get(q, h.u32(pn));
    }));
  },

  /**
   * Checks the TSA's reply and returns { 'noqtis.sig', time }: the seal
   * with the timestamp, to store in place of the old one. Options: nonce,
   * anchors (DER certificates the TSA must chain to). EVRFY, with what
   * failed, when the reply does not check.
   */
  tsput(files, reply, opts = {}) {
    const rp = bytes(reply, 'reply');
    const nc = opts.nonce === undefined ? null : key(opts.nonce, 'nonce');
    return withdir(files, (dir) => run((h) => {
      const anc = blist(h, opts.anchors === undefined ? [] : opts.anchors,
        'anchors', false);
      const gt = h.alloc(8);
      const pw = h.alloc(4);
      M.HEAPU32[pw >>> 2] = 0;
      const rc = M._nqtsput(h.str(dir), h.put(rp), rp.length,
        nc ? h.put(nc) : 0, nc ? nc.length : 0, anc.p, anc.l, anc.n, gt, pw);
      check(rc, h.u32(pw) ? M.UTF8ToString(h.u32(pw)) : '');
      return { 'noqtis.sig': M.FS.readFile(`${dir}/noqtis.sig`),
        time: Number(new DataView(M.HEAPU8.buffer).getBigInt64(gt, true)) };
    }));
  },

  /**
   * The TimeStampReq of the next archive timestamp of the capsule's
   * evidence record (RFC 4998; noqtis.ers among the files when there is
   * one): opts.hash 'sha256', 'sha384' or 'sha512' for a hash-tree
   * renewal; opts.nonce.
   */
  ersreq(files, opts = {}) {
    const nc = opts.nonce === undefined ? null : key(opts.nonce, 'nonce');
    const hh = opts.hash === undefined ? 0 : halg(opts.hash);
    return withdir(files, (dir) => run((h) => {
      const q = h.alloc(256);
      const pn = h.alloc(4);
      const pw = h.alloc(4);
      M.HEAPU32[pw >>> 2] = 0;
      check(M._nqersreq(h.str(dir), hh, nc ? h.put(nc) : 0, nc ? nc.length : 0,
        q, 256, pn, pw), h.u32(pw) ? M.UTF8ToString(h.u32(pw)) : '');
      return h.get(q, h.u32(pn));
    }));
  },

  /**
   * Adds the reply to ersreq() to the evidence record once it and the
   * record check: { 'noqtis.ers', time, how: 'new' | 'timestamp' |
   * 'hash-tree' }. Options as ersreq(), and anchors.
   */
  ersput(files, reply, opts = {}) {
    const rp = bytes(reply, 'reply');
    const nc = opts.nonce === undefined ? null : key(opts.nonce, 'nonce');
    const hh = opts.hash === undefined ? 0 : halg(opts.hash);
    return withdir(files, (dir) => run((h) => {
      const anc = blist(h, opts.anchors === undefined ? [] : opts.anchors,
        'anchors', false);
      const gt = h.alloc(8);
      const how = h.alloc(4);
      const pw = h.alloc(4);
      M.HEAPU32[pw >>> 2] = 0;
      check(M._nqersput(h.str(dir), hh, h.put(rp), rp.length,
        nc ? h.put(nc) : 0, nc ? nc.length : 0, anc.p, anc.l, anc.n, gt, how,
        pw), h.u32(pw) ? M.UTF8ToString(h.u32(pw)) : '');
      return { 'noqtis.ers': M.FS.readFile(`${dir}/noqtis.ers`),
        time: Number(new DataView(M.HEAPU8.buffer).getBigInt64(gt, true)),
        how: ['new', 'timestamp', 'hash-tree'][h.u32(how)] };
    }));
  },

  /**
   * The capsule as one file (noqtis-bundle-1), as `noqtis pack` writes
   * it: its seal, manifest, evidence record and every listed file
   * (`opts.files` false: only its data record). Check it first.
   */
  pack(files, opts = {}) {
    return withdir(files, (dir) => run((h) => {
      const out = `${dir}.nqb`;
      check(M._nqdpack(h.str(dir), opts.files === false ? 0 : 1, h.str(out)));
      try {
        return M.FS.readFile(out);
      } finally {
        M.FS.unlink(out);
      }
    }));
  },

  /**
   * The files of a bundle, as a Map of path -> bytes, refused whole (EDEC,
   * with what is wrong) when any path or size is not one a capsule holds.
   * Check them after (capsule.check).
   */
  unpack(bundle) {
    const b = bytes(bundle, 'bundle');
    need();
    const f = `/nq${++fsn}.nqb`;
    const dir = `/nq${++fsn}`;
    M.FS.writeFile(f, b);
    try {
      return run((h) => {
        const why = h.alloc(600);
        M.HEAPU8[why] = 0;
        check(M._nqdunpack(h.str(f), h.str(dir), 0, why, 600),
          M.UTF8ToString(why));
        const out = new Map();
        const walk = (rel) => {
          const abs = rel === '' ? dir : `${dir}/${rel}`;
          for (const n of M.FS.readdir(abs)) {
            if (n === '.' || n === '..') continue;
            const r = rel === '' ? n : `${rel}/${n}`;
            if (M.FS.isDir(M.FS.lstat(`${dir}/${r}`).mode)) walk(r);
            else out.set(r, M.FS.readFile(`${dir}/${r}`));
          }
        };
        walk('');
        rmtree(dir);
        return new Map([...out.entries()].sort((x, y) => (x[0] < y[0] ? -1
          : x[0] > y[0] ? 1 : 0)));
      });
    } finally {
      M.FS.unlink(f);
    }
  },

  /**
   * Checks an append-only chain of capsules (each as files), oldest
   * first: each sealed in format 2 with the one before as its only input,
   * all by the first one's key (`opts.trust` when given). { ok, code,
   * rows, head }: head the last capsule's id when every row passed.
   */
  chain(caps, opts = {}) {
    if (!Array.isArray(caps)) throw new TypeError('noqtis: caps: an array');
    return withdirs(caps, (dirs) => run((h) => {
      const t = opts.trust === undefined ? null : key(opts.trust, 'trust');
      const anc = blist(h, opts.anchors === undefined ? [] : opts.anchors,
        'anchors', false);
      const ds = blist(h, dirs, 'dirs', true);
      const o = h.alloc(48);
      M.HEAPU8.fill(0, o, o + 48);
      const w = [t ? h.put(t) : 0, t ? t.length : 0, anc.p, anc.l, anc.n];
      w.forEach((v, i) => {
        M.HEAPU32[(o >>> 2) + i] = v;
      });
      const hd = h.alloc(32);
      const rp = h.alloc(4);
      M.HEAPU32[rp >>> 2] = 0;
      const r = dreport(h, M._nqdchain(ds.p, ds.n, o, hd, rp), rp);
      return { ...r, head: r.ok ? h.get(hd, 32) : null };
    }));
  },
});

// ---- identity cards ------------------------------------------------------

// nqcardf in wasm32 memory: the offsets of include/noqtis.h's struct,
// which tests/tcard.c asserts when built for wasm32
const CF = {
  alg: 0, pk: 4, pklen: 2628, fp: 2632, utc: 2672, name: 2693, orcid: 2949,
  email: 2969, url: 3224, affil: 4249, size: 4512,
};
const FIELDS = ['name', 'orcid', 'email', 'url', 'affil'];

export const idcard = Object.freeze({
  /**
   * An identity card (noqtis-idcard-1, canonical JSON bytes): the public
   * key with `fields.name` and, when given, `orcid` (its check digit
   * verified; its https://orcid.org/ address is stored bare), `email`,
   * `url` (https://) and `affil`, made at `opts.at` (seconds since 1970
   * or a Date; default now) and signed by the key pair under the card's
   * own context. A field out of its limits throws NQEARG; Ed25519 alone
   * NQENOSUP.
   */
  make(alg, secretKey, publicKey, fields, opts = {}) {
    const a = salg(alg);
    const sk = key(secretKey, 'secretKey');
    const pk = key(publicKey, 'publicKey');
    if (fields === null || typeof fields !== 'object') {
      throw new TypeError('noqtis: fields must be an object with a name');
    }
    for (const f of FIELDS) {
      const v = fields[f];
      if (v === undefined || v === null) {
        if (f === 'name') throw new TypeError('noqtis: fields.name is needed');
        continue;
      }
      if (typeof v !== 'string') {
        throw new TypeError(`noqtis: fields.${f} must be a string`);
      }
      if (v.includes('\0')) throw new NoqtisError(CODES.EARG, f);
    }
    const at = epoch(opts.at);
    return run((h) => {
      const psk = h.put(sk);
      const ppk = h.put(pk);
      const p = FIELDS.map((f) =>
        (fields[f] === undefined || fields[f] === null ? 0 : h.str(fields[f])));
      return sized(h, (po, cap, pn) => M._nqcard(a.id, psk, sk.length, ppk,
        pk.length, p[0], p[1], p[2], p[3], p[4], at, po, cap, pn),
      4 * pk.length + 65536);
    });
  },

  /**
   * The card's fields when it verifies (and, with `opts.trust`, is for
   * that public key): { name, orcid, email, url, affil } (null for a
   * field it has not), `created`, `alg`, `publicKey` and `keySha256` (hex,
   * as `noqtis inspect` shows a seal's key); null when its signature does
   * not verify or it is for another key. Input that is not a card throws
   * (NQEDEC). A card is self-signed: compare keySha256 with the one its
   * holder published, or give `trust`.
   */
  verify(card, opts = {}) {
    const c = bytes(card, 'card');
    const t = opts.trust === undefined || opts.trust === null
      ? null : key(opts.trust, 'trust');
    return run((h) => {
      const pc = h.put(c);
      const pt = t ? h.put(t) : 0;
      const f = h.alloc(CF.size);
      const rc = M._nqcardvrfy(pc, c.length, pt, t ? t.length : 0, f);
      if (rc === CODES.EVRFY) return null;
      check(rc);
      const s = (o) => M.UTF8ToString(f + o);
      const opt = (o) => (M.HEAPU8[f + o] === 0 ? null : s(o));
      const fp = h.get(f + CF.fp, 32);
      return {
        name: s(CF.name), orcid: opt(CF.orcid), email: opt(CF.email),
        url: opt(CF.url), affil: opt(CF.affil), created: s(CF.utc),
        alg: M.UTF8ToString(M._nqsname(M.HEAPU32[f >>> 2])),
        publicKey: h.get(f + CF.pk, h.u32(f + CF.pklen)),
        keySha256: Array.from(fp, (b) => b.toString(16).padStart(2, '0'))
          .join(''),
      };
    });
  },
});

// ---- DSSE envelopes ------------------------------------------------------

export const dsse = Object.freeze({
  /**
   * A DSSE envelope (canonical JSON bytes) of payload with payloadType
   * `type` (1 to 255 printable ASCII bytes, no space, quote or
   * backslash), signed by the key pair over the pre-authentication
   * encoding; keyid is the hex SHA-256 of the public key.
   */
  sign(alg, secretKey, publicKey, type, payload) {
    const a = salg(alg);
    const sk = key(secretKey, 'secretKey');
    const pk = key(publicKey, 'publicKey');
    if (typeof type !== 'string' || type.includes('\0')) {
      throw new TypeError('noqtis: type must be a string');
    }
    const d = bytes(payload, 'payload');
    return run((h) => {
      const psk = h.put(sk);
      const ppk = h.put(pk);
      const pt = h.str(type);
      const pd = h.put(d);
      return sized(h, (po, cap, pn) => M._nqdsse(a.id, psk, sk.length, ppk,
        pk.length, pt, pd, d.length, po, cap, pn), 2 * d.length + 65536);
    });
  },

  /**
   * { payload, payloadType } when one of the envelope's signatures (at
   * most 16) verifies under publicKey; null when none does. Text that is
   * not an envelope throws (NQEDEC).
   */
  verify(alg, publicKey, envelope) {
    const a = salg(alg);
    const pk = key(publicKey, 'publicKey');
    const e = bytes(envelope, 'envelope');
    return run((h) => {
      const po = h.alloc(e.length);
      const pn = h.alloc(4);
      const pt = h.alloc(256);
      const rc = M._nqdssevrfy(a.id, h.put(pk), pk.length, h.put(e),
        e.length, po, e.length, pn, pt);
      if (rc === CODES.EVRFY) return null;
      check(rc);
      return { payload: h.get(po, h.u32(pn)), payloadType: M.UTF8ToString(pt) };
    });
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
  /**
   * The CLI's key file text for a key: kind is 'pub' or 'sec'; a secret
   * key with `opts.passphrase` (bytes or text) is kept under it, as
   * `noqtis keygen --pass-fd` writes it.
   */
  encode(alg, kind, keyBytes, opts = {}) {
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
    let body = k;
    if (opts.passphrase !== undefined) {
      if (kind !== 'sec') {
        throw new NoqtisError(CODES.EARG, 'a passphrase protects a secret key only');
      }
      body = keyfile.pwenc(opts.passphrase, k,
        { ad: `noqtis-key-1 ${a.name} sec` });
    }
    const b = b64e(body);
    if (body !== k) body.fill(0);
    let s = `noqtis-key-1 ${a.name} ${kind}\n`;
    for (let i = 0; i < b.length; i += 64) s += `${b.slice(i, i + 64)}\n`;
    return s;
  },

  /**
   * { alg, kind, key } from key file text, strictly as the CLI reads it;
   * a secret key under a passphrase needs `opts.passphrase`.
   */
  decode(text, opts = {}) {
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
    let k = b64d(body);
    const want = f[2] === 'pub' ? a.pk : a.sk;
    const prot = f[2] === 'sec' && k.length === want + 51 &&
      k[0] === 0x4e && k[1] === 0x51 && k[2] === 0x50 && k[3] === 0x57;
    if (prot) {
      if (opts.passphrase === undefined) {
        throw new NoqtisError(CODES.EARG,
          'the key is protected by a passphrase: give opts.passphrase');
      }
      const e = k;
      k = keyfile.pwdec(opts.passphrase, e, { ad: `noqtis-key-1 ${a.name} sec` });
      e.fill(0);
    } else if (opts.passphrase !== undefined && f[2] === 'sec' &&
        k.length === want) {
      k.fill(0);
      throw new NoqtisError(CODES.EARG, 'the key is not protected by a passphrase');
    }
    if (k.length !== want) {
      k.fill(0);
      throw new NoqtisError(CODES.EDEC, 'key length');
    }
    return { alg: a.name, kind: f[2], key: k };
  },
  /**
   * sk under passphrase (noqtis-pwkey-1): Argon2id (opts m KiB, t passes,
   * p lanes; 0 or absent: 64 MiB, 3, 4) gives the key of
   * ChaCha20-Poly1305, whose associated data includes opts.ad.
   */
  pwenc(passphrase, sk, opts = {}) {
    const pw = bytes(passphrase, 'passphrase');
    const k = key(sk, 'sk');
    const ad = opts.ad === undefined ? new Uint8Array(0) : bytes(opts.ad, 'ad');
    return run((h) => sized(h, (o, cap, n) => M._nqpwenc(h.put(pw), pw.length,
      h.put(ad), ad.length, opts.m || 0, opts.t || 0, opts.p || 0, h.put(k),
      k.length, o, cap, n), k.length + 51));
  },

  /**
   * The key pwenc() protected: EVRFY for a wrong passphrase or ad, or any
   * changed byte; ELIM for parameters over the limits.
   */
  pwdec(passphrase, data, opts = {}) {
    const pw = bytes(passphrase, 'passphrase');
    const d = key(data, 'data');
    const ad = opts.ad === undefined ? new Uint8Array(0) : bytes(opts.ad, 'ad');
    return run((h) => sized(h, (o, cap, n) => M._nqpwdec(h.put(pw), pw.length,
      h.put(ad), ad.length, h.put(d), d.length, o, cap, n),
    Math.max(d.length - 51, 1)));
  },
});

// For the package's own tests: the WebAssembly memory, to check that no
// secret is left in it. Not part of the API.
export function _heap() {
  need();
  return M.HEAPU8;
}

// ---- the data layer (nqd.h) ---------------------------------------------

const dec8 = new TextDecoder();

// nqdrec from JSON text (a record), freed by fn's end
function withrec(h, text, fn) {
  if (typeof text !== 'string') {
    throw new TypeError('noqtis: a record is its JSON text');
  }
  const b = enc.encode(text);
  const rp = h.alloc(4);
  const why = h.alloc(600);
  M.HEAPU8[why] = 0;
  check(M._nqdparse(h.put(b), b.length, rp, why, 600), M.UTF8ToString(why));
  const r = h.u32(rp);
  try {
    return fn(r);
  } finally {
    M._nqdrfree(r);
  }
}

function rtext(h, r) {
  return dec8.decode(sized(h, (o, c, n) => M._nqdjson(r, o, c, n), 4096));
}

// the rows of an nqd report: [{ check, ok, detail, stats }]
function drows(h, rp) {
  const r = h.u32(rp);
  const rows = [];
  if (r === 0) return rows;
  try {
    const n = M._nqdrepn(r);
    const pc = h.alloc(4);
    const po = h.alloc(4);
    const pd = h.alloc(4);
    for (let i = 0; i < n; i++) {
      check(M._nqdrepi(r, i, pc, po, pd));
      const j = M._nqdrepj(r, i);
      rows.push({
        check: M.UTF8ToString(h.u32(pc)),
        ok: h.u32(po) !== 0,
        detail: M.UTF8ToString(h.u32(pd)),
        stats: j === 0 ? null : JSON.parse(M.UTF8ToString(j)),
      });
    }
  } finally {
    M._nqdrepfree(r);
  }
  return rows;
}

function dreport(h, rc, rp) {
  const rows = drows(h, rp);
  if (rc !== CODES.OK && rc !== CODES.EVRFY) throw new NoqtisError(rc);
  return { ok: rc === CODES.OK, code: rc, rows };
}

// nqdcsvopt: char delim, int noheader, int ranges (12 bytes)
function csvopt(h, o = {}) {
  const p = h.alloc(12);
  const d = o.delim === undefined ? ',' : o.delim;
  if (typeof d !== 'string' || enc.encode(d).length !== 1) {
    throw new NoqtisError(CODES.EARG, 'delim is one byte');
  }
  const v = new DataView(M.HEAPU8.buffer, p, 12);
  v.setUint8(0, enc.encode(d)[0]);
  v.setInt32(4, o.header === false ? 1 : 0, true);
  v.setInt32(8, o.ranges ? 1 : 0, true);
  return p;
}

function elem(x) {
  return typeof x === 'string' ? x : JSON.stringify(x);
}

export const data = Object.freeze({
  /** The record (JSON text) in canonical form; throws when it is not one. */
  canon(record) {
    return run((h) => withrec(h, record, (r) => rtext(h, r)));
  },

  /**
   * A record with each of paths (files of the capsule given as files)
   * recorded as a source, its SHA-256 and size, keeping what record (JSON
   * text, or null for a new one) says of it; fields (url, title, ...) set
   * as strings. Returns the new record's text.
   */
  add(record, files, paths, fields = {}) {
    return withdir(files, (dir) => run((h) => {
      const rec = record === null || record === undefined
        ? `{"format":"noqtis-data-1"}` : record;
      return withrec(h, rec, (r) => {
        const why = h.alloc(600);
        for (const p of Array.isArray(paths) ? paths : [paths]) {
          M.HEAPU8[why] = 0;
          check(M._nqdsrc(r, h.str(dir), h.str(p), why, 600),
            M.UTF8ToString(why));
          for (const [k, v] of Object.entries(fields)) {
            const j = JSON.stringify(v);
            M.HEAPU8[why] = 0;
            check(M._nqdset(r, h.str('sources'), h.str(p), h.str(k),
              h.str(j), enc.encode(j).length, why, 600),
            M.UTF8ToString(why));
          }
        }
        return rtext(h, r);
      });
    }));
  },

  /** record with element (JSON text or a value) put in member. */
  put(record, member, element) {
    return run((h) => withrec(h, record, (r) => {
      const j = elem(element);
      const why = h.alloc(600);
      M.HEAPU8[why] = 0;
      check(M._nqdput(r, h.str(member), h.str(j), enc.encode(j).length, why,
        600), M.UTF8ToString(why));
      return rtext(h, r);
    }));
  },

  /** Checks the capsule given as files against its noqtis.data.json. */
  check(files) {
    return withdir(files, (dir) => run((h) => {
      const rp = h.alloc(4);
      M.HEAPU32[rp >>> 2] = 0;
      return dreport(h, M._nqdchk(h.str(dir), rp), rp);
    }));
  },

  /** The schema of the CSV file path of files, a "schemas" element. */
  schema(files, path, opts = {}) {
    return withdir(files, (dir) => run((h) => {
      const why = h.alloc(600);
      M.HEAPU8[why] = 0;
      const o = csvopt(h, opts);
      const pn = h.alloc(4);
      let cap = 65536;
      for (;;) {
        const po = h.alloc(cap);
        const rc = M._nqdinfer(h.str(dir), h.str(path), o, po, cap, pn, why,
          600);
        if (rc === CODES.EBUF && h.u32(pn) >= cap) {
          cap = h.u32(pn) + 1;
          continue;
        }
        check(rc, M.UTF8ToString(why));
        return dec8.decode(h.get(po, h.u32(pn)));
      }
    }));
  },

  /** Checks the CSV file of a "schemas" element against it. */
  schemaCheck(files, schema) {
    return withdir(files, (dir) => run((h) => {
      const j = elem(schema);
      const rp = h.alloc(4);
      M.HEAPU32[rp >>> 2] = 0;
      return dreport(h, M._nqdschk(h.str(dir), h.str(j), enc.encode(j).length,
        rp), rp);
    }));
  },

  /** The drift summaries of the CSV file path of files, a "stats" element. */
  pin(files, path, opts = {}) {
    return withdir(files, (dir) => run((h) => {
      const why = h.alloc(600);
      M.HEAPU8[why] = 0;
      const o = csvopt(h, opts);
      const pn = h.alloc(4);
      let cap = 1 << 20;
      for (;;) {
        const po = h.alloc(cap);
        const rc = M._nqdstats(h.str(dir), h.str(path), o, po, cap, pn, why,
          600);
        if (rc === CODES.EBUF && h.u32(pn) >= cap) {
          cap = h.u32(pn) + 1;
          continue;
        }
        check(rc, M.UTF8ToString(why));
        return dec8.decode(h.get(po, h.u32(pn)));
      }
    }));
  },

  /**
   * Compares the CSV file data (bytes or text) with the "stats" element
   * stats: { ok, code, rows } with a "drift" or "drift.warn" row per
   * column. Options: psiwarn, psifail, alpha, minn, benford, delim, header.
   */
  drift(stats, data, opts = {}) {
    return withdir(new Map([['f.csv', data]]), (dir) => run((h) => {
      const j = elem(stats);
      const o = csvopt(h, opts);
      const d = h.alloc(40);
      const v = new DataView(M.HEAPU8.buffer, d, 40);
      v.setFloat64(0, opts.psiwarn === undefined ? 0.1 : opts.psiwarn, true);
      v.setFloat64(8, opts.psifail === undefined ? 0.25 : opts.psifail, true);
      v.setFloat64(16, opts.alpha === undefined ? 0.001 : opts.alpha, true);
      v.setFloat64(24, opts.minn === undefined ? 1000 : opts.minn, true);
      v.setInt32(32, opts.benford ? 1 : 0, true);
      const rp = h.alloc(4);
      M.HEAPU32[rp >>> 2] = 0;
      return dreport(h, M._nqddrift(h.str(j), enc.encode(j).length,
        h.str(`${dir}/f.csv`), o, d, rp), rp);
    }));
  },

  /** What changed from capsule a to capsule b (each as files). */
  diff(a, b) {
    return withdirs([a, b], (dirs) => run((h) => {
      const rp = h.alloc(4);
      M.HEAPU32[rp >>> 2] = 0;
      return dreport(h, M._nqddiff(h.str(dirs[0]), h.str(dirs[1]), rp), rp);
    }));
  },

  /**
   * The addresses the source path of record can be fetched from, in the
   * order to try them: [{ kind: 'url' | 'portal' | 'mirror' | 'archived',
   * url }]; none for a synthetic source.
   */
  addrs(record, path) {
    const kinds = ['', 'url', 'portal', 'mirror', 'archived'];
    return run((h) => withrec(h, record, (r) => {
      const out = [];
      const pk = h.alloc(4);
      const pp = h.str(path);
      for (let i = 0; ; i++) {
        const po = h.alloc(4400);
        const pn = h.alloc(4);
        const rc = M._nqdaddr(r, pp, i, pk, po, 4400, pn);
        if (rc === CODES.EARG || (rc === CODES.EIO && i > 0)) return out;
        check(rc);
        out.push({ kind: kinds[h.u32(pk)] || 'archived',
          url: dec8.decode(h.get(po, h.u32(pn))) });
      }
    }));
  },

  /** Whether bytes are the source path's recorded bytes (size, SHA-256). */
  verify(record, path, b) {
    const x = bytes(b, 'bytes');
    return run((h) => withrec(h, record, (r) => {
      const rc = M._nqdvrfy(r, h.str(path), h.put(x), x.length);
      if (rc !== CODES.OK && rc !== CODES.EVRFY) throw new NoqtisError(rc);
      return rc === CODES.OK;
    }));
  },

  /** Field name of element i of member, as text; null when there is none. */
  field(record, member, i, name) {
    if (!Number.isSafeInteger(i) || i < 0) {
      throw new NoqtisError(CODES.EARG, 'i');
    }
    return run((h) => withrec(h, record, (r) => {
      const pn = h.alloc(4);
      const m = h.str(member);
      const f = h.str(name);
      let rc = M._nqdfld(r, m, i, f, 0, 0, pn);
      if (rc === CODES.EIO) return null;
      if (rc !== CODES.EBUF) check(rc);
      const n = h.u32(pn);
      const po = h.alloc(n + 1);
      rc = M._nqdfld(r, m, i, f, po, n + 1, pn);
      check(rc);
      return dec8.decode(h.get(po, n));
    }));
  },

  /** The request (a GET address) for a source's resolver (JSON). */
  request(resolver) {
    return run((h) => {
      const j = elem(resolver);
      const why = h.alloc(600);
      M.HEAPU8[why] = 0;
      const po = h.alloc(4400);
      const pn = h.alloc(4);
      check(M._nqdrslv(h.str(j), enc.encode(j).length, po, 4400, pn, why,
        600), M.UTF8ToString(why));
      return dec8.decode(h.get(po, h.u32(pn)));
    });
  },

  /**
   * Reads the portal's reply to request(): { url, time }, time the
   * Wayback Machine copy's ("" for the other portals).
   */
  reply(resolver, body) {
    const b = bytes(body, 'reply');
    return run((h) => {
      const j = elem(resolver);
      const why = h.alloc(600);
      M.HEAPU8[why] = 0;
      const po = h.alloc(4400);
      const pn = h.alloc(4);
      const tm = h.alloc(21);
      check(M._nqdrsp(h.str(j), enc.encode(j).length, h.put(b), b.length, po,
        4400, pn, tm, why, 600), M.UTF8ToString(why));
      return { url: dec8.decode(h.get(po, h.u32(pn))),
        time: M.UTF8ToString(tm) };
    });
  },

  /** The raw-bytes address of a Wayback Machine copy. */
  wayback(url) {
    return run((h) => dec8.decode(sized(h,
      (o, c, n) => M._nqdwb(h.str(url), o, c, n), 4400)));
  },
  /** The element of member with key (path or name), or null. */
  key(record, member, k) {
    return run((h) => withrec(h, record, (r) => {
      const pn = h.alloc(4);
      const m = h.str(member);
      const kk = h.str(k);
      const rc = M._nqdkey(r, m, kk, 0, 0, pn);
      if (rc === CODES.EIO) return null;
      if (rc !== CODES.EBUF) check(rc);
      return dec8.decode(sized(h, (o, c, n) => M._nqdkey(r, m, kk, o, c, n),
        h.u32(pn) + 1));
    }));
  },

  /** record without the element of member with key, or the whole member. */
  del(record, member, k = null) {
    return run((h) => withrec(h, record, (r) => {
      check(M._nqddel(r, h.str(member), k === null ? 0 : h.str(k)));
      return rtext(h, r);
    }));
  },

  /**
   * Writes a synthetic stand-in for the CSV file path from record's schema
   * of it (rows rows, 0: the schema's minimum, else 100; the same bytes for
   * the same seed): { record, data }, the record with it as a synthetic
   * source. files are the capsule's other files (may be empty).
   */
  synth(record, files, path, seed, rows = 0) {
    if (!Number.isSafeInteger(seed) || seed < 0 ||
        !Number.isSafeInteger(rows) || rows < 0) {
      throw new NoqtisError(CODES.EARG, 'seed and rows');
    }
    return withdir(files, (dir) => run((h) => withrec(h, record, (r) => {
      // the stand-in's folders, as a folder on disk would have them
      let d = dir;
      for (const part of path.split('/').slice(0, -1)) {
        d += `/${part}`;
        if (!M.FS.analyzePath(d).exists) M.FS.mkdir(d);
      }
      const why = h.alloc(600);
      M.HEAPU8[why] = 0;
      check(M._nqdsyn(r, h.str(dir), h.str(path), BigInt(seed), BigInt(rows),
        why, 600), M.UTF8ToString(why));
      return { record: rtext(h, r), data: M.FS.readFile(`${dir}/${path}`) };
    })));
  },

  /**
   * The "stats" element stats calibrated on the CSV files datas (bytes or
   * text each) known not to have drifted from it: drift() then warns only
   * beyond what they showed. Options as drift() (delim, header).
   */
  calibrate(stats, datas, opts = {}) {
    if (!Array.isArray(datas)) throw new TypeError('noqtis: datas: an array');
    const fs = new Map(datas.map((d, i) => [`f${i}.csv`, d]));
    return withdir(fs, (dir) => run((h) => {
      const j = elem(stats);
      const why = h.alloc(600);
      M.HEAPU8[why] = 0;
      const o = csvopt(h, opts);
      const fl = blist(h, datas.map((_, i) => `${dir}/f${i}.csv`), 'datas',
        true);
      const pn = h.alloc(4);
      let cap = 1 << 20;
      for (;;) {
        const po = h.alloc(cap);
        const rc = M._nqddcal(h.str(j), enc.encode(j).length, fl.p, fl.n, o,
          po, cap, pn, why, 600);
        if (rc === CODES.EBUF && h.u32(pn) >= cap) {
          cap = h.u32(pn) + 1;
          continue;
        }
        check(rc, M.UTF8ToString(why));
        return dec8.decode(h.get(po, h.u32(pn)));
      }
    }));
  },

  /**
   * The SHA-256 of each `chunk` bytes (1,024 to 2^30) of data, the file
   * path, as a "chunks" element, so that a piece of it can be checked
   * alone (piece()).
   */
  chunks(data, path, chunk) {
    if (!Number.isSafeInteger(chunk) || chunk < 0) {
      throw new NoqtisError(CODES.EARG, 'chunk');
    }
    return withdir(new Map([[path, data]]), (dir) => run((h) => {
      const why = h.alloc(600);
      M.HEAPU8[why] = 0;
      const pn = h.alloc(4);
      let cap = 1 << 16;
      for (;;) {
        const po = h.alloc(cap);
        const rc = M._nqdchunk(h.str(dir), h.str(path), BigInt(chunk), po, cap,
          pn, why, 600);
        if (rc === CODES.EBUF && h.u32(pn) >= cap) {
          cap = h.u32(pn) + 1;
          continue;
        }
        check(rc, M.UTF8ToString(why));
        return dec8.decode(h.get(po, h.u32(pn)));
      }
    }));
  },

  /**
   * Checks piece, the bytes of a "chunks" element's file from byte off on
   * (a multiple of its chunk), against the element: { ok, code, rows }.
   */
  piece(element, piece, off = 0) {
    if (!Number.isSafeInteger(off) || off < 0) {
      throw new NoqtisError(CODES.EARG, 'off');
    }
    return withdir(new Map([['piece', piece]]), (dir) => run((h) => {
      const j = elem(element);
      const rp = h.alloc(4);
      M.HEAPU32[rp >>> 2] = 0;
      return dreport(h, M._nqdpiece(h.str(j), enc.encode(j).length,
        h.str(`${dir}/piece`), BigInt(off), rp), rp);
    }));
  },

  /** The commitment to m under salt (16 to 1,024 bytes): 64 hex digits. */
  commitment(salt, m) {
    const s = key(salt, 'salt');
    const b = bytes(m, 'm');
    return run((h) => {
      const hx = h.alloc(65);
      check(M._nqdcommit(h.put(s), s.length, h.put(b), b.length, hx));
      return M.UTF8ToString(hx);
    });
  },

  /**
   * A commitment to m (a randomisation list, an analysis plan), as `noqtis
   * commit` records it: { record, salt }, the record with it and the
   * 32-byte secret salt, to keep outside the capsule until the reveal.
   * Options: kind ('randomisation', 'preregistration', 'other'), label,
   * after (a UTC time before which it is not to be revealed), time
   * (seconds since 1970; default the clock).
   */
  commit(record, m, opts = {}) {
    const salt = random(32);
    const t = opts.time === undefined ? Date.now() / 1000 : opts.time;
    const e = { kind: opts.kind || 'other',
      created: new Date(Math.floor(t) * 1000).toISOString()
        .replace(/\.\d{3}Z$/, 'Z'),
      alg: 'sha3-256', digest: data.commitment(salt, m) };
    if (opts.label !== undefined) e.label = opts.label;
    if (opts.after !== undefined) e.after = opts.after;
    return { record: data.put(record, 'commits', e), salt };
  },

  /** The index in "commits" of the commitment to m under salt, or null. */
  reveal(record, m, salt) {
    const s = key(salt, 'salt');
    const b = bytes(m, 'm');
    return run((h) => withrec(h, record, (r) => {
      const pi = h.alloc(4);
      const rc = M._nqdreveal(r, h.put(s), s.length, h.put(b), b.length, pi);
      if (rc === CODES.EVRFY) return null;
      check(rc);
      return h.u32(pi);
    }));
  },

  /** How to cite the data, from record's "cite": fmt 'cff' or 'bib'. */
  cite(record, fmt = 'cff') {
    const f = { cff: 1, bib: 2, bibtex: 2 }[fmt];
    if (f === undefined) throw new NoqtisError(CODES.EARG, "fmt: 'cff' or 'bib'");
    return run((h) => withrec(h, record, (r) => dec8.decode(sized(h,
      (o, c, n) => M._nqdcite(r, f, o, c, n), 4096))));
  },

  /**
   * A report of the capsule given as files, as `noqtis report` writes it:
   * whether every check passed, the capsule's check (with `opts.trust` the
   * seal must be by that key), what its record says and the record's
   * check. `opts.format` 'md' (default) or 'txt'.
   */
  report(files, opts = {}) {
    const f = { md: 1, markdown: 1, txt: 2, text: 2 }[opts.format || 'md'];
    if (f === undefined) throw new NoqtisError(CODES.EARG, "format: 'md' or 'txt'");
    const list = entries(files);
    const has = (n) => list.some(([p]) => p.length === 1 && p[0] === n);
    const sealed = has('noqtis.sig');
    const rec = has('noqtis.data.json');
    if (!sealed && !rec) {
      throw new NoqtisError(CODES.EIO, 'neither a seal nor a data record');
    }
    return withdir(files, (dir) => run((h) => {
      const t = opts.trust === undefined ? null : key(opts.trust, 'trust');
      const o = h.alloc(48);
      M.HEAPU8.fill(0, o, o + 48);
      if (t) {
        M.HEAPU32[o >>> 2] = h.put(t);
        M.HEAPU32[(o >>> 2) + 1] = t.length;
      }
      const cp = h.alloc(4);
      const dp = h.alloc(4);
      M.HEAPU32[cp >>> 2] = 0;
      M.HEAPU32[dp >>> 2] = 0;
      const d = h.str(dir);
      try {
        if (sealed) {
          const rc = M._nqchkx(d, o, cp);
          if (h.u32(cp) === 0) throw new NoqtisError(rc);
        }
        if (rec) {
          const rc = M._nqdchk(d, dp);
          if (h.u32(dp) === 0) throw new NoqtisError(rc);
        }
        return dec8.decode(sized(h, (x, c, n) => M._nqdrpt(d, h.u32(cp),
          h.u32(dp), f, x, c, n), 65536));
      } finally {
        if (h.u32(cp)) M._nqrepfree(h.u32(cp));
        if (h.u32(dp)) M._nqdrepfree(h.u32(dp));
      }
    }));
  },

  /**
   * record with its "env" set as `noqtis env` records it (os, arch, the
   * noqtis version, locale, tz), with the JavaScript runtime: Node, Deno
   * or Bun and its version, or the browser's user agent, and the packages
   * (opts.packages, else none: a page or module knows no list of its
   * own). Options: rng and seed, locks ({ path: bytes } of lock files,
   * recorded with their SHA-256), packages ([{ name, version, source }]).
   */
  env(record, opts = {}) {
    const g = globalThis;
    const p = g.process;
    let rt;
    if (g.Deno) rt = { language: 'javascript', version: `deno ${g.Deno.version.deno}` };
    else if (g.Bun) rt = { language: 'javascript', version: `bun ${g.Bun.version}` };
    else if (p && p.versions && p.versions.node) {
      rt = { language: 'javascript', version: `node ${p.versions.node}` };
    } else {
      rt = { language: 'javascript', version: (g.navigator && g.navigator.userAgent) || '' };
    }
    rt.packages = [...(opts.packages || [])].map((x) => ({ name: x.name,
      version: x.version, source: x.source }))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    const os = { win32: 'windows', darwin: 'macos', linux: 'linux',
      freebsd: 'freebsd', openbsd: 'openbsd', netbsd: 'netbsd' };
    const ar = { x64: 'x86_64', arm64: 'aarch64', ia32: 'i686', arm: 'arm',
      s390x: 's390x', riscv64: 'riscv' };
    const e = { os: (p && os[p.platform]) || 'other',
      arch: (p && ar[p.arch]) || 'wasm32', noqtis: version() };
    const env = (p && p.env) || {};
    const loc = env.LC_ALL || env.LANG ||
      (g.Intl ? Intl.DateTimeFormat().resolvedOptions().locale : '');
    if (loc) e.locale = loc;
    const tz = env.TZ || (g.Intl ? Intl.DateTimeFormat().resolvedOptions().timeZone : '');
    if (tz) e.tz = tz;
    e.runtime = rt;
    if (opts.locks) {
      const lk = Object.entries(opts.locks).map(([path, b]) => ({ path,
        sha256: [...hash('sha256', bytes(b, path))]
          .map((x) => x.toString(16).padStart(2, '0')).join('') }));
      lk.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
      if (lk.length) e.locks = lk;
    }
    if (opts.seed !== undefined && opts.rng === undefined) {
      throw new NoqtisError(CODES.EARG, 'seed needs rng');
    }
    if (opts.rng !== undefined) {
      e.rng = { kind: opts.rng };
      if (opts.seed !== undefined) e.rng.seed = opts.seed;
    }
    return data.put(record, 'env', e);
  },
});

export default {
  init, version, selftest, algs, random, hash, hmac, sign, kem, capsule, dsse,
  idcard, keyfile, data, NoqtisError, codes, errmsg, cteq, blake2b, argon2id,
  hasher, kt128, kt256, chacha20, sivenc, sivdec, gsivenc, gsivdec,
};
