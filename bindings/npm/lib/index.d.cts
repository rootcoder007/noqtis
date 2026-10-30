// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

export type Bytes = Uint8Array;
/** Messages, contexts and hash input may also be strings (UTF-8). */
export type Data = Uint8Array | ArrayBuffer | ArrayBufferView | string;

export type SignAlg =
  | 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87'
  | 'SLH-DSA-SHA2-128s' | 'SLH-DSA-SHA2-128f'
  | 'SLH-DSA-SHA2-192s' | 'SLH-DSA-SHA2-192f'
  | 'SLH-DSA-SHA2-256s' | 'SLH-DSA-SHA2-256f'
  | 'SLH-DSA-SHAKE-128s' | 'SLH-DSA-SHAKE-128f'
  | 'SLH-DSA-SHAKE-192s' | 'SLH-DSA-SHAKE-192f'
  | 'SLH-DSA-SHAKE-256s' | 'SLH-DSA-SHAKE-256f'
  | 'ML-DSA-44+Ed25519' | 'ML-DSA-65+Ed25519' | 'ML-DSA-87+Ed25519'
  | 'Ed25519'
  | (string & {});

export type KemAlg =
  | 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024'
  | 'HQC-128' | 'HQC-192' | 'HQC-256'
  | (string & {});

export type HashAlg =
  | 'sha224' | 'sha256' | 'sha384' | 'sha512' | 'sha512-224' | 'sha512-256'
  | 'sha3-224' | 'sha3-256' | 'sha3-384' | 'sha3-512'
  | 'shake128' | 'shake256';

export interface InitOptions {
  /** noqtis.wasm as bytes, a compiled module, or its URL or path. */
  wasm?: Uint8Array | ArrayBuffer | WebAssembly.Module | URL | string;
}

/** Loads the WebAssembly module; call (and await) once before anything else. */
export function init(opts?: InitOptions): Promise<void>;
export function version(): string;
/** n bytes from crypto.getRandomValues, through the library's nqrand. */
export function random(n: number): Bytes;

export type AlgInfo =
  | { name: string; kind: 'sign'; publicKey: number; secretKey: number;
      signature: number }
  | { name: string; kind: 'kem'; publicKey: number; secretKey: number;
      ciphertext: number; sharedSecret: number }
  | { name: HashAlg; kind: 'hash'; digest: number };

/** Every algorithm with its sizes in bytes. */
export function algs(): AlgInfo[];

/** SHAKE takes opts.length (default 32 for shake128, 64 for shake256). */
export function hash(alg: HashAlg, data: Data, opts?: { length?: number }):
  Bytes;
export function hmac(alg: Exclude<HashAlg, 'shake128' | 'shake256'>,
  key: Data, data: Data): Bytes;

export interface KeyPair {
  publicKey: Bytes;
  secretKey: Bytes;
}

export interface SignOptions {
  /** Context string, at most 255 bytes. */
  ctx?: Data;
  /** All-zero per-signature randomness (the deterministic variant). */
  deterministic?: boolean;
  /** Per-signature randomness: 32 bytes ML-DSA and hybrids, n SLH-DSA. */
  rnd?: Bytes;
  /** HashML-DSA / HashSLH-DSA with this hash; msg is hashed inside. */
  prehash?: HashAlg;
}

export interface VerifyOptions {
  ctx?: Data;
  prehash?: HashAlg;
}

export const sign: {
  /**
   * seed: xi (32 bytes) for ML-DSA, SK.seed||SK.prf||PK.seed for SLH-DSA,
   * the 32-byte private key for Ed25519, xi||the Ed25519 key (64 bytes)
   * for a hybrid.
   */
  keygen(alg: SignAlg, opts?: { seed?: Bytes }): KeyPair;
  sign(alg: SignAlg, secretKey: Bytes, msg: Data, opts?: SignOptions): Bytes;
  /** false when the signature does not verify or is malformed. */
  verify(alg: SignAlg, publicKey: Bytes, msg: Data, sig: Bytes,
    opts?: VerifyOptions): boolean;
};

export const kem: {
  keygen(alg: KemAlg, opts?: { seed?: Bytes }): KeyPair;
  encap(alg: KemAlg, publicKey: Bytes, opts?: { seed?: Bytes }):
    { ciphertext: Bytes; sharedSecret: Bytes };
  /** Implicit rejection: a bad ciphertext gives an unrelated secret. */
  decap(alg: KemAlg, secretKey: Bytes, ciphertext: Bytes): Bytes;
};

/** Capsule files: '/'-separated relative paths to contents. */
export type Files =
  | Map<string, Data>
  | Record<string, Data>
  | Iterable<readonly [string, Data]>;

export interface CheckRow {
  check: string;
  ok: boolean;
  detail: string;
}

export interface CheckResult {
  /** true only when every check passed. */
  ok: boolean;
  /** 0 (NQOK) or -3 (NQEVRFY). */
  code: number;
  checks: CheckRow[];
}

export interface CheckOptions {
  /** The public key the seal must carry; without it the seal's own. */
  trust?: Bytes;
  /** DER certificates of TSA trust anchors, at most 32. */
  anchors?: Bytes[];
  /** Check just these paths; "partial" rows say what was left out. */
  only?: string[];
  /** Capsules among which a format 2 capsule's inputs are found by id. */
  lineage?: Files[];
  /** Key statements from capsule.rotate / capsule.revoke; need trust. */
  keys?: Data[];
  /** A proof from capsule.prove, checked instead of (or with) the files. */
  proof?: Data;
}

export interface SealOptions {
  /** A JSON value, or JSON text, kept in the manifest. */
  meta?: unknown;
  /** Creation time in seconds since 1970; default the clock. */
  time?: number;
  /** 1 (the default) or 2: a Merkle tree over the files. */
  format?: 1 | 2;
  /** Format 2: the capsules this one was made from, by capsule.id. */
  inputs?: { name: string; id: Bytes }[];
}

export interface KeyOptions {
  /** When it takes effect: seconds since 1970 or a Date; default now. */
  at?: number | Date;
  /** Up to 255 bytes of text. */
  reason?: string;
}

export interface FileEntry {
  path: string;
  size: number;
  /** 64 hex digits. */
  sha256: string;
}

export const capsule: {
  /** files may be null when opts.proof is given. */
  check(files: Files | null, opts?: CheckOptions): CheckResult;
  seal(files: Files, alg: SignAlg, secretKey: Bytes, publicKey: Bytes,
    opts?: SealOptions): { 'noqtis.json': Bytes; 'noqtis.sig': Bytes };
  /** The capsule's id (32 bytes); nothing is checked. */
  id(files: Files): Bytes;
  /** A proof (JSON bytes) that paths are files of a format 2 capsule. */
  prove(files: Files, paths: string | string[]): Bytes;
  /** The files the manifest lists; nothing is checked. */
  files(files: Files): FileEntry[];
  /** A key statement (JSON bytes): the key pair is replaced by the new. */
  rotate(alg: SignAlg, secretKey: Bytes, publicKey: Bytes, newAlg: SignAlg,
    newSecretKey: Bytes, newPublicKey: Bytes, opts?: KeyOptions): Bytes;
  /** A key statement (JSON bytes) that the key pair is revoked. */
  revoke(alg: SignAlg, secretKey: Bytes, publicKey: Bytes,
    opts?: KeyOptions): Bytes;
};

export const dsse: {
  /** A DSSE envelope (canonical JSON bytes) signed by the key pair. */
  sign(alg: SignAlg, secretKey: Bytes, publicKey: Bytes, type: string,
    payload: Data): Bytes;
  /** The payload and its type, or null when no signature verifies. */
  verify(alg: SignAlg, publicKey: Bytes, envelope: Data):
    { payload: Bytes; payloadType: string } | null;
};

export interface CardFields {
  /** 1 to 255 bytes of text, no control character, no edge spaces. */
  name: string;
  /** An ORCID iD or its https://orcid.org/ address; check digit verified. */
  orcid?: string | null;
  email?: string | null;
  /** An https:// address. */
  url?: string | null;
  affil?: string | null;
}

export interface Card {
  name: string;
  orcid: string | null;
  email: string | null;
  url: string | null;
  affil: string | null;
  /** YYYY-MM-DDTHH:MM:SSZ */
  created: string;
  alg: string;
  publicKey: Bytes;
  /** The SHA-256 of publicKey, hex. */
  keySha256: string;
}

export const idcard: {
  /** An identity card (JSON bytes) for the key pair, signed by it. */
  make(alg: SignAlg, secretKey: Bytes, publicKey: Bytes, fields: CardFields,
    opts?: { at?: number | Date }): Bytes;
  /** The card, or null when it does not verify or is not trust's. */
  verify(card: Data, opts?: { trust?: Bytes | null }): Card | null;
};

export const keyfile: {
  encode(alg: SignAlg | KemAlg, kind: 'pub' | 'sec', key: Bytes): string;
  decode(text: string | Bytes):
    { alg: string; kind: 'pub' | 'sec'; key: Bytes };
};

export const codes: Readonly<{
  OK: 0; EARG: -1; EBUF: -2; EVRFY: -3; EDEC: -4; ERNG: -5; EMEM: -6;
  EIO: -7; ENOSUP: -8; ELIM: -9; ESTATE: -10;
}>;

/** The library's message (nqerr) for an NQE* code. */
export function errmsg(code: number): string;

export class NoqtisError extends Error {
  /** The NQE* code, negative. */
  readonly code: number;
}

