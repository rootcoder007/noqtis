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
  /**
   * noqtis.wasm as bytes, a compiled module or a Response; on Node, Deno and
   * Bun also its path or file: URL, and optional there (the package reads
   * its own). Required in a browser, where the package fetches nothing.
   */
  wasm?: Uint8Array | ArrayBuffer | WebAssembly.Module | Response | URL | string;
}

/** Loads the WebAssembly module; call (and await) once before anything else. */
export function init(opts?: InitOptions): Promise<void>;
export function version(): string;
/** The known-answer self-test; throws (code EKAT) when an answer differs. */
export function selftest(): void;
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

export interface Signer {
  update(data: Data): Signer;
  sign(opts?: SignOptions): Bytes;
  end(): void;
}

export interface Verifier {
  update(data: Data): Verifier;
  verify(sig: Bytes): boolean;
  end(): void;
}

export interface Hasher {
  update(data: Data): Hasher;
  /** For SHAKE, len bytes more each call. */
  digest(len?: number): Bytes;
  end(): void;
}

export interface StreamOptions {
  ctx?: Data;
  /** 1024 to 16777216 bytes; 65536. */
  chunk?: number;
}

export interface Sealer {
  readonly header: Bytes;
  readonly chunk: number;
  update(chunk: Data): Bytes;
  last(chunk: Data): Bytes;
  end(): void;
}

export interface Opener {
  readonly chunk: number;
  update(chunk: Data): Bytes;
  last(chunk: Data): Bytes;
  end(): void;
}

export type Pieces = Iterable<Data> | AsyncIterable<Data>;

export interface Package {
  name: string;
  version: string;
  source: string;
}

/** true when a and b are equal, in time that depends only on their length. */
export function cteq(a: Data, b: Data): boolean;
/** BLAKE2b (RFC 7693), keyed with opts.key; opts.length 1 to 64 (64). */
export function blake2b(data: Data, opts?: { key?: Data; length?: number }): Bytes;
/** KangarooTwelve KT128 (RFC 9861): opts.length bytes (32), opts.custom. */
export function kt128(data: Data, opts?: { length?: number; custom?: Data }): Bytes;
/** KangarooTwelve KT256 (RFC 9861): opts.length bytes (64), opts.custom. */
export function kt256(data: Data, opts?: { length?: number; custom?: Data }): Bytes;
/** The ChaCha20 stream (RFC 8439) from block opts.counter (0). NOT AUTHENTICATED. */
export function chacha20(key: Data, nonce: Data, data: Data, opts?: { counter?: number }): Bytes;
/** AES-SIV (RFC 5297): the 16-byte IV, then the ciphertext; ad is up to 126 strings. */
export function sivenc(key: Data, data: Data, ad?: Data[]): Bytes;
/** The plaintext of sivenc; throws when it does not verify. */
export function sivdec(key: Data, data: Data, ad?: Data[]): Bytes;
/** AES-GCM-SIV (RFC 8452): the ciphertext, then the 16-byte tag. */
export function gsivenc(key: Data, nonce: Data, data: Data, ad?: Data): Bytes;
/** The plaintext of gsivenc; throws when it does not verify. */
export function gsivdec(key: Data, nonce: Data, data: Data, ad?: Data): Bytes;
/** Argon2id (RFC 9106): opts t (3), m KiB (65536), p (4), length (32). */
export function argon2id(pw: Data, salt: Data, opts?: { t?: number; m?: number;
  p?: number; length?: number; key?: Data; ad?: Data }): Bytes;
/** A digest of data given in pieces. */
export function hasher(alg: HashAlg): Hasher;

export const sign: {
  /**
   * seed: xi (32 bytes) for ML-DSA, SK.seed||SK.prf||PK.seed for SLH-DSA,
   * the 32-byte private key for Ed25519, xi||the Ed25519 key (64 bytes)
   * for a hybrid.
   */
  keygen(alg: SignAlg, opts?: { seed?: Bytes }): KeyPair;
  sign(alg: SignAlg, secretKey: Bytes, msg: Data, opts?: SignOptions): Bytes;
  /** false when the signature does not verify or is malformed. */
  /** The 64-byte message representative mu of FIPS 204 (ML-DSA). */
  mu(alg: SignAlg, publicKey: Bytes, msg: Data, opts?: SignOptions): Bytes;
  /** The signature of the message whose mu is mu; opts.rnd or deterministic. */
  signmu(alg: SignAlg, secretKey: Bytes, mu: Bytes, opts?: SignOptions): Bytes;
  verifymu(alg: SignAlg, publicKey: Bytes, mu: Bytes, sig: Bytes): boolean;
  /** A signature over a message given in pieces. */
  signer(alg: SignAlg, secretKey: Bytes, opts?: SignOptions): Signer;
  /** verify() over a message given in pieces. */
  verifier(alg: SignAlg, publicKey: Bytes, opts?: SignOptions): Verifier;
  verify(alg: SignAlg, publicKey: Bytes, msg: Data, sig: Bytes,
    opts?: VerifyOptions): boolean;
};

export const kem: {
  keygen(alg: KemAlg, opts?: { seed?: Bytes }): KeyPair;
  encap(alg: KemAlg, publicKey: Bytes, opts?: { seed?: Bytes }):
    { ciphertext: Bytes; sharedSecret: Bytes };
  /** Implicit rejection: a bad ciphertext gives an unrelated secret. */
  decap(alg: KemAlg, secretKey: Bytes, ciphertext: Bytes): Bytes;
  /** msg sealed to the ML-KEM public key (noqtis-kseal-1). */
  seal(alg: KemAlg, publicKey: Bytes, msg: Data, opts?: { ctx?: Data }): Bytes;
  /** The message seal() sealed; EVRFY for any change, key or ctx. */
  open(alg: KemAlg, secretKey: Bytes, data: Data, opts?: { ctx?: Data }): Bytes;
  /** A stream sealed to an ML-KEM key (noqtis-kstream-1), chunk by chunk. */
  sealer(alg: KemAlg, publicKey: Bytes, opts?: StreamOptions): Sealer;
  /** Opens what sealer() wrote, chunk by chunk. */
  opener(alg: KemAlg, secretKey: Bytes, header: Bytes, opts?: { ctx?: Data }):
    Opener;
  /** Seals source to the sealed stream's pieces, one chunk held at a time. */
  box(alg: KemAlg, publicKey: Bytes, source: Pieces, opts?: StreamOptions):
    AsyncGenerator<Bytes, void, undefined>;
  /** Opens a sealed stream to its plaintext pieces, each once it verified. */
  unbox(alg: KemAlg, secretKey: Bytes, source: Pieces, opts?: { ctx?: Data }):
    AsyncGenerator<Bytes, void, undefined>;
  /** Seals source to several ML-KEM keys, signed when a sender is named. */
  boxTo(recipients: Array<{ alg: KemAlg; publicKey: Bytes }>, source: Pieces,
    opts?: StreamOptions & { sender?: { alg: SignAlg; secretKey: Bytes } }):
    AsyncGenerator<Bytes, void, undefined>;
  /** Opens what boxTo() sealed with one recipient's key; sender checks it. */
  unboxFrom(alg: KemAlg, secretKey: Bytes, source: Pieces,
    opts?: { ctx?: Data; sender?: Bytes }):
    AsyncGenerator<Bytes, void, undefined>;
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
  /** true when the checks left files out (only, a proof): ok then says
   * nothing of the others. */
  partial: boolean;
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
  /** A key statement (JSON bytes) that the key pair seals until opts.at. */
  expire(alg: SignAlg, secretKey: Bytes, publicKey: Bytes,
    opts: KeyOptions): Bytes;
  /** What the capsule says ("info.*" rows), with nothing checked. */
  inspect(files: Files): CheckResult;
  /** Why seal() refused the files, or null. */
  sealWhy(files: Files): { why: string; path: string } | null;
  /** The RFC 3161 TimeStampReq for the seal. */
  tsreq(files: Files, opts?: { nonce?: Bytes }): Bytes;
  /** The seal with the TSA's reply as its timestamp, once it checks. */
  tsput(files: Files, reply: Data, opts?: { nonce?: Bytes; anchors?: Bytes[] }):
    { 'noqtis.sig': Bytes; time: number };
  /** The TimeStampReq of the evidence record's next archive timestamp. */
  ersreq(files: Files, opts?: { hash?: HashAlg; nonce?: Bytes }): Bytes;
  /** The evidence record with the reply added, once both check. */
  ersput(files: Files, reply: Data,
    opts?: { hash?: HashAlg; nonce?: Bytes; anchors?: Bytes[] }):
    { 'noqtis.ers': Bytes; time: number; how: 'new' | 'timestamp' | 'hash-tree' };
  /** The capsule as one file (noqtis-bundle-1). */
  pack(files: Files, opts?: { files?: boolean }): Bytes;
  /** A bundle's files; EDEC for anything a capsule cannot hold. */
  unpack(bundle: Data): Map<string, Bytes>;
  /** Checks an append-only chain of capsules, oldest first. */
  chain(caps: Files[], opts?: { trust?: Bytes; anchors?: Bytes[] }):
    DReport & { head: Bytes | null };
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
  encode(alg: SignAlg | KemAlg, kind: 'pub' | 'sec', key: Bytes,
    opts?: { passphrase?: Data }): string;
  /** sk under a passphrase (noqtis-pwkey-1). */
  pwenc(passphrase: Data, sk: Bytes,
    opts?: { ad?: Data; m?: number; t?: number; p?: number }): Bytes;
  /** The key pwenc() protected; EVRFY for a wrong passphrase. */
  pwdec(passphrase: Data, data: Bytes, opts?: { ad?: Data }): Bytes;
  decode(text: string | Bytes, opts?: { passphrase?: Data }):
    { alg: string; kind: 'pub' | 'sec'; key: Bytes };
};

/** What an X.509 certificate says of its key and holder. */
export interface Cert {
  /** '' for a key of a kind noqtis does not have. */
  alg: string; kem: boolean;
  /** SHA-256 of the certificate, hex. */
  fingerprint: string;
  /** Seconds since 1970. */
  notBefore: number; notAfter: number;
  ca: boolean; name: string; email: string;
  /** Empty when read as a signer alone. */
  publicKey: Bytes;
}

export const armor: {
  /** data as text (RFC 7468) under the label. */
  encode(label: string, data: Data): string;
  /** One armor read back. */
  decode(text: Data): { label: string; data: Bytes };
};

export const mail: {
  /** A self-signed X.509 certificate (DER) for a signature key. */
  selfCert(alg: SignAlg, secretKey: Bytes, publicKey: Bytes, name: string,
    opts?: { email?: string | null; notBefore?: number | Date;
      notAfter?: number | Date }): Bytes;
  /** A certificate for an ML-KEM public key, issued by a signature key. */
  kemCert(issuerAlg: SignAlg, issuerSecretKey: Bytes,
    issuerCertificate: Bytes, alg: KemAlg, publicKey: Bytes,
    opts?: { notBefore?: number | Date; notAfter?: number | Date }): Bytes;
  readCert(certificate: Bytes): Cert;
  /** A CMS SignedData (DER). */
  cmsSign(alg: SignAlg, secretKey: Bytes, certificate: Bytes, content: Data,
    opts?: { detached?: boolean; at?: number | Date }): Bytes;
  /** The content and the signer, or null when it does not verify. */
  cmsVerify(cms: Data, anchors: Bytes[],
    opts?: { content?: Data | null; at?: number | Date }):
    { content: Bytes; signer: Cert } | null;
  /** A CMS AuthEnvelopedData (DER) to ML-KEM certificates. */
  cmsEncrypt(certificates: Bytes[], content: Data): Bytes;
  /** The content, or null when it is not for this key or was changed. */
  cmsDecrypt(alg: KemAlg, secretKey: Bytes, cms: Data,
    opts?: { certificate?: Bytes | null }): Bytes | null;
  smimeSign(alg: SignAlg, secretKey: Bytes, certificate: Bytes, entity: Data,
    opts?: { detached?: boolean; at?: number | Date }): string;
  smimeVerify(mime: Data, anchors: Bytes[], opts?: { at?: number | Date }):
    { entity: string; signer: Cert } | null;
  smimeEncrypt(certificates: Bytes[], entity: Data): string;
  smimeDecrypt(alg: KemAlg, secretKey: Bytes, mime: Data,
    opts?: { certificate?: Bytes | null }): string | null;
};

export type PgpAlg = 'mldsa65-ed25519' | 'ed25519' | 'slh-shake-128s'
  | 'slh-shake-128f' | 'slh-shake-256s';
export type PgpEncAlg = 'mlkem768-x25519' | 'x25519';
export type PgpArmor = 'message' | 'public key' | 'private key' | 'signature';

/** What an OpenPGP key or certificate says of itself. */
export interface PgpKey {
  alg: string; encAlg: string | null; secret: boolean; locked: boolean;
  fingerprint: string; encFingerprint: string | null;
  /** Seconds since 1970; expires null: never. */
  created: number; expires: number | null; userId: string;
}

export const pgp: {
  /** A new version 6 OpenPGP key (RFC 9580). */
  generate(userId: string, opts?: { alg?: PgpAlg; encAlg?: PgpEncAlg | null;
    passphrase?: Data | null; created?: number | Date }):
    { secretKey: Bytes; certificate: Bytes };
  info(key: Bytes): PgpKey;
  sign(secretKey: Bytes, content: Data,
    opts?: { mode?: 'inline' | 'detached' | 'clear';
      passphrase?: Data | null; at?: number | Date }): Bytes;
  /** The data and the signature's time, or null. */
  verify(certificate: Bytes, signature: Data,
    opts?: { content?: Data | null }): { data: Bytes; at: number } | null;
  encrypt(content: Data, opts?: { to?: Bytes[]; passphrase?: Data | null;
    signer?: Bytes | null; signerPassphrase?: Data | null;
    at?: number | Date }): Bytes;
  /** The content, or null when it does not open. */
  decrypt(message: Data, opts?: { key?: Bytes | null;
    passphrase?: Data | null; signer?: Bytes | null }):
    { data: Bytes; signed: boolean; at: number | null } | null;
  armor(kind: PgpArmor, data: Data): string;
  dearmor(text: Data): { kind: PgpArmor; data: Bytes };
};

export type Trust = 'unknown' | 'never' | 'marginal' | 'full' | 'ultimate';
/** The files of a key store: path to bytes. */
export type StoreFiles = Map<string, Data> | Record<string, Data> | null;

/** One public key of a store. */
export interface StoreKey {
  alg: string; kem: boolean; fingerprint: Bytes; name: string; email: string;
  card: boolean; trust: Trust; valid: 'none' | 'marginal' | 'full';
  certs: number;
}

export const keystore: {
  add(files: StoreFiles, alg: SignAlg | KemAlg, publicKey: Bytes,
    name: string, opts?: { email?: string | null; card?: Data | null }):
    { files: Map<string, Bytes>; fingerprint: Bytes };
  list(files: StoreFiles, query?: string | null): StoreKey[];
  get(files: StoreFiles, fingerprint: Bytes | string):
    { alg: string; publicKey: Bytes };
  certify(files: StoreFiles, alg: SignAlg, secretKey: Bytes,
    publicKey: Bytes, fingerprint: Bytes | string,
    opts?: { at?: number | Date }):
    { files: Map<string, Bytes>; cert: string };
  addCert(files: StoreFiles, cert: Data): { files: Map<string, Bytes> };
  trust(files: StoreFiles, fingerprint: Bytes | string, level: Trust):
    { files: Map<string, Bytes> };
  remove(files: StoreFiles, fingerprint: Bytes | string):
    { files: Map<string, Bytes> };
  export(files: StoreFiles, fingerprint: Bytes | string): string;
  import(files: StoreFiles, bundle: Data, opts?: { email?: string | null }):
    { files: Map<string, Bytes>; fingerprint: Bytes; keys: number };
  /** Where the keys of an address are looked for, over https. */
  url(email: string): string;
};

/** A row of a data check; stats holds a drift row's numbers. */
export interface DRow {
  check: string; ok: boolean; detail: string;
  stats: Record<string, unknown> | null;
}
export interface DReport { ok: boolean; code: number; rows: DRow[] }
export interface CsvOptions { delim?: string; header?: boolean; ranges?: boolean }
export interface DriftOptions extends CsvOptions {
  psiwarn?: number; psifail?: number; alpha?: number; minn?: number;
  benford?: boolean;
}
export type Element = string | Record<string, unknown>;

/** The data layer (noqtis-data(5)): records are their JSON text. */
export const data: {
  canon(record: string): string;
  add(record: string | null, files: Files, paths: string | string[],
    fields?: Record<string, string>): string;
  put(record: string, member: string, element: Element): string;
  check(files: Files): DReport;
  schema(files: Files, path: string, opts?: CsvOptions): string;
  schemaCheck(files: Files, schema: Element): DReport;
  pin(files: Files, path: string, opts?: CsvOptions): string;
  drift(stats: Element, data: Data, opts?: DriftOptions): DReport;
  diff(a: Files, b: Files): DReport;
  addrs(record: string, path: string):
    { kind: 'url' | 'portal' | 'mirror' | 'archived'; url: string }[];
  verify(record: string, path: string, bytes: Data): boolean;
  field(record: string, member: string, i: number, name: string):
    string | null;
  request(resolver: Element): string;
  reply(resolver: Element, body: Data): { url: string; time: string };
  wayback(url: string): string;
  key(record: string, member: string, key: string): string | null;
  del(record: string, member: string, key?: string | null): string;
  synth(record: string, files: Files, path: string, seed: number,
    rows?: number): { record: string; data: Bytes };
  calibrate(stats: Element, datas: Data[], opts?: CsvOptions): string;
  chunks(data: Data, path: string, chunk: number): string;
  piece(element: Element, piece: Data, off?: number): DReport;
  commitment(salt: Bytes, m: Data): string;
  commit(record: string, m: Data, opts?: { kind?: string; label?: string;
    after?: string; time?: number }): { record: string; salt: Bytes };
  reveal(record: string, m: Data, salt: Bytes): number | null;
  cite(record: string, fmt?: 'cff' | 'bib' | 'bibtex'): string;
  report(files: Files, opts?: { trust?: Bytes; format?: 'md' | 'txt' }): string;
  env(record: string, opts?: { rng?: string; seed?: number | string;
    locks?: Record<string, Data>; packages?: Package[] }): string;
};

export const codes: Readonly<{
  OK: 0; EARG: -1; EBUF: -2; EVRFY: -3; EDEC: -4; ERNG: -5; EMEM: -6;
  EIO: -7; ENOSUP: -8; ELIM: -9; ESTATE: -10; EFLT: -11; EKAT: -12; ESTOP: -13;
}>;

/** The library's message (nqerr) for an NQE* code. */
export function errmsg(code: number): string;

export class NoqtisError extends Error {
  /** The NQE* code, negative. */
  readonly code: number;
}

