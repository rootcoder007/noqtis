---
title: Capsule format, version 1
description: The normative specification of NOQTIS capsules, noqtis-capsule-1 manifests and noqtis-seal-1 seals.
---

| | |
|---|---|
| **Manifest format** | `noqtis-capsule-1` |
| **Seal format** | `noqtis-seal-1` |
| **Status** | Version 1, stable within the 0.x series of NOQTIS; any incompatible change gets new format strings |
| **Reference implementation** | `src/cap/` of NOQTIS (`nqseal`, `nqchk`, `nqchkt`) |

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT and MAY are to
be read as described in BCP 14 (RFC 2119, RFC 8174) when, and only when,
they appear in all capitals.

## 1. Overview

A **capsule** is a folder (the *capsule root*) that holds a set of files
together with two files at its top level:

- `noqtis.json`, the **manifest**: every file's path, size, SHA-256 and
  SHA3-256;
- `noqtis.sig`, the **seal**: a post-quantum signature over the exact bytes
  of the manifest, the signer's public key, and optionally an RFC 3161
  timestamp over the signature.

A **sealer** writes both files; a **checker** decides whether the folder
is exactly what was sealed.

## 2. Canonical JSON

Both files MUST be JSON texts (RFC 8259) in the canonical form of the JSON
Canonicalization Scheme (JCS, RFC 8785):

1. UTF-8 without a byte order mark; every string valid UTF-8 (no overlong
   forms, no surrogates).
2. No whitespace outside strings.
3. Object members sorted by their names compared as arrays of UTF-16 code
   units; no name twice in one object.
4. Strings escaped minimally: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`; any
   other character below U+0020 as `\u00` followed by two lower-case hex
   digits; every other character, including `/` and all non-ASCII, as
   itself.
5. Numbers in the ECMAScript shortest round-trip form. Integers in the
   fields this specification defines MUST be written as plain decimal
   digits without sign, leading zeros, fraction or exponent.

A checker MUST verify that each file is byte-identical to the canonical
form of the value it parses, and MUST treat any difference as a failure.
JSON values MUST NOT be nested more than 64 levels deep.

## 3. The manifest, `noqtis.json`

The manifest is a JSON object with exactly the following members; a
member not listed here MUST cause a failure.

| Member | Type | Required | Value |
|---|---|---|---|
| `created` | string | yes | the creation time (§3.2) |
| `files` | array | yes | one entry per file (§3.1), sorted (§3.3) |
| `format` | string | yes | exactly `noqtis-capsule-1` |
| `meta` | object | no | any JSON object, opaque to NOQTIS, at most 1 MiB of canonical text |

Because of the canonical member order the manifest always has the layout

```text
{"created":S,"files":[E,E,...],"format":"noqtis-capsule-1"[,"meta":{...}]}
E = {"path":S,"sha256":H,"sha3_256":H,"size":N}
```

and a checker MAY read it as a stream in exactly this layout, one entry at
a time.

### 3.1 File entries

Each element of `files` is an object with exactly these members:

| Member | Type | Value |
|---|---|---|
| `path` | string | the file's path relative to the capsule root (§4) |
| `sha256` | string | SHA-256 (FIPS 180-4) of the file's bytes, 64 lower-case hex digits |
| `sha3_256` | string | SHA3-256 (FIPS 202) of the file's bytes, 64 lower-case hex digits |
| `size` | number | the file's length in bytes, an integer from 0 to 2^53 − 1 |

Upper-case hex digits MUST cause a failure.

### 3.2 Creation time

`created` MUST be an RFC 3339 date-time in UTC of the form
`YYYY-MM-DDTHH:MM:SSZ`, optionally with a fraction of a second
(`.` and one or more digits) before the `Z`. The date MUST exist (leap
years included); the seconds MAY be 60 (a leap second). A sealer SHOULD
write whole seconds and SHOULD take the time from `SOURCE_DATE_EPOCH`
when that environment variable is set.

`created` is the sealer's claim. It is covered by the signature but
proves nothing about the actual time; see §6.4.

### 3.3 Order

The entries MUST be sorted in ascending order of the bytes of their `path`
(after JSON unescaping, compared as unsigned bytes, a proper prefix sorting
first). No `path` may appear twice.

## 4. Paths

A `path` MUST satisfy all of the following:

1. It is not empty, does not start with `/`, and contains no NUL.
2. Its segments are separated by `/`. It is in **normal form**: no empty
   segment (no `//`, no trailing `/`) and no segment `.`.
3. Every segment is a **portable name**: not empty, not `.` or `..`, valid
   UTF-8, and containing no control character (U+0000 to U+001F, U+007F),
   `/`, `\` or `:`.
4. It is at most 4096 bytes long.
5. It names a regular file inside the capsule root, reached without
   following any symbolic link, junction or other reparse point.
6. No two paths of one capsule are equal when ASCII letters are compared
   without case.

A checker MUST report a path that breaks rule 1 or 3 as refused, and MUST
report a path that breaks rule 2 as not in normal form even when its
normalised form names a listed file.

The capsule root's own `noqtis.json` and `noqtis.sig` MUST NOT be listed.
Files with those names in subfolders are ordinary files. Folders are not
listed: they are implied by the paths, so an empty folder is not part of a
capsule. File permissions, owners and times are not recorded.

## 5. The seal, `noqtis.sig`

The seal is a JSON object with exactly the following members, at most
1 MiB in total; a member not listed here MUST cause a failure.

| Member | Type | Required | Value |
|---|---|---|---|
| `alg` | string | yes | the signature algorithm (§5.1) |
| `context` | string | yes | the FIPS 204/205 context string: exactly `noqtis-capsule-1` |
| `format` | string | yes | exactly `noqtis-seal-1` |
| `manifest_sha256` | string | yes | SHA-256 of the exact bytes of `noqtis.json`, 64 lower-case hex digits |
| `public_key` | string | yes | the signer's public key, base64 (§5.2) |
| `signature` | string | yes | the signature, base64 (§5.2) |
| `timestamp` | string | no | an RFC 3161 time-stamp token, base64 (§5.3) |

### 5.1 Signature

`alg` MUST be one of `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`,
`SLH-DSA-SHA2-128s`, `SLH-DSA-SHA2-128f`, `SLH-DSA-SHA2-192s`,
`SLH-DSA-SHA2-192f`, `SLH-DSA-SHA2-256s`, `SLH-DSA-SHA2-256f`,
`SLH-DSA-SHAKE-128s`, `SLH-DSA-SHAKE-128f`, `SLH-DSA-SHAKE-192s`,
`SLH-DSA-SHAKE-192f`, `SLH-DSA-SHAKE-256s`, `SLH-DSA-SHAKE-256f`,
`ML-DSA-44+Ed25519`, `ML-DSA-65+Ed25519` or `ML-DSA-87+Ed25519`, spelled
exactly so. `Ed25519` alone is not post-quantum and MUST be refused.

A hybrid (`ML-DSA-*+Ed25519`) `public_key` is the ML-DSA public key
followed by the 32-byte Ed25519 one, and its `signature` the ML-DSA
signature followed by the 64-byte Ed25519 one; both parts MUST verify.
Each part signs the same bytes with the context `noqtis-hybrid:`
followed by `context` (ML-DSA with that context string, Ed25519 as
Ed25519ctx, RFC 8032). The Ed25519 public key MUST be of prime order.

`signature` MUST be a signature of the **pure** variant (ML-DSA.Sign of
FIPS 204 or slh_sign of FIPS 205, not the pre-hash variants) over the
exact bytes of `noqtis.json` as stored, with `context` as the context
string. The context MUST be `noqtis-capsule-1`, and a checker MUST refuse
any other: it separates seals from every other use of the same key, so
that a signature made for another purpose over the same bytes (a plain
`noqtis sign`, say) is never taken for a seal. Hedged and deterministic signatures are equally valid.

`public_key` and `signature` MUST have exactly the sizes the algorithm
defines (FIPS 204 Table 2, FIPS 205 Table 2).

### 5.2 Base64

`public_key`, `signature` and `timestamp` use the base64 alphabet of
RFC 4648 section 4 with `=` padding, without line breaks or any other
character; the padding bits MUST be zero. Anything else MUST cause a
failure.

### 5.3 Timestamp

When present, `timestamp` holds a DER-encoded RFC 3161 `TimeStampToken`
(a CMS `SignedData`) whose `messageImprint` is the hash, by its own
`hashAlgorithm` (SHA-256, SHA-384 or SHA-512), of the decoded `signature`
bytes. It covers the signature, and therefore the manifest and the files,
without revealing any of them to the TSA.

## 6. Sealing

A sealer:

1. MUST list every entry under the capsule root without following
   symbolic links or reparse points.
2. MUST refuse to seal, writing nothing, when the folder holds a symbolic
   link, a reparse point, a device, pipe, socket or other non-regular file,
   a name §4 refuses, two paths equal but for ASCII case, a file larger
   than 2^53 − 1 bytes, or more than any limit of §8 allows.
3. MUST write the manifest and the seal in canonical form (§2).
4. MUST verify the new signature with `public_key` before it writes
   `noqtis.sig`, so that a seal made with a secret key and a public key
   that are not one pair is never written.
5. SHOULD write `noqtis.json` before `noqtis.sig`.

## 7. Checking

A checker MUST perform each of the following checks and MUST report a
capsule as valid only when every check passed. A check that cannot be
performed counts as failed. A checker SHOULD continue after a failure and
report every failure it can.

1. **Seal.** `noqtis.sig` is a regular file (not reached through a link)
   of at most 1 MiB, canonical JSON (§2), with exactly the members of §5
   and their types, `format` is `noqtis-seal-1`, `alg` is known (§5.1),
   `context` is `noqtis-capsule-1`, `public_key` and `signature` decode
   (§5.2) to the algorithm's sizes, and `manifest_sha256` is 64 lower-case
   hex digits.
2. **Manifest digest.** `noqtis.json` is a regular file of at most 512 MiB
   (checked before it is read, and again if it grows while being read),
   and its SHA-256 equals `manifest_sha256`.
3. **Key.** When the caller supplies a trusted public key, `public_key`
   MUST equal it byte for byte, and the signature MUST be verified with the
   trusted key. When no key is supplied, the checker uses `public_key` and
   MUST say in its report that the key was not pinned.
4. **Signature.** `signature` verifies (§5.1) over the exact bytes of
   `noqtis.json`.
5. **Timestamp.** When the caller supplies TSA trust anchors: `timestamp`
   MUST be present; its imprint MUST match (§5.3); the token's signature
   MUST verify under its signer certificate; and that certificate's path
   MUST lead to one of the anchors and be valid at the token's `genTime`.
   When the caller supplies no anchors and `timestamp` is present, the
   check MUST fail, because the timestamp cannot be checked.
6. **Manifest.** `noqtis.json` is canonical JSON with exactly the members of
   §3, `format` is `noqtis-capsule-1`, `created` is valid (§3.2), entries
   are sorted with no repeats (§3.3), and every path satisfies §4.
7. **Files.** For each entry: the path exists, is a regular file reached
   without following links, and has exactly `size` bytes, the SHA-256
   `sha256` and the SHA3-256 `sha3_256`.
8. **Completeness.** Every regular file under the capsule root (other than
   `noqtis.json` and `noqtis.sig` at its top) is listed; the folder holds
   no link, reparse point, special file or name §4 refuses; and no two
   listed paths differ only in ASCII case.

## 8. Limits

These bounds keep checking safe on hostile input. A checker MUST refuse
input over a limit with a failing check, and MUST NOT silently truncate.

| Item | Limit |
|---|---|
| `noqtis.json` | 512 MiB |
| `noqtis.sig` | 1 MiB |
| `meta` | 1 MiB of canonical text |
| files in one capsule | 2,000,000 |
| one path | 4096 bytes |
| folder depth below the root | 64 levels |
| JSON nesting | 64 levels |
| file size | 2^53 − 1 bytes |
| TSA trust anchors in one check | 32 |

## 9. Security considerations

- Without a trusted key (§7.3) a valid capsule proves only that its files
  are unchanged since someone sealed them. Checkers SHOULD obtain the
  signer's public key independently of the capsule.
- `created` is not evidence of time; a verified timestamp is.
- The pure signature is over the whole manifest, so a checker holds the
  manifest in memory while verifying it (about the manifest's size, plus
  about 100 bytes per file for the folder listing); the 512 MiB limit bounds
  this.
- Two independent digests per file mean that a second-preimage attack on
  one hash function alone does not let an attacker swap a file.
- Case-colliding and non-portable names are refused so that a capsule
  checks the same on every file system.
- In format 2 the signature covers the file list only through the Merkle
  root: a checker that skips §11.2 accepts any list of entries. A partial
  check (`--only`) or a proof shows the files it names and nothing about
  the others; the report says so.

## 10. Example

A manifest (one line in the file):

```json
{"created":"2026-10-28T23:35:26Z","files":[{"path":"data/in.csv","sha256":"5be08c9684a1d25efcee09318204824278b08bbfb4aef973ffefd0b9d7478313","sha3_256":"cec130ccd077888d742e367e7a57930c9c22115e294fb375b29343edc10479a1","size":4},{"path":"report.txt","sha256":"8e54b0ca18020275e4aef1ca0eb5e197e066c065c1864817652a8a39c55402cd","sha3_256":"cfd6402fe57231a13c50feb77a4d9e594287810bfa913618dad5076d1bbd01f5","size":2}],"format":"noqtis-capsule-1","meta":{"project":"demo"}}
```

Its seal, with the base64 shortened:

```json
{"alg":"ML-DSA-65","context":"noqtis-capsule-1","format":"noqtis-seal-1","manifest_sha256":"9f322e95960a45ea27b84f7d618c75402f8bce5cb250d157564ae16dbc6130f0","public_key":"1qWycP39...","signature":"..."}
```

The test suite of NOQTIS carries a complete sample capsule under
`tests/vectors/cap/sample`.

## 11. Format 2: Merkle manifests and inputs

A format 2 capsule (`noqtis seal --format 2`) lets a reader check some of
its files without seeing the others, and records the capsules it was made
from. Its manifest format is `noqtis-capsule-2` and its seal format
`noqtis-seal-2`.

### 11.1 The manifest

The format 1 manifest with these members after `format`, in canonical
order:

| Member | Value |
|---|---|
| `inputs` | optional: 1 to 1024 objects `{"capsule": <id>, "name": <string>}`; `capsule` is an input's id (§11.4), 64 lower-case hex digits; `name` 1 to 255 bytes of UTF-8 with no control character |
| `merkle` | `{"alg": "sha256", "leaves": <number of entries>, "root": <64 hex digits>}` |
| `meta` | optional, as in format 1 |

### 11.2 The tree

`root` is the Merkle Tree Hash of RFC 9162 §2.1.1 over the file entries,
in manifest order:

- a leaf is `SHA-256(0x00 || entry)`, where `entry` is the entry's
  canonical bytes exactly as they appear in the manifest;
- a node is `SHA-256(0x01 || left || right)`, the tree of n entries
  splitting at the largest power of two below n;
- the tree of no entries is `SHA-256("")`.

A checker MUST recompute the tree over the listed entries and fail
(`manifest.merkle`) unless it has the head's `root` and `leaves`.

### 11.3 The head and the seal

The **head** is the manifest with the member `"files":[...],` removed:
the bytes before `"files"` and the bytes after the comma that ends the
array. The seal signs the head, not the manifest: in place of
`manifest_sha256` it has `head_sha256`, the SHA-256 of the head, and its
`context` is `noqtis-capsule-2`. A checker makes every check of §7 over
the head where format 1 makes it over the manifest, then §11.2.

### 11.4 Ids and lineage

A capsule's **id** is the SHA-256 of the bytes its seal signs: the
manifest in format 1, the head in format 2 (`manifest_sha256` or
`head_sha256`, once the seal checks). `noqtis seal --input` records the id
of each input after checking it; `noqtis check --lineage <dir>` finds each
input among the folders given by its id and checks it in full, with its
own inputs, to 64 levels.

### 11.5 Proofs

A proof (`noqtis prove`) shows that some entries are in a format 2
capsule. It is canonical JSON:

```text
{"entries":[{"entry":E,"index":I,"path":[H,...]},...],
 "format":"noqtis-proof-1","head":HEAD,"seal":SEAL}
```

`seal` is the seal object and `head` the head as a JSON object. Each
`entry` is a file entry exactly as in the manifest, at position `index`
(from 0); `path` is its audit path (RFC 9162 §2.1.3.1), from the leaf up,
each node 64 lower-case hex digits. A checker MUST check the seal and its
signature over the canonical bytes of `head`, as for a capsule, then each
entry's path to the head's `root` for the tree size `leaves`, by RFC 9162
§2.1.3.2. The tree size is authenticated by the signed head, not by the
path. A proof holds no name, size or digest of the entries it does not
prove.

### 11.6 Example

The capsule of §10 sealed in format 2 (one line in the file):

```json
{"created":"2026-10-28T18:04:05Z","files":[{"path":"data/in.csv","sha256":"5be08c9684a1d25efcee09318204824278b08bbfb4aef973ffefd0b9d7478313","sha3_256":"cec130ccd077888d742e367e7a57930c9c22115e294fb375b29343edc10479a1","size":4},{"path":"report.txt","sha256":"8e54b0ca18020275e4aef1ca0eb5e197e066c065c1864817652a8a39c55402cd","sha3_256":"cfd6402fe57231a13c50feb77a4d9e594287810bfa913618dad5076d1bbd01f5","size":2}],"format":"noqtis-capsule-2","merkle":{"alg":"sha256","leaves":2,"root":"4f701b0322535eca8d47c46459225d0d20407af3f791630ae0642b857952e2b6"},"meta":{"project":"demo"}}
```

Its head is the same line without `"files":[...],`, and the seal
carries its SHA-256:

```json
{"alg":"ML-DSA-65","context":"noqtis-capsule-2","format":"noqtis-seal-2","head_sha256":"dbe89ba080d657b467a517ea72733826e8295309ea30ae553a8ef1b8a4ec7f0f","public_key":"WbxksFmm...","signature":"..."}
```

The proof of `report.txt` (index 1) has the one-node audit path
`["d8bd2987be160bc32ab8c239c37ad69a6e18abd2e1ddb801fa819178fe391c73"]`,
the leaf of `data/in.csv`.

## References

- RFC 8785, JSON Canonicalization Scheme (JCS).
- RFC 8259, The JavaScript Object Notation (JSON) Data Interchange Format.
- RFC 3339, Date and Time on the Internet: Timestamps.
- RFC 4648, The Base16, Base32, and Base64 Data Encodings.
- RFC 3161, Time-Stamp Protocol (TSP); RFC 5280, X.509 certificate paths.
- RFC 9162, Certificate Transparency Version 2.0 (§2.1, Merkle trees).
- FIPS 180-4 (SHA-2), FIPS 202 (SHA-3), FIPS 204 (ML-DSA), FIPS 205
  (SLH-DSA).
