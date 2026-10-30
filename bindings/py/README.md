# noqtis for Python <img src="https://raw.githubusercontent.com/rootcoder007/noqtis/main/docs/logo/noqtis-hex-512.png" align="right" height="139" alt="NOQTIS hex logo" />

Post-quantum signatures, key encapsulation, hashes and sealed file
capsules, from the [noqtis](https://github.com/rootcoder007/noqtis) C
library. The library is compiled into the package: no runtime
dependencies, and wheels for Linux (glibc and musl), macOS and Windows on
x86-64 and arm64, one abi3 wheel per platform for CPython 3.9 and later.

| Family | Algorithms | Standard |
|---|---|---|
| Signatures | ML-DSA-44/65/87 | FIPS 204 |
| | SLH-DSA-SHA2 and SLH-DSA-SHAKE, 128/192/256, s and f | FIPS 205 |
| | Ed25519; hybrids ML-DSA-44/65/87+Ed25519 (both parts must verify) | RFC 8032 |
| KEMs | ML-KEM-512/768/1024 | FIPS 203 |
| | HQC-128/192/256 | HQC round 4 |
| Hashes | SHA-224 ... SHA-512/256, SHA3-224 ... SHA3-512, SHAKE128/256, HMAC | FIPS 180-4, FIPS 202 |

```sh
pip install noqtis      # or: uv add noqtis
```

## Signatures

```python
from noqtis import sign

pk, sk = sign.keygen("ML-DSA-65")
sig = sign.sign("ML-DSA-65", sk, b"message", ctx=b"app-v1")
assert sign.verify("ML-DSA-65", pk, b"message", sig, ctx=b"app-v1")
```

- `keygen(alg, seed=None)` returns `(pk, sk)`; a seed gives the
  standard's deterministic key pair.
- `sign(alg, sk, msg, ctx=b"", deterministic=False, prehash=None)`:
  `prehash="SHA-512"` (or any name from `noqtis.hashes()`) selects
  HashML-DSA / HashSLH-DSA; `msg` is still the message.
- `verify(...)` returns `True` or `False`; it never raises for a bad or
  malformed signature.

## Key encapsulation

```python
from noqtis import kem

pk, sk = kem.keygen("ML-KEM-768")
ct, ss = kem.encap("ML-KEM-768", pk)
assert kem.decap("ML-KEM-768", sk, ct) == ss
```

A tampered ciphertext decapsulates to an unrelated secret rather than an
error (implicit rejection, as FIPS 203 requires).

## Hashes

```python
import noqtis

noqtis.hash("SHA3-256", b"abc")
noqtis.hash("SHAKE256", b"abc", 100)   # 100 bytes of output
noqtis.hmac("SHA-256", b"key", b"data")
```

## Capsules

A capsule is a folder sealed with a manifest of every file in it
(`noqtis.json`) and a post-quantum signature over it (`noqtis.sig`).

```python
import noqtis

pk, sk = noqtis.sign.keygen("ML-DSA-65")
noqtis.seal("results/", sk, pk, meta={"project": "survey-2026"})

report = noqtis.check("results/", pk)
print(report.ok)            # True only if every check passed
for row in report.rows:     # (check, ok, detail)
    print(row)
```

Without `pk`, `check` trusts the key inside the seal and its report says
so. `anchors=[der, ...]` requires an RFC 3161 timestamp under one of the
given TSA certificates.

### Format 2, proofs and lineage

`seal(..., format=2)` adds a Merkle tree over the files to the manifest
and signs its head. `prove` then shows some files to a reader without
the names or digests of the others:

```python
noqtis.seal("results/", sk, pk, format=2)
proof = noqtis.prove("results/", ["tables/t1.csv"])    # bytes (JSON)
noqtis.check(proof=proof, pk=pk).ok                    # the proof alone
noqtis.check("results/", pk, proof=proof).ok           # and the files
```

`seal(..., inputs=["raw/", ("cleaned", "clean/")])` records the capsules
this one was made from, by id (`noqtis.capid(dir)`, 32 bytes);
`check(dir, pk, lineage=["raw/", "clean/"])` finds each input among those
folders and checks it, to 64 levels. `check(dir, pk, only=["a.csv"])`
checks just those files (a "partial" row says so). `noqtis.files(dir)`
lists what the manifest holds, `File(path, size, sha256)`, with nothing
checked.

### Key statements

```python
st = noqtis.rotate(old_sk, old_pk, new_sk, new_pk, reason="yearly")
noqtis.check("results/", old_pk, keys=[st]).ok   # sealed by the new key
rv = noqtis.revoke(old_sk, old_pk, at=1767225600)
```

A statement (bytes, or a file path) needs `pk`, the trusted key. With
it, `check` accepts a seal by a key the trusted key was rotated to, and
requires a verified timestamp from before a seal key was rotated away or
revoked. Ed25519 alone cannot make statements.

## DSSE envelopes

```python
from noqtis import dsse

env = dsse.sign("ML-DSA-65", sk, pk, "application/vnd.in-toto+json", stmt)
dsse.verify("ML-DSA-65", pk, env)   # Signed(type, payload), or None
```

The envelope (in-toto and SLSA's signing wrapper) is canonical JSON with
one signature over the pre-authentication encoding; its keyid is the hex
SHA-256 of `pk`. `verify` returns `None` when no signature verifies and
raises `DecodeError` for text that is not an envelope.

## Key files

`noqtis.keyfile` reads and writes the text key files `noqtis keygen`
makes (`noqtis-key-1 <alg> <pub|sec>`, then base64), as strictly as the
command-line tool reads them:

```python
from noqtis import keyfile

k = keyfile.read("me", "sec")      # Key(alg, kind, key); "me.pub" for pub
noqtis.sign.sign(k.alg, k.key, b"a message")

pk, sk = noqtis.sign.keygen("ML-DSA-65")
keyfile.write("you", "ML-DSA-65", "sec", sk)      # owner-only, no overwrite
keyfile.write("you.pub", "ML-DSA-65", "pub", pk)
text = keyfile.encode("ML-DSA-65", "pub", pk)     # the same text, as a str
assert keyfile.decode(text).key == pk
```

`write` never replaces a file unless `force=True`. Python's base64 is not
constant time: decode secret key files where timing is not observable.

## Errors

Every failure raises a subclass of `noqtis.NoqtisError`, one per library
error code: `ArgError`, `BufError`, `VerifyError`, `DecodeError`,
`RandError`, `MemError`, `FileError`, `UnsupportedError`, `LimitError`,
`StateError`. Each has `.code`, the library's `NQE*` value.

## Notes

- Inputs may be `bytes`, `bytearray` or `memoryview`; outputs are `bytes`.
  Python cannot wipe `bytes`, so secret keys and shared secrets you hold
  in Python live until the garbage collector frees them.
- Long operations release the GIL, so threads sign and verify in parallel.
- The package is typed (`py.typed`).

Licensed under Apache-2.0 WITH LLVM-exception.
