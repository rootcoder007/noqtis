# noqtis for Python

Post-quantum signatures, key encapsulation, hashes and sealed file
capsules, from the [noqtis](https://github.com/rootcoder007/noqtis) C
library. The library is compiled into the package: no runtime
dependencies, and wheels for Linux (glibc and musl), macOS and Windows on
x86-64 and arm64, one abi3 wheel per platform for CPython 3.9 and later.

| Family | Algorithms | Standard |
|---|---|---|
| Signatures | ML-DSA-44/65/87 | FIPS 204 |
| | SLH-DSA-SHA2 and SLH-DSA-SHAKE, 128/192/256, s and f | FIPS 205 |
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
