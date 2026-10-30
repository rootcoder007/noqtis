---
title: Use from Python
description: The noqtis Python package - seal and check a folder, sign and verify, encapsulate and hash, with the C library compiled in.
---

The `noqtis` Python package has the C library compiled into it: no
runtime dependencies, one wheel per platform for CPython 3.9 and later.

```sh
pip install noqtis      # or: uv add noqtis
```

## Seal, check, sign

Save this as `prov.py` and run `python prov.py`:

```python
import pathlib
import tempfile

import noqtis
from noqtis import kem, sign

# a folder with some results
d = pathlib.Path(tempfile.mkdtemp()) / "results"
(d / "data").mkdir(parents=True)
(d / "data" / "in.csv").write_text("a,b\n1,2\n")
(d / "report.txt").write_text("r\n")

# seal it, then check it with the public key pinned
pk, sk = sign.keygen("ML-DSA-65")
noqtis.seal(d, sk, pk, meta={"project": "tutorial"})
report = noqtis.check(d, pk)
print("check:", report.ok, len(report), "checks")

# change a file: the check fails and says why
with open(d / "report.txt", "a") as f:
    f.write("edited\n")
report = noqtis.check(d, pk)
print("after edit:", report.ok)
for row in report.failed:
    print("FAIL", row.check, row.detail)

# a detached signature with a context string
sig = sign.sign("ML-DSA-65", sk, b"the results in table 2", ctx=b"app-v1")
print("verify:", sign.verify("ML-DSA-65", pk, b"the results in table 2",
                             sig, ctx=b"app-v1"))
print("other context:", sign.verify("ML-DSA-65", pk,
                                    b"the results in table 2", sig))

# key encapsulation and hashes
kpk, ksk = kem.keygen("ML-KEM-768")
ct, ss = kem.encap("ML-KEM-768", kpk)
print("decap matches:", kem.decap("ML-KEM-768", ksk, ct) == ss)
print("sha3-256:", noqtis.hash("SHA3-256", b"abc").hex())
```

It prints:

```text
check: True 22 checks
after edit: False
FAIL file report.txt: size differs
verify: True
other context: False
decap matches: True
sha3-256: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
```

- `noqtis.seal(dir, sk, pk, meta=...)` writes `noqtis.json` and
  `noqtis.sig` into the folder; `meta` is any JSON-serialisable object,
  signed with the manifest and never interpreted.
- `noqtis.check(dir, pk)` returns a `Report`: `ok` is `True` only when
  every check passed, `rows` lists every `(check, ok, detail)`, and
  `failed` the rows that did not pass. Without `pk` it accepts the key in
  the seal, and its report says so.
- `sign.verify` returns `True` or `False` and never raises for a bad
  signature. A context string (`ctx`) binds a signature to one use.
- Every other failure raises a subclass of `noqtis.NoqtisError`
  (`ArgError`, `FileError`, `UnsupportedError`, ...) with the library's
  code in `.code`.

## Notes

- Inputs may be `bytes`, `bytearray` or `memoryview`; outputs are `bytes`.
  Python cannot wipe `bytes`, so a secret key you hold in Python lives
  until the garbage collector frees it. Keep long-term keys in key files
  made by `noqtis keygen` and seal from a short-lived process;
  `noqtis.keyfile.read("me", "sec")` loads one.
- Long operations release the GIL, so threads sign and verify in
  parallel.
- The package is typed (`py.typed`).

The full API is in the package's
[README](https://github.com/rootcoder007/noqtis/tree/main/bindings/py#readme).
