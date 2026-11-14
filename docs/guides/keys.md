# Keys and key files

## Choosing an algorithm

```sh
$ noqtis algs
algorithm              type      pk      sk  sig/ct   ss
ML-DSA-44              sig     1312    2560    2420    -
ML-DSA-65              sig     1952    4032    3309    -
ML-DSA-87              sig     2592    4896    4627    -
SLH-DSA-SHA2-128s      sig       32      64    7856    -
...
```

- **ML-DSA-65** (FIPS 204, lattice-based): small, fast, the default choice.
  ML-DSA-44 and ML-DSA-87 trade size for security level (NIST categories
  2, 3, 5).
- **SLH-DSA** (FIPS 205, hash-based): its security rests only on the hash
  function, a conservative choice for records that must last decades. The
  `s` sets have smaller signatures and slow signing; the `f` sets sign
  faster with larger signatures. SHA2 and SHAKE variants differ only in the
  hash inside.
- **ML-DSA-65+Ed25519** (and the 44 and 87 hybrids): an ML-DSA signature
  and a classical Ed25519 signature at once, both required to verify. For
  places that must still show a classical signature during the move to
  post-quantum ones, or that want a second, independent assumption.
- **Ed25519** alone is classical (RFC 8032), for interoperating with tools
  that expect it; `noqtis seal` refuses it, since quantum computers will
  break it.
- **ML-KEM** (FIPS 203) and **HQC** (experimental: its NIST standard is
  not final, and the final encoding may differ) are key encapsulation mechanisms, for
  [enc](https://noqtis.dev/reference/man/noqtis-enc-1/) and
  [dec](https://noqtis.dev/reference/man/noqtis-dec-1/); they cannot sign or seal.

Names are case-insensitive on the command line.

## Making keys

```sh
$ noqtis keygen -a ML-DSA-65 -o me
ML-DSA-65 key pair: me (secret), me.pub (public)
```

The secret key file is created with mode 0600 (owner only) on POSIX
systems, exclusively and without following links; on Windows it takes the
folder's permissions, so keep it in a private folder. `keygen` never
overwrites a file unless given `--force`, which removes the old file first.

## The key file format

A key file is text: one header line, then the key bytes in the standard's
own encoding as padded base64 (RFC 4648) in lines of 64 characters.

```text
noqtis-key-1 ML-DSA-65 pub
aUkpZEKpknBmeJ3AZALNm/fBJWRLYPuawV199DHjRFfjbRKpKyfIa8RsONsUi9zm
...
```

The header is exactly three fields separated by single spaces: the magic
`noqtis-key-1`, the algorithm name as `noqtis algs` prints it, and `pub` or
`sec`. Readers accept `\n` or `\r\n` line ends and reject anything else:
another character, non-canonical padding, the wrong kind of key (`pub`
where a secret key is needed or the reverse), or a key whose length is not
the algorithm's. The base64 decoder runs in constant time, so reading a
secret key leaks nothing through timing.

Because the bytes are the standard's encoding, a public key (after
base64-decoding the body) and NOQTIS's raw signatures can be checked by any
conforming FIPS 204/205 implementation; the ML-DSA module is cross-checked
against OpenSSL 3.5.

## Key files from Python, JavaScript and R

The bindings read and write the same files, as strictly as the command
line does, so a key made with `noqtis keygen` works everywhere:

```python
from noqtis import keyfile
k = keyfile.read("me", "sec")         # Key(alg, kind, key)
keyfile.write("me2.pub", k.alg, "pub", public_key_bytes)
```

```js
import { keyfile } from 'noqtis';
const { alg, kind, key } = keyfile.decode(fs.readFileSync('me.pub', 'utf8'));
```

```r
k <- nqreadkey("me")                  # list(alg, kind, key)
nqwritekey("me2.pub", pk, k$alg, "pub")
```

Written secret key files are owner-only, and no binding replaces an
existing file unless asked to (`force=True`, `force = TRUE`). See the
[Python](https://noqtis.dev/reference/api/python/),
[JavaScript](https://noqtis.dev/reference/api/javascript/) and
[R](https://noqtis.dev/reference/api/r/) API references.

## Deterministic keys

`--seed` derives the key pair from the standard's seed, the way the NIST
test vectors do: 32 bytes for ML-DSA, 3n bytes for SLH-DSA (48, 72 or 96),
64 for ML-KEM, 32 for HQC. Give hex digits, or the name of a file holding
the raw bytes.

```sh
$ noqtis keygen -a ml-dsa-44 -o det --seed \
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
ML-DSA-44 key pair: det (secret), det.pub (public)
```

The seed **is** the secret key: anyone who has it can derive the key.
A seed on the command line also lands in shell history and process
listings; prefer a seed file.

## Keys under a passphrase

`--pass-fd <n>` or `--pass-env <name>` keeps a secret key under a
passphrase:

```sh
$ noqtis keygen -a ML-DSA-65 -o me --pass-fd 3 3<pass.txt
ML-DSA-65 key pair: me (secret, under the passphrase), me.pub (public)
$ NQPASS=$(cat pass.txt) noqtis sign -k me --pass-env NQPASS report.pdf
```

The passphrase is read from the open descriptor `<n>` up to a newline,
or taken from the environment variable whose name the option gives; it
is never an argument (other users can read the process list), never
echoed, and at most 4096 bytes. `noqtis sign` and `noqtis dec` take the
same options; the other commands that read a secret key refuse a
protected one and say so.

The file keeps the first line of an unprotected secret key
(`noqtis-key-1 <alg> sec`); its base64 body is the format
noqtis-pwkey-1 (`nqpwenc(3)`): `NQPW`, the version, Argon2id and
ChaCha20-Poly1305 as one byte each, the memory, passes and lanes, a
random 16-byte salt, then the key under ChaCha20-Poly1305 and its tag.
Argon2id of the passphrase gives the cipher's key and nonce (64 MiB, 3
passes and 4 lanes when it is written); the header and the first line
are its associated data, so changing either fails like a wrong
passphrase. A reader refuses parameters outside 8 MiB to 1 GiB of
memory, 1 to 16 passes and 1 to 16 lanes, or memory times passes over
4 GiB, before it derives anything: a file cannot make it take more.

## Keeping the secret key safe

- Keep it off shared machines and out of repositories; in CI, store it as
  an encrypted secret (see [CI](https://noqtis.dev/guides/ci/)).
- Publish the `.pub` file widely and in more than one place, so others can
  pin it.
- There is no revocation in the capsule format: if a secret key leaks,
  announce it where you published the public key, make a new key and
  reseal what matters. A [timestamp](https://noqtis.dev/guides/timestamps/) shows
  which seals predate the leak.
