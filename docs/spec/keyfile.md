# Key files and the secret-key container, version 2

This document specifies the key files `noqtis keygen` writes and the
bindings read, and the version 2 container of a signature secret key,
which carries an integrity value checked every time the key signs.

## 1. Key files

A key file is UTF-8 text: a first line, a newline, then the key in
base64 (RFC 4648, standard alphabet, padded), which may be broken into
lines of at most 64 characters.

```text
noqtis-key-1 <alg> pub        a public key, of any algorithm
noqtis-key-1 <alg> sec        a secret key: a KEM key, or a signature
                              key written before 0.3.0 (version 1)
noqtis-key-2 <alg> sec        a signature secret key in the version 2
                              container (section 2)
```

`<alg>` is the algorithm's name as `noqtis algs` lists it. The body of a
secret key is either the key itself or, when it is under a passphrase,
the format noqtis-pwkey-1 (`nqpwenc(3)`) whose plaintext is the key and
whose associated data is the first line. For a version 2 file "the key"
is the whole container X of section 2, so under a passphrase the
integrity value is inside the AEAD with the rest.

## 2. The version 2 container

For a signature algorithm with standard secret key S (FIPS 204, FIPS 205,
RFC 8032, or for a hybrid the ML-DSA key followed by the 32-byte Ed25519
seed), the container is

```text
X = S || P || T
P = the Ed25519 public key (32 bytes) for Ed25519 and for a hybrid;
    empty for ML-DSA and SLH-DSA
T = SHA3-256("noqtis-sk-2" || 0x00 || alg || 0x00 || S || P)
```

with `alg` the algorithm's name as ASCII. Its length is the length of S
plus 32 (ML-DSA, SLH-DSA) or plus 64 (Ed25519, hybrids); `nqsxsz` gives
it. `nqsxmk` makes X from S (it derives P), and `nqsxchk` checks one.

### 2.1 What T is for, and what it reveals

T detects a change to any byte of the stored key: S (including fields
that only feed the signer's randomness: ML-DSA's K, SLH-DSA's SK.prf, the
Ed25519 seed's prefix half), P, or T itself. A change of one bit leaves
T equal with probability 2^-256 when SHA3-256 is taken as a random
function. It is not a MAC and needs no key: it guards against faults,
not against an attacker who can write the file, who could as well
replace the whole key.

T is a deterministic function of S and P, which are stored beside it, so
it says nothing that the key itself does not: whoever can read T can read
S. Under a passphrase T is encrypted with S. A T seen apart from its key
(say, in a log) would let someone confirm a guess of the whole key, which
is a 256-bit or larger random value and cannot be guessed. The domain
string and the algorithm name keep T apart from every other hash noqtis
computes and bind it to one algorithm.

P is public, and stored only so that the signer can compare it with the
public key it derives from the seed: a changed seed is then caught twice,
by T and by the comparison.

### 2.2 When it is checked

`nqsign`, `nqsignd`, `nqsignmu` and the streaming signer (`nqsfin`) take
either S (version 1: no integrity check) or X. With X they sign with S as
before and then, after the signature is made and before it is released,
compute T again from the key in memory and compare it with the stored T,
and for Ed25519 and the hybrids derive the public key from the seed
again and compare it with P. Each comparison leaves a verdict word that
holds a fixed tag only when it held, and the signature leaves only
through the mask those verdicts make (`nqrel`, two passes): as for the
signers' own checks, no single skipped instruction releases it. The
check runs after signing, so a change to the key in memory while it
signs is caught too, not only one made in storage. Loading a key file
also checks it (`nqsxchk`) and refuses a damaged one.

With S alone (a version 1 key) signing behaves as before: the signers'
checks catch every stored-key fault except in the fields not tied to the
public key, which give a valid signature (docs/security.md). `nqsxchk`
returns `NQENOSUP` for a key of version 1's length, which is how a
caller learns that a key has no integrity value; the command-line tool
says so in a `note:` and `noqtis passwd` rewrites the file as version 2.

### 2.3 What carries it, and what does not

- The C API: raw keys of either length; nothing changes for a caller that
  passes S. Key generation (`nqskg`, `nqskgd`) still gives S; `nqsxmk`
  makes X.
- Key files: `noqtis keygen` and `noqtis passwd` write version 2 for
  signature keys; every reader takes both versions. noqtis before 0.3.0
  refuses a `noqtis-key-2` file as "not a noqtis key file".
- KEM secret keys stay `noqtis-key-1`: decapsulation releases a shared
  secret, not a signature, and its fault behaviour is implicit rejection.
- PKCS #11 tokens: the token holds and uses the key; noqtis never sees
  it, so there is nothing to carry. Not applicable.
- OpenPGP and CMS secret keys use their own formats; noqtis has no
  PKCS #8 import or export. T is noqtis's own and is not part of any
  standard encoding: an exported standard key is S, and an imported one
  becomes X through `nqsxmk`.
- The key store holds public keys only.
- Bindings: each reads and writes both versions and exposes `nqsxmk`,
  `nqsxchk` and `nqsxsz`.

### 2.4 Known answers

`tests/vectors/skx/kat.txt` gives X for fixed keys of each algorithm
(the Ed25519 key of RFC 8032 section 7.1 test 1, ML-DSA and SLH-DSA keys
from fixed seeds), computed from this section with Python's `hashlib`.
