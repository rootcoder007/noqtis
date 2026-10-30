# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Signatures: ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).

>>> from noqtis import sign
>>> pk, sk = sign.keygen("ML-DSA-65")
>>> sig = sign.sign("ML-DSA-65", sk, b"data")
>>> sign.verify("ML-DSA-65", pk, b"data", sig)
True
"""
from typing import Optional, Tuple

from . import _noqtis as _c
from ._alg import AlgLike, Bytes, buf, find, hid, opt
from ._err import ArgError, DecodeError

__all__ = ["keygen", "rndlen", "sign", "verify"]


def rndlen(alg: AlgLike) -> int:
    """Bytes of per-signature randomness: 32 for ML-DSA and the hybrids
    (ML-DSA-65+Ed25519, ...), n for SLH-DSA, 0 for Ed25519."""
    a = find(alg, "sign")
    if a.name == "Ed25519":
        return 0
    return 32 if a.name.startswith("ML-DSA") else a.pk // 2


def _ph(prehash: Optional[str]) -> int:
    return 0 if prehash is None else hid(prehash)


def keygen(alg: AlgLike, seed: Optional[Bytes] = None) -> Tuple[bytes, bytes]:
    """A new key pair (pk, sk). With ``seed`` (xi for ML-DSA, 32 bytes;
    SK.seed || SK.prf || PK.seed for SLH-DSA, 3n bytes) the pair is the
    standard's deterministic one; without, it comes from the OS CSPRNG."""
    a = find(alg, "sign")
    return _c.skg(a.id, opt(seed, "seed"))


def sign(alg: AlgLike, sk: Bytes, msg: Bytes, ctx: Bytes = b"",
         deterministic: bool = False, prehash: Optional[str] = None,
         rnd: Optional[Bytes] = None) -> bytes:
    """The signature of ``msg``. ``ctx`` is the context string (at most
    255 bytes). ``deterministic`` uses all-zero randomness (the standard's
    deterministic variant); ``rnd`` gives the randomness explicitly.
    ``prehash`` names a hash ('SHA-512', 'SHAKE256', ...) for HashML-DSA /
    HashSLH-DSA: ``msg`` is still the message, hashed here."""
    a = find(alg, "sign")
    if deterministic and rnd is not None:
        raise ArgError(-1, "deterministic and rnd exclude each other")
    r = opt(rnd, "rnd")
    if deterministic:
        r = bytes(rndlen(a))
    return _c.sign(a.id, buf(sk, "sk"), buf(msg, "msg"), buf(ctx, "ctx"),
                   _ph(prehash), r)


def verify(alg: AlgLike, pk: Bytes, msg: Bytes, sig: Bytes, ctx: Bytes = b"",
           prehash: Optional[str] = None) -> bool:
    """True when ``sig`` is a valid signature of ``msg`` under ``pk``;
    False for any invalid or malformed signature. A public key of the
    wrong size raises DecodeError; a context over 255 bytes, ArgError."""
    a = find(alg, "sign")
    p = buf(pk, "pk")
    if len(p) != a.pk:
        raise DecodeError(-4, "%s public keys are %d bytes, not %d"
                          % (a.name, a.pk, len(p)))
    rc = _c.vrfy(a.id, p, buf(msg, "msg"), buf(ctx, "ctx"), _ph(prehash),
                 buf(sig, "sig"))
    return rc == 0
