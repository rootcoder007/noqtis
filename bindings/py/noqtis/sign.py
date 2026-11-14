# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Signatures: ML-DSA (FIPS 204), SLH-DSA (FIPS 205), Ed25519 (RFC 8032)
and the hybrids ML-DSA-44/65/87+Ed25519, which need both parts to verify.

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

__all__ = ["Signer", "Verifier", "keygen", "mu", "rndlen", "sign",
           "signmu", "verify", "verifymu"]


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
    SK.seed || SK.prf || PK.seed for SLH-DSA, 3n bytes; the 32-byte
    private key for Ed25519; xi || the Ed25519 key, 64 bytes, for a
    hybrid) the pair is the standard's deterministic one; without, it
    comes from the OS CSPRNG."""
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


# ---- ML-DSA with an external mu ----

def mu(alg: AlgLike, pk: Bytes, msg: Bytes, ctx: Bytes = b"",
       prehash: Optional[str] = None) -> bytes:
    """The 64-byte message representative mu of FIPS 204 for ``msg``
    under ``pk``, as ``sign`` computes it (ML-DSA only), so that the
    message can be hashed away from where the secret key is."""
    a = find(alg, "sign")
    return _c.smu(a.id, buf(pk, "pk"), buf(msg, "msg"), buf(ctx, "ctx"),
                  _ph(prehash))


def signmu(alg: AlgLike, sk: Bytes, mu: Bytes, deterministic: bool = False,
           rnd: Optional[Bytes] = None) -> bytes:
    """The signature of the message whose mu is ``mu`` (from ``mu``): the
    same bytes ``sign`` gives for that message with the same ``rnd``."""
    a = find(alg, "sign")
    if deterministic and rnd is not None:
        raise ArgError(-1, "deterministic and rnd exclude each other")
    r = bytes(32) if deterministic else opt(rnd, "rnd")
    return _c.signmu(a.id, buf(sk, "sk"), buf(mu, "mu"), r)


def verifymu(alg: AlgLike, pk: Bytes, mu: Bytes, sig: Bytes) -> bool:
    """True when ``sig`` verifies for the message whose mu is ``mu``."""
    a = find(alg, "sign")
    return _c.vrfymu(a.id, buf(pk, "pk"), buf(mu, "mu"),
                     buf(sig, "sig")) == 0


# ---- streaming ----

class Signer:
    """A signature over a message given in pieces: ``update`` (or
    ``write``, so ``shutil.copyfileobj(f, signer)`` works) any number of
    times, then ``finish``, which gives the bytes ``sign`` gives for the
    whole message with the same ``rnd``. Only the piece at hand is held;
    the secret key is the caller's object, used again at ``finish``.
    ML-DSA (pure and pre-hash), and HashSLH-DSA, Ed25519ph and the
    hybrids with ``prehash="SHA-512"``; the others raise
    UnsupportedError. One use: after ``finish`` it raises StateError."""

    __slots__ = ("_a", "_k", "_c")

    def __init__(self, alg: AlgLike, sk: Bytes, ctx: Bytes = b"",
                 prehash: Optional[str] = None) -> None:
        self._a = find(alg, "sign")
        self._k = buf(sk, "sk")
        self._c = _c.sini(self._a.id, self._k, buf(ctx, "ctx"), _ph(prehash),
                          False)

    def update(self, data: Bytes) -> None:
        _c.supd(self._c, buf(data, "data"))

    def write(self, data: Bytes) -> int:
        self.update(data)
        return len(data)

    def finish(self, deterministic: bool = False,
               rnd: Optional[Bytes] = None) -> bytes:
        if deterministic and rnd is not None:
            raise ArgError(-1, "deterministic and rnd exclude each other")
        r = bytes(rndlen(self._a)) if deterministic else opt(rnd, "rnd")
        return _c.sfin(self._c, self._a.id, self._k, r)


class Verifier:
    """``verify`` over a message given in pieces: ``update``/``write``,
    then ``finish(sig)``, True when it verifies. As ``Signer``."""

    __slots__ = ("_k", "_c")

    def __init__(self, alg: AlgLike, pk: Bytes, ctx: Bytes = b"",
                 prehash: Optional[str] = None) -> None:
        a = find(alg, "sign")
        self._k = buf(pk, "pk")
        self._c = _c.sini(a.id, self._k, buf(ctx, "ctx"), _ph(prehash), True)

    def update(self, data: Bytes) -> None:
        _c.supd(self._c, buf(data, "data"))

    def write(self, data: Bytes) -> int:
        self.update(data)
        return len(data)

    def finish(self, sig: Bytes) -> bool:
        return _c.vfin(self._c, self._k, buf(sig, "sig")) == 0
