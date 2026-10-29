# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Key encapsulation: ML-KEM (FIPS 203) and HQC.

>>> from noqtis import kem
>>> pk, sk = kem.keygen("ML-KEM-768")
>>> ct, ss = kem.encap("ML-KEM-768", pk)
>>> kem.decap("ML-KEM-768", sk, ct) == ss
True
"""
from typing import Optional, Tuple

from . import _noqtis as _c
from ._alg import AlgLike, Bytes, buf, find, opt

__all__ = ["decap", "encap", "keygen"]


def keygen(alg: AlgLike, seed: Optional[Bytes] = None) -> Tuple[bytes, bytes]:
    """A new key pair (pk, sk); with ``seed`` (d || z for ML-KEM) the
    standard's deterministic one."""
    a = find(alg, "kem")
    return _c.kkg(a.id, opt(seed, "seed"))


def encap(alg: AlgLike, pk: Bytes,
          seed: Optional[Bytes] = None) -> Tuple[bytes, bytes]:
    """(ciphertext, shared secret) for ``pk``; ``seed`` (m for ML-KEM)
    makes it deterministic, for test vectors."""
    a = find(alg, "kem")
    return _c.enc(a.id, buf(pk, "pk"), opt(seed, "seed"))


def decap(alg: AlgLike, sk: Bytes, ct: Bytes) -> bytes:
    """The shared secret in ``ct``. A tampered ciphertext gives an
    unrelated pseudorandom secret, not an error (implicit rejection); only
    a ciphertext or key of the wrong size raises."""
    a = find(alg, "kem")
    return _c.dec(a.id, buf(sk, "sk"), buf(ct, "ct"))
