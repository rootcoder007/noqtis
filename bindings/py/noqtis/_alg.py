# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Algorithm tables and the argument helpers the modules share."""
import os
from typing import Dict, List, NamedTuple, Optional, Union

from . import _noqtis as _c
from ._err import ERRS, NoqtisError, UnsupportedError

_c.setup({**ERRS, 0: NoqtisError})

Bytes = Union[bytes, bytearray, memoryview]


class Alg(NamedTuple):
    """One algorithm and its sizes in bytes (None where they do not
    apply: ``sig`` for a KEM, ``ct`` and ``ss`` for a signature)."""

    name: str
    kind: str  # "sign" or "kem"
    id: int
    pk: int
    sk: int
    sig: Optional[int]
    ct: Optional[int]
    ss: Optional[int]


SIGS: List[Alg] = [Alg(n, "sign", i, p, s, g, None, None)
                   for i, n, p, s, g in _c.salgs()]
KEMS: List[Alg] = [Alg(n, "kem", i, p, s, None, c, x)
                   for i, n, p, s, c, x in _c.kalgs()]
_BYNAME: Dict[str, Alg] = {a.name.lower(): a for a in SIGS + KEMS}

AlgLike = Union[str, Alg]


def find(alg: AlgLike, kind: str) -> Alg:
    """The Alg for a name (any case) or an Alg, of the given kind."""
    if isinstance(alg, Alg):
        a: Optional[Alg] = alg
    elif isinstance(alg, str):
        a = _BYNAME.get(alg.lower())
    else:
        raise TypeError("alg: a name such as 'ML-DSA-65', or an Alg")
    if a is None:
        raise UnsupportedError(-8, "unknown algorithm %r" % (alg,))
    if a.kind != kind:
        what = "signature" if kind == "sign" else "KEM"
        raise UnsupportedError(-8, "%s is not a %s algorithm" % (a.name, what))
    return a


# nqhalg: the names noqtis uses, and the spellings hashlib and the CLI use
_HNAMES = ["SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224",
           "SHA-512/256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
           "SHAKE128", "SHAKE256"]
HASHES: Dict[str, int] = {n: i + 1 for i, n in enumerate(_HNAMES)}
_HKEY = {n.replace("-", "").replace("/", "").replace("_", "").lower(): i
         for n, i in HASHES.items()}


def hid(name: str) -> int:
    """The nqhalg for a hash name: 'SHA-256', 'sha256', 'sha3_256',
    'shake_128', 'sha512-224', ..."""
    if not isinstance(name, str):
        raise TypeError("hash: a name such as 'SHA-256'")
    k = name.replace("-", "").replace("/", "").replace("_", "").lower()
    i = _HKEY.get(k)
    if i is None:
        raise UnsupportedError(-8, "unknown hash %r" % (name,))
    return i


def isshake(i: int) -> bool:
    return i >= HASHES["SHAKE128"]


def buf(x: Bytes, what: str) -> bytes:
    """bytes for a bytes-like argument (bytearray and memoryview copied)."""
    if isinstance(x, bytes):
        return x
    if isinstance(x, (bytearray, memoryview)):
        return bytes(x)
    raise TypeError("%s: bytes, bytearray or memoryview, not %s"
                    % (what, type(x).__name__))


def opt(x: Optional[Bytes], what: str) -> Optional[bytes]:
    return None if x is None else buf(x, what)


def path(d: "Union[str, bytes, os.PathLike[str], os.PathLike[bytes]]"
         ) -> bytes:
    """A folder as the bytes the library takes (UTF-8 on Windows)."""
    return os.fsencode(os.fspath(d))
