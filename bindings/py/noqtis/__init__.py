# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""noqtis: post-quantum signatures, KEMs, hashes and sealed capsules.

Python binding of the noqtis C library (FIPS 203, 204, 205, 202, 180-4
and HQC), compiled into the package; no runtime dependencies.

>>> import noqtis
>>> pk, sk = noqtis.sign.keygen("ML-DSA-44")
>>> noqtis.seal("results", sk, pk, meta={"project": "x"})  # doctest: +SKIP
>>> noqtis.check("results", pk).ok  # doctest: +SKIP
True
"""
import json
from typing import Any, Iterable, Iterator, List, Mapping, NamedTuple, Optional, Union

from . import _noqtis as _c
from . import kem, keyfile, sign
from ._alg import HASHES, KEMS, SIGS, Alg, AlgLike, Bytes, buf, find, hid, isshake, path
from ._err import (
    ArgError,
    BufError,
    DecodeError,
    FileError,
    LimitError,
    MemError,
    NoqtisError,
    RandError,
    StateError,
    UnsupportedError,
    VerifyError,
)

__version__: str = _c.version()

__all__ = [
    "Alg",
    "ArgError",
    "BufError",
    "DecodeError",
    "FileError",
    "LimitError",
    "MemError",
    "NoqtisError",
    "RandError",
    "Report",
    "Row",
    "StateError",
    "UnsupportedError",
    "VerifyError",
    "__version__",
    "algs",
    "check",
    "hash",
    "hashes",
    "hmac",
    "kem",
    "keyfile",
    "seal",
    "sign",
]


def algs(kind: Optional[str] = None) -> List[Alg]:
    """Every algorithm with its sizes; ``kind`` 'sign' or 'kem' filters."""
    if kind not in (None, "sign", "kem"):
        raise ArgError(-1, "kind: None, 'sign' or 'kem'")
    out = SIGS + KEMS
    return [a for a in out if kind is None or a.kind == kind]


def hashes() -> List[str]:
    """The hash names ``hash``, ``hmac`` and ``prehash=`` take."""
    return list(HASHES)


def hash(alg: str, data: Bytes, n: Optional[int] = None) -> bytes:
    """The digest of ``data``. ``alg`` is 'SHA-256', 'SHA3-512',
    'SHAKE128', ... (hashlib spellings such as 'sha3_256' work too). ``n``
    is the output length for SHAKE (default 32 for SHAKE128, 64 for
    SHAKE256); other hashes have a fixed length and take no ``n``."""
    i = hid(alg)
    d = _c.hlen(i)
    if n is not None:
        if not isshake(i):
            raise ArgError(-1, "%s has a fixed length; n is for SHAKE" % alg)
        if not isinstance(n, int) or n < 0:
            raise ArgError(-1, "n: a length in bytes")
        d = n
    return _c.hash(i, buf(data, "data"), d)


def hmac(alg: str, key: Bytes, data: Bytes) -> bytes:
    """HMAC of ``data`` under ``key`` with a SHA-2 or SHA-3 hash."""
    i = hid(alg)
    return _c.hmac(i, buf(key, "key"), buf(data, "data"), _c.hlen(i))


class Row(NamedTuple):
    """One check of a capsule: its name, whether it passed, and why."""

    check: str
    ok: bool
    detail: str


class Report:
    """What ``check`` found: ``rows`` lists every check; ``ok`` is True
    only when the library passed the capsule as a whole."""

    __slots__ = ("rows", "code")

    def __init__(self, code: int, rows: Iterable[Row]) -> None:
        self.code = code
        self.rows: List[Row] = list(rows)

    @property
    def ok(self) -> bool:
        return self.code == 0 and all(r.ok for r in self.rows)

    @property
    def failed(self) -> List[Row]:
        """The rows that did not pass."""
        return [r for r in self.rows if not r.ok]

    def __bool__(self) -> bool:
        return self.ok

    def __iter__(self) -> Iterator[Row]:
        return iter(self.rows)

    def __len__(self) -> int:
        return len(self.rows)

    def __repr__(self) -> str:
        return "<noqtis.Report ok=%s rows=%d failed=%d>" % (
            self.ok, len(self.rows), len(self.failed))

    def __str__(self) -> str:
        return "\n".join("%-4s %s: %s" % ("ok" if r.ok else "FAIL", r.check,
                                         r.detail) for r in self.rows)


PathLike = Any  # str, bytes or os.PathLike


def _salg(sk: bytes, pk: bytes) -> Alg:
    """The signature algorithm a key pair belongs to. SLH-DSA with SHA-2
    and with SHAKE have the same sizes: the pair decides, as the one whose
    key generation from sk's seeds gives pk."""
    c = [a for a in SIGS if a.pk == len(pk) and a.sk == len(sk)]
    if len(c) == 1:
        return c[0]
    for a in c:
        n = a.pk // 2
        if _c.skg(a.id, sk[:3 * n])[0] == pk:
            return a
    raise ArgError(-1, "sk and pk are not a key pair noqtis knows; "
                   "pass alg=")


def seal(dir: PathLike, sk: Bytes, pk: Bytes,
         meta: Union[None, str, Mapping[str, Any]] = None,
         alg: Optional[AlgLike] = None) -> None:
    """Writes noqtis.json and noqtis.sig into ``dir``, covering every
    regular file in it. ``meta`` is a JSON object (a dict, or its text).
    ``alg`` defaults to the algorithm of the key pair. The creation time
    is SOURCE_DATE_EPOCH when set, else the clock."""
    s, p = buf(sk, "sk"), buf(pk, "pk")
    a = _salg(s, p) if alg is None else find(alg, "sign")
    m: Optional[str]
    if meta is None or isinstance(meta, str):
        m = meta
    elif isinstance(meta, Mapping):
        m = json.dumps(dict(meta), allow_nan=False, separators=(",", ":"))
    else:
        raise TypeError("meta: a dict, a JSON string or None")
    _c.seal(path(dir), a.id, s, p, m)


def check(dir: PathLike, pk: Optional[Bytes] = None,
          anchors: Optional[Iterable[Bytes]] = None) -> Report:
    """Checks ``dir`` against its seal. With ``pk`` the seal must be by
    that key; without, the key in the seal is trusted (a row says so).
    ``anchors`` are DER TSA certificates (at most 32): the seal must then
    carry an RFC 3161 timestamp that verifies under one of them."""
    anc = tuple(buf(x, "anchor") for x in (anchors or ()))
    code, rows = _c.chk(path(dir), None if pk is None else buf(pk, "pk"),
                        anc)
    return Report(code, (Row(*r) for r in rows))
