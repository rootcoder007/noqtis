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
import datetime
import json
import os
import time
from typing import Any, Iterable, Iterator, List, Mapping, NamedTuple, Optional, Tuple, Union

from . import _noqtis as _c
from . import dsse, kem, keyfile, sign
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
    "Card",
    "DecodeError",
    "File",
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
    "capid",
    "check",
    "dsse",
    "files",
    "hash",
    "hashes",
    "hmac",
    "idcard",
    "idcheck",
    "kem",
    "keyfile",
    "prove",
    "revoke",
    "rotate",
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


def _cstr(s: Union[str, bytes], what: str) -> bytes:
    """A path or name as the NUL-terminated UTF-8 the library takes."""
    b = s.encode("utf-8") if isinstance(s, str) else buf(s, what)
    if b"\0" in b:
        raise ArgError(-1, "%s: no NUL character" % what)
    return b


def _strs(x: Union[None, str, bytes, Iterable[Union[str, bytes]]],
          what: str) -> Tuple[bytes, ...]:
    if x is None:
        return ()
    if isinstance(x, (str, bytes)):
        x = [x]
    return tuple(_cstr(s, what) for s in x)


def _dirs(x: Union[None, PathLike, Iterable[PathLike]],
          what: str) -> Tuple[bytes, ...]:
    if x is None:
        return ()
    if isinstance(x, (str, bytes, os.PathLike)):
        x = [x]
    out = tuple(path(d) for d in x)
    if any(b"\0" in d for d in out):
        raise ArgError(-1, "%s: no NUL character" % what)
    return out


def _blob(x: Union[Bytes, PathLike], what: str) -> bytes:
    """Bytes as given, or the contents of the file a path names."""
    if isinstance(x, (bytes, bytearray, memoryview)):
        return buf(x, what)
    with open(x, "rb") as f:
        return f.read()


def _inputs(inputs: Iterable[Any]) -> Tuple[Tuple[bytes, bytes], ...]:
    out = []
    for x in inputs:
        if isinstance(x, tuple):
            if len(x) != 2:
                raise ArgError(-1, "inputs: a folder or a (name, folder) pair")
            name, src = x
        else:
            name, src = None, x
        if isinstance(src, (bytes, bytearray, memoryview)):
            # an id: a folder is a str or a path object
            i = bytes(src)
            if len(i) != 32 or name is None:
                raise ArgError(-1, "inputs: an id is 32 bytes, with a name")
        else:
            i = capid(src)
        if name is None:
            name = os.path.basename(os.path.normpath(os.fspath(src)))
            if isinstance(name, bytes):
                name = os.fsdecode(name)
        out.append((i, _cstr(name, "input name")))
    return tuple(out)


def seal(dir: PathLike, sk: Bytes, pk: Bytes,
         meta: Union[None, str, Mapping[str, Any]] = None,
         alg: Optional[AlgLike] = None, format: Optional[int] = None,
         inputs: Optional[Iterable[Any]] = None) -> None:
    """Writes noqtis.json and noqtis.sig into ``dir``, covering every
    regular file in it. ``meta`` is a JSON object (a dict, or its text).
    ``alg`` defaults to the algorithm of the key pair. The creation time
    is SOURCE_DATE_EPOCH when set, else the clock.

    ``format=2`` writes capsule format 2: the manifest carries a Merkle
    tree over its files, so that ``prove`` can show some files without
    the others. ``inputs`` (format 2, the default with it) records the
    capsules this one was made from: each a capsule folder (named by its
    last component) or a ``(name, folder)`` pair, or ``(name, id)`` with
    the 32-byte id from ``capid``. Check the inputs before you name them;
    ``check(lineage=...)`` follows them back."""
    s, p = buf(sk, "sk"), buf(pk, "pk")
    a = _salg(s, p) if alg is None else find(alg, "sign")
    m: Optional[str]
    if meta is None or isinstance(meta, str):
        m = meta
    elif isinstance(meta, Mapping):
        m = json.dumps(dict(meta), allow_nan=False, separators=(",", ":"))
    else:
        raise TypeError("meta: a dict, a JSON string or None")
    f = format if format is not None else (1 if inputs is None else 2)
    if f not in (1, 2):
        raise ArgError(-1, "format: 1 or 2")
    if f == 1 and inputs is not None:
        raise ArgError(-1, "inputs need format 2")
    ins = None if inputs is None else _inputs(inputs)
    if f == 1:
        _c.seal(path(dir), a.id, s, p, m)
    else:
        _c.seal2(path(dir), a.id, s, p, m, ins or ())


def capid(dir: PathLike) -> bytes:
    """The capsule's id (32 bytes): the SHA-256 of what its seal signs,
    as ``seal(inputs=...)`` records it. Nothing is checked: ``check``
    the capsule first."""
    return _c.capid(path(dir))


def check(dir: Optional[PathLike] = None, pk: Optional[Bytes] = None,
          anchors: Optional[Iterable[Bytes]] = None,
          only: Union[None, str, Iterable[str]] = None,
          lineage: Union[None, PathLike, Iterable[PathLike]] = None,
          keys: Optional[Iterable[Union[Bytes, PathLike]]] = None,
          proof: Union[None, Bytes, PathLike] = None) -> Report:
    """Checks ``dir`` against its seal. With ``pk`` the seal must be by
    that key; without, the key in the seal is trusted (a row says so).
    ``anchors`` are DER TSA certificates (at most 32): the seal must then
    carry an RFC 3161 timestamp that verifies under one of them.

    ``only`` checks just these files (paths as the manifest lists them,
    '/' between folders); "partial" rows say what was left out.
    ``lineage`` are capsule folders in which the inputs of a format 2
    capsule are found by id and checked, to 64 levels ("lineage" rows).
    ``keys`` are key statements (from ``rotate`` or ``revoke``, as bytes
    or a file path; at most 32) and need ``pk``: the seal may then be by
    a key ``pk`` was rotated to, and must carry a timestamp from before
    its key was rotated away or revoked.

    ``proof`` (bytes, or a file path) checks a proof from ``prove``
    instead of a folder: its seal, its signature and each proven entry;
    with ``dir`` too, the proven files there. ``only``, ``lineage`` and
    ``keys`` do not apply to a proof."""
    anc = tuple(buf(x, "anchor") for x in (anchors or ()))
    k = None if pk is None else buf(pk, "pk")
    pf = None if proof is None else _blob(proof, "proof")
    if pf is not None and (only is not None or lineage is not None or
                           keys is not None):
        raise ArgError(-1, "only, lineage and keys do not apply to a proof")
    if pf is None and dir is None:
        raise ArgError(-1, "dir: the capsule folder (or give proof=)")
    st = tuple(_blob(x, "key statement") for x in (keys or ()))
    if st and k is None:
        raise ArgError(-1, "keys need pk, the trusted key")
    code, rows = _c.chk(None if dir is None else path(dir), k, anc,
                        _strs(only, "only"), _dirs(lineage, "lineage"), st,
                        pf)
    return Report(code, (Row(*r) for r in rows))


def prove(dir: PathLike, paths: Union[str, Iterable[str]]) -> bytes:
    """A proof (noqtis-proof-1, JSON) that ``paths`` are files of the
    format 2 capsule in ``dir``: the seal, the manifest's head and each
    file's entry and Merkle audit path, and nothing of the other files.
    ``check(proof=...)`` checks it. Check the capsule first."""
    p = _strs(paths, "paths")
    if not p:
        raise ArgError(-1, "paths: at least one file")
    return _c.prove(path(dir), p)


class File(NamedTuple):
    """One file a manifest lists: its path, size in bytes and SHA-256
    (64 hex digits)."""

    path: str
    size: int
    sha256: str


def files(dir: PathLike) -> List[File]:
    """The files the capsule's manifest lists, in manifest order, read
    without checking anything (``check`` does that)."""
    code, rows = _c.files(path(dir))
    bad = [r for r in rows if not r[1]]
    if code != 0 or bad:
        why = bad[0][2] if bad else "the manifest does not parse"
        raise DecodeError(code if code < 0 else -4, why)
    out = []
    for c, _, d in rows:
        if c == "info.file":
            n, h, p = d.split(" ", 2)
            out.append(File(p, int(n), h))
    return out


def _at(at: Union[None, int, float, datetime.datetime]) -> int:
    if at is None:
        return int(time.time())
    if isinstance(at, datetime.datetime):
        if at.tzinfo is None:
            raise ArgError(-1, "at: a datetime with a time zone")
        return int(at.timestamp())
    if isinstance(at, bool) or not isinstance(at, (int, float)):
        raise TypeError("at: seconds since 1970, a datetime or None")
    return int(at)


def _reason(reason: Optional[str]) -> Optional[str]:
    if reason is not None and not isinstance(reason, str):
        raise TypeError("reason: a str or None")
    return reason


def rotate(sk: Bytes, pk: Bytes, nsk: Bytes, npk: Bytes,
           at: Union[None, int, float, datetime.datetime] = None,
           reason: Optional[str] = None, alg: Optional[AlgLike] = None,
           nalg: Optional[AlgLike] = None) -> bytes:
    """A key statement (noqtis-keys-1, JSON) that the key pair (sk, pk)
    is replaced by (nsk, npk) from ``at`` (seconds since 1970 or an aware
    datetime; default now), signed by both keys. ``reason`` is up to 255
    bytes of text. ``alg`` and ``nalg`` default to the pairs' algorithms;
    both must be post-quantum (Ed25519 alone is refused). Give it to
    ``check(keys=...)``."""
    s, p = buf(sk, "sk"), buf(pk, "pk")
    ns, np = buf(nsk, "nsk"), buf(npk, "npk")
    a = _salg(s, p) if alg is None else find(alg, "sign")
    na = _salg(ns, np) if nalg is None else find(nalg, "sign")
    return _c.kstmt(a.id, s, p, na.id, ns, np, _at(at), _reason(reason))


def revoke(sk: Bytes, pk: Bytes,
           at: Union[None, int, float, datetime.datetime] = None,
           reason: Optional[str] = None,
           alg: Optional[AlgLike] = None) -> bytes:
    """A key statement (noqtis-keys-1, JSON) that the key pair (sk, pk)
    is revoked from ``at`` (default now), signed by it; as ``rotate``."""
    s, p = buf(sk, "sk"), buf(pk, "pk")
    a = _salg(s, p) if alg is None else find(alg, "sign")
    return _c.kstmt(a.id, s, p, a.id, None, None, _at(at), _reason(reason))


class Card(NamedTuple):
    """An identity card that verified: who it names (None for a field it
    has not), when it was made, and its key: the algorithm, the public key
    and its SHA-256 in hex, as ``noqtis inspect`` shows a seal's."""

    name: str
    orcid: Optional[str]
    email: Optional[str]
    url: Optional[str]
    affil: Optional[str]
    created: str
    alg: str
    pk: bytes
    key_sha256: str


def _field(v: Optional[str], what: str) -> Optional[str]:
    if v is not None and not isinstance(v, str):
        raise TypeError(what + ": a str or None")
    if v is not None and "\0" in v:
        raise ArgError(-1, what + ": no NUL character")
    return v


def idcard(sk: Bytes, pk: Bytes, name: str, orcid: Optional[str] = None,
           email: Optional[str] = None, url: Optional[str] = None,
           affil: Optional[str] = None,
           at: Union[None, int, float, datetime.datetime] = None,
           alg: Optional[AlgLike] = None) -> bytes:
    """An identity card (noqtis-idcard-1, JSON): the public key ``pk``
    with ``name`` and, when given, an ORCID iD (its check digit verified;
    its https://orcid.org/ address is stored bare), an e-mail address, an
    https:// web page and an affiliation, made at ``at`` (default now) and
    signed by ``sk`` under the card's own context. A field out of its
    limits (see noqtis-idcard(1)) raises ArgError; Ed25519 alone raises
    UnsupportedError."""
    if not isinstance(name, str):
        raise TypeError("name: a str")
    s, p = buf(sk, "sk"), buf(pk, "pk")
    a = _salg(s, p) if alg is None else find(alg, "sign")
    return _c.card(a.id, s, p, _field(name, "name"), _field(orcid, "orcid"),
                   _field(email, "email"), _field(url, "url"),
                   _field(affil, "affil"), _at(at))


def idcheck(card: Union[Bytes, str, "os.PathLike[str]"],
            pk: Optional[Bytes] = None) -> Optional[Card]:
    """The card's fields when it verifies (and, with ``pk``, is for that
    key); None when its signature does not verify or it is for another
    key. ``card`` is the card's bytes or the path of a card file. Input
    that is not a card raises DecodeError. A card is self-signed: compare
    ``key_sha256`` with the one its holder published, or pass ``pk``."""
    if isinstance(card, (str, os.PathLike)):
        with open(card, "rb") as f:
            b = f.read((256 << 10) + 1)
    else:
        b = buf(card, "card")
    rc, f = _c.cardvrfy(b, None if pk is None else buf(pk, "pk"))
    if rc == _c.EDEC:
        raise DecodeError(rc, "not a noqtis-idcard-1 card")
    if rc != 0 or f is None:
        return None
    aid, kp, fp, _, utc, nm, orc, em, u, af = f
    return Card(nm, orc or None, em or None, u or None, af or None, utc,
                next(x.name for x in SIGS if x.id == aid), kp, fp.hex())
