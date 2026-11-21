# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""A store of other people's public keys in a folder: keys under names
and addresses, certifications of them, and how far each is trusted. A
key is valid when a fully trusted valid key certified it, or three
marginally trusted ones; the owner's own keys are trusted ultimately.

>>> from noqtis import store
>>> store.url("ada@example.org").startswith(
...     "https://example.org/.well-known/noqtis/")
True
"""
import os
import time
from typing import List, NamedTuple, Optional, Tuple, Union

from . import _noqtis as _c
from ._alg import KEMS, SIGS, AlgLike, Bytes, buf, find, opt, path

__all__ = ["TRUST_FULL", "TRUST_MARGINAL", "TRUST_NEVER", "TRUST_ULTIMATE",
           "TRUST_UNKNOWN", "VALID_FULL", "VALID_MARGINAL", "VALID_NONE",
           "Key", "add", "addcert", "certify", "delete", "export", "get",
           "imports", "keys", "trust", "url"]

TRUST_UNKNOWN = 0
TRUST_NEVER = 1
TRUST_MARGINAL = 2
TRUST_FULL = 3
TRUST_ULTIMATE = 4   # the owner's own key
VALID_NONE = 0
VALID_MARGINAL = 1
VALID_FULL = 2

_Dir = Union[str, bytes, "os.PathLike[str]", "os.PathLike[bytes]"]


class Key(NamedTuple):
    """One public key of a store."""

    alg: str
    kem: bool
    fingerprint: bytes   # SHA-256 of the public key
    name: str
    email: str           # "" when it has none
    card: bool           # the store holds its identity card
    trust: int           # a TRUST_ value
    valid: int           # a VALID_ value
    certs: int           # certifications of it under its present name


def _name(kem: int, alg: int) -> str:
    for a in (KEMS if kem else SIGS):
        if a.id == alg:
            return a.name
    return ""


def _any(alg: AlgLike) -> Tuple[int, int]:
    try:
        return 0, find(alg, "sign").id
    except Exception:
        return 1, find(alg, "kem").id


def add(folder: _Dir, alg: AlgLike, pk: Bytes, name: str,
        email: Optional[str] = None, card: Optional[Bytes] = None) -> bytes:
    """Puts the public key ``pk`` into the store in ``folder``, which
    must exist, under ``name`` and ``email``; ``card`` is its identity
    card. Returns the key's fingerprint."""
    kem, a = _any(alg)
    return _c.ksadd(path(folder), kem, a, buf(pk, "pk"), name, email,
                    opt(card, "card"))


def keys(folder: _Dir, query: Optional[str] = None) -> List[Key]:
    """The keys of the store whose name, address or fingerprint (in hex,
    from its start) matches ``query``; all of them with None."""
    return [Key(_name(k, a), bool(k), fp, n, e, bool(c), t, v, nc)
            for k, a, fp, n, e, c, t, v, nc in _c.kslist(path(folder),
                                                         query)]


def get(folder: _Dir, fingerprint: Bytes) -> Tuple[str, bytes]:
    """(algorithm, public key) of the key with the fingerprint."""
    kem, a, pk = _c.ksget(path(folder), buf(fingerprint, "fingerprint"))
    return _name(kem, a), pk


def certify(folder: _Dir, alg: AlgLike, sk: Bytes, pk: Bytes,
            fingerprint: Bytes, *, at: Optional[int] = None) -> str:
    """Signs, with the signature key pair (``sk``, ``pk``), that the key
    ``fingerprint`` of the store belongs to the name and address the
    store has for it. The certification (text) is kept in the store and
    returned, to pass on."""
    a = find(alg, "sign")
    return _c.kscert(path(folder), a.id, buf(sk, "sk"), buf(pk, "pk"),
                     buf(fingerprint, "fingerprint"),
                     int(time.time()) if at is None else int(at)).decode()


def addcert(folder: _Dir, cert: "Bytes | str") -> None:
    """Puts a certification someone else made into the store: both keys
    must be in it, and its signature must verify."""
    b = cert.encode() if isinstance(cert, str) else buf(cert, "cert")
    _c.ksop(0, path(folder), b, 0)


def trust(folder: _Dir, fingerprint: Bytes, level: int) -> None:
    """Sets how far the owner of the key is trusted to certify other
    keys: a TRUST_ value."""
    _c.ksop(1, path(folder), buf(fingerprint, "fingerprint"), int(level))


def delete(folder: _Dir, fingerprint: Bytes) -> None:
    """Removes the key and what the store holds about it."""
    _c.ksop(2, path(folder), buf(fingerprint, "fingerprint"), 0)


def export(folder: _Dir, fingerprint: Bytes) -> str:
    """A bundle (text) of the key: the key, its name and address, its
    identity card and the certifications of it, for another store to
    import or to publish at its :func:`url`."""
    return _c.ksexp(path(folder), buf(fingerprint, "fingerprint")).decode()


def imports(folder: _Dir, bundle: "Bytes | str",
            email: Optional[str] = None) -> Tuple[bytes, int]:
    """Puts the keys of a bundle into the store. With ``email`` the
    bundle's keys must be for that address. Returns the fingerprint of
    the first key and how many keys came in."""
    b = bundle.encode() if isinstance(bundle, str) else buf(bundle, "bundle")
    return _c.ksimp(path(folder), b, email)


def url(email: str) -> str:
    """Where the bundle of an address is looked for, over https at its
    own domain: ``https://<domain>/.well-known/noqtis/<hash of the local
    part>``. Fetch it, and give what comes back to :func:`imports` with
    the address."""
    return _c.ksurl(email)
