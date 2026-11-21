# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Keys on a token, through PKCS #11: a smart card, a hardware security
module, or a software token. The private key stays there; the token
signs and decapsulates. The post-quantum key types are those of PKCS #11
version 3.2.

>>> from noqtis.token import Token
>>> with Token("/usr/lib/softhsm/libsofthsm2.so") as t:  # doctest: +SKIP
...     t.login(t.tokens()[0].slot, "1234")
...     k = t.generate("ML-DSA-65", "release")
...     sig = t.sign(k, b"a release")
"""
import os
from typing import Any, List, NamedTuple, Optional, Union

from . import _noqtis as _c
from ._alg import KEMS, SIGS, AlgLike, Bytes, buf, find, opt, path

__all__ = ["Info", "Key", "Token"]


class Info(NamedTuple):
    """One token present."""

    slot: int
    label: str
    maker: str
    model: str
    serial: str
    login: bool   # its keys need the PIN


class Key(NamedTuple):
    """A private key on a token that noqtis can use. ``handle`` is the
    object in the session that listed it."""

    alg: str
    kem: bool
    label: str
    id: bytes
    handle: int


def _name(kem: int, alg: int) -> str:
    for a in (KEMS if kem else SIGS):
        if a.id == alg:
            return a.name
    return ""


def _key(t: tuple) -> Key:
    kem, alg, h, label, kid = t
    return Key(_name(kem, alg), bool(kem), label.decode("utf-8", "replace"),
               kid, h)


class Token:
    """A loaded PKCS #11 module, at the path ``module``. The path must
    have a folder in it: a bare name, which the system would search for,
    raises ArgError. Close it, or use it in a ``with`` block; it is for
    one thread at a time."""

    def __init__(self, module: Union[str, bytes, "os.PathLike[str]",
                                     "os.PathLike[bytes]"]) -> None:
        self._h: Any = _c.p11open(path(module))

    def close(self) -> None:
        """Ends the session and unloads the module."""
        _c.p11close(self._h)

    def __enter__(self) -> "Token":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def why(self) -> int:
        """The module's own return value for the last call it refused: a
        CKR number of the standard."""
        return _c.p11why(self._h)

    def tokens(self) -> List[Info]:
        """The tokens present."""
        return [Info(s, la, ma, mo, se, bool(lo))
                for s, la, ma, mo, se, lo in _c.p11toks(self._h)]

    def login(self, slot: int, pin: Optional[str] = None) -> None:
        """Opens a session with the token in ``slot`` and, with a PIN,
        logs the user in. Raises VerifyError for a wrong or locked
        PIN."""
        _c.p11login(self._h, int(slot),
                    None if pin is None else pin.encode())

    def keys(self) -> List[Key]:
        """The private keys of the token that noqtis can use. A token
        shows its private keys after the PIN."""
        return [_key(t) for t in _c.p11keys(self._h)]

    def _use(self, op: int, k: Key, data: bytes,
             ctx: Optional[bytes]) -> bytes:
        a = find(k.alg, "kem" if k.kem else "sign")
        return _c.p11use(self._h, op, int(k.kem), a.id, k.handle, k.id,
                         data, ctx)

    def publickey(self, key: Key) -> bytes:
        """The public key of ``key``, as sign.verify and kem.encap take
        it."""
        return self._use(0, key, b"", None)

    def sign(self, key: Key, msg: Bytes, ctx: Optional[Bytes] = None
             ) -> bytes:
        """``msg`` signed on the token with the signature key and the
        context: the signature sign.sign makes, which sign.verify
        checks."""
        return self._use(1, key, buf(msg, "msg"), opt(ctx, "ctx") or None)

    def decap(self, key: Key, ct: Bytes) -> bytes:
        """The shared secret of the ML-KEM ciphertext, decapsulated on
        the token. The module must be of PKCS #11 version 3.2; an older
        one raises UnsupportedError."""
        return self._use(2, key, buf(ct, "ct"), None)

    def generate(self, alg: AlgLike, label: str) -> Key:
        """A new key pair of ``alg`` on the token under ``label``; the
        private key is marked never to leave it."""
        try:
            kem, a = 0, find(alg, "sign").id
        except Exception:
            kem, a = 1, find(alg, "kem").id
        return _key(_c.p11gen(self._h, kem, a, label))
