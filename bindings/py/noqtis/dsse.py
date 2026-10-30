# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""DSSE envelopes (the in-toto and SLSA signing wrapper), signed with any
noqtis signature algorithm.

>>> from noqtis import dsse, sign
>>> pk, sk = sign.keygen("ML-DSA-65")
>>> env = dsse.sign("ML-DSA-65", sk, pk, "application/vnd.in-toto+json",
...                 b'{"a":1}')
>>> dsse.verify("ML-DSA-65", pk, env)
Signed(type='application/vnd.in-toto+json', payload=b'{"a":1}')
"""
from typing import NamedTuple, Optional, Union

from . import _noqtis as _c
from ._alg import AlgLike, Bytes, buf, find
from ._err import ArgError, DecodeError

__all__ = ["Signed", "sign", "verify"]


class Signed(NamedTuple):
    """What a verified envelope carries: its payloadType and payload."""

    type: str
    payload: bytes


def _data(x: Union[Bytes, str], what: str) -> bytes:
    if isinstance(x, str):
        return x.encode("utf-8")
    return buf(x, what)


def sign(alg: AlgLike, sk: Bytes, pk: Bytes, type: str,
         payload: Union[Bytes, str]) -> bytes:
    """A DSSE envelope (canonical JSON) of ``payload`` (bytes, or a str as
    its UTF-8) with payloadType
    ``type`` (1 to 255 printable ASCII bytes, no space, quote or
    backslash), signed by the key pair (sk, pk) over the envelope's
    pre-authentication encoding; its keyid is the hex SHA-256 of pk. The
    signature is checked before the envelope is returned."""
    a = find(alg, "sign")
    if not isinstance(type, str):
        raise TypeError("type: a str such as 'application/vnd.in-toto+json'")
    t = type.encode("utf-8")
    if b"\0" in t:
        raise ArgError(-1, "type: no NUL character")
    return _c.dsse(a.id, buf(sk, "sk"), buf(pk, "pk"), t,
                   _data(payload, "payload"))


def verify(alg: AlgLike, pk: Bytes,
           env: Union[Bytes, str]) -> Optional[Signed]:
    """The envelope's (type, payload) when one of its signatures (at most
    16) verifies under ``pk``; None when none does. An ``env`` that is
    not a DSSE envelope raises DecodeError."""
    a = find(alg, "sign")
    rc, t, p = _c.dssevrfy(a.id, buf(pk, "pk"), _data(env, "env"))
    if rc == _c.EDEC:
        raise DecodeError(rc, "not a DSSE envelope")
    if rc != 0:
        return None
    return Signed(t, p)
