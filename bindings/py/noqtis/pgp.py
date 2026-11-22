# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""OpenPGP (RFC 9580) in its version 6 forms, with Ed25519 and X25519
and the post-quantum algorithms of RFC 9980: keys,
signatures and encrypted messages. Keys and messages are binary packets;
:func:`armor` and :func:`dearmor` make them text and back, and
:func:`verify` and :func:`decrypt` take either.

>>> from noqtis import pgp
>>> sec, cert = pgp.generate("Ada <ada@example.org>", pgp.ED25519,
...                          pgp.X25519)
>>> s = pgp.sign(sec, b"hello")
>>> pgp.verify(cert, s).data
b'hello'
"""
import time
from typing import Iterable, NamedTuple, Optional, Tuple

from . import _noqtis as _c
from ._alg import Bytes, buf, opt

__all__ = ["CLEAR", "DETACHED", "ED25519", "INLINE", "MESSAGE", "MLDSA65",
           "MLKEM768", "PRIVATEKEY", "PUBLICKEY", "SIGNATURE", "SLH128F",
           "SLH128S", "SLH256S", "X25519", "Key", "Opened", "Verified",
           "armor", "dearmor", "decrypt", "encrypt", "generate", "info",
           "sign", "verify"]

# the algorithms, by their OpenPGP numbers
X25519 = 25      # an encryption subkey (RFC 9580)
ED25519 = 27
MLDSA65 = 30     # ML-DSA-65 with Ed25519
SLH128S = 32     # SLH-DSA-SHAKE-128s
SLH128F = 33
SLH256S = 34
MLKEM768 = 35    # ML-KEM-768 with X25519, an encryption subkey

# how sign signs
INLINE = 0       # a signed message that carries the data
DETACHED = 1     # the signature alone
CLEAR = 2        # the text with the armored signature under it

# the kinds of armor
MESSAGE = 1
PUBLICKEY = 2
PRIVATEKEY = 3
SIGNATURE = 4


class Key(NamedTuple):
    """What an OpenPGP key or certificate says of itself."""

    alg: int
    encalg: int                     # 0 when it has no encryption subkey
    secret: bool
    locked: bool                    # under a passphrase
    fingerprint: bytes
    encfingerprint: Optional[bytes]
    created: int                    # seconds since 1970
    expires: Optional[int]          # None: never
    userid: str


class Verified(NamedTuple):
    """What :func:`verify` checked: the data and the signature's time."""

    data: bytes
    at: int


class Opened(NamedTuple):
    """What :func:`decrypt` opened; ``signed`` when the signature of the
    ``signer`` certificate verified, at the time ``at``."""

    data: bytes
    signed: bool
    at: int


def _at(at: Optional[int]) -> int:
    return int(time.time()) if at is None else int(at)


def _in(x: "Bytes | str", what: str) -> bytes:
    return x.encode() if isinstance(x, str) else buf(x, what)


def _pw(x: "Optional[Bytes | str]", what: str) -> Optional[bytes]:
    return None if x is None else _in(x, what)


def generate(userid: str, alg: int = MLDSA65,
             encalg: Optional[int] = MLKEM768, *,
             passphrase: "Optional[Bytes | str]" = None,
             created: Optional[int] = None) -> Tuple[bytes, bytes]:
    """(secret key, certificate) of a new version 6 OpenPGP key: a
    primary key of ``alg`` that certifies and signs, the user ID (by
    convention "Name <address>"), and an encryption subkey of
    ``encalg`` (None for none). The secret key is under ``passphrase``
    when one is given."""
    return _c.pgpgen(int(alg), int(encalg or 0), userid, _at(created),
                     _pw(passphrase, "passphrase"))


def info(key: Bytes) -> Key:
    """What an OpenPGP key or certificate (binary) says. Only what a
    self-signature of the primary key binds is taken; a key with none,
    or a revoked one, raises VerifyError."""
    alg, enc, sec, lock, fp, efp, created, exp, uid = _c.pgpinfo(
        buf(key, "key"))
    return Key(alg, enc, bool(sec), bool(lock), fp, efp if enc else None,
               created, exp or None, uid.decode("utf-8", "replace"))


def sign(key: Bytes, msg: "Bytes | str", mode: int = INLINE, *,
         passphrase: "Optional[Bytes | str]" = None,
         at: Optional[int] = None) -> bytes:
    """``msg`` signed with the secret key: binary packets, except with
    ``mode`` CLEAR, which is text."""
    return _c.pgpsign(buf(key, "key"), _pw(passphrase, "passphrase"),
                      _in(msg, "msg"), int(mode), _at(at))


def verify(cert: Bytes, sig: "Bytes | str",
           msg: "Optional[Bytes | str]" = None) -> Verified:
    """Checks a signed message, a cleartext signature or a detached
    signature (``msg`` is then what it signs), armored or binary, under
    the certificate. Raises VerifyError when it does not verify."""
    return Verified(*_c.pgpvrfy(buf(cert, "cert"), _in(sig, "sig"),
                                _pw(msg, "msg")))


def encrypt(msg: "Bytes | str", certs: Iterable[Bytes] = (), *,
            passphrase: "Optional[Bytes | str]" = None,
            signer: Optional[Bytes] = None,
            signerpass: "Optional[Bytes | str]" = None,
            at: Optional[int] = None) -> bytes:
    """``msg`` encrypted to the encryption subkeys of ``certs`` (at most
    64) and, with ``passphrase``, to that passphrase as well: AES-256
    with OCB. With ``signer``, a secret key, the message is signed
    first."""
    return _c.pgpenc(tuple(buf(c, "certs") for c in certs),
                     _pw(passphrase, "passphrase"), opt(signer, "signer"),
                     _pw(signerpass, "signerpass"), _in(msg, "msg"),
                     _at(at))


def decrypt(msg: "Bytes | str", key: Optional[Bytes] = None, *,
            passphrase: "Optional[Bytes | str]" = None,
            signer: Optional[Bytes] = None) -> Opened:
    """Opens an encrypted message, armored or binary, with the secret
    key (``passphrase`` is then the key's) or, with no key, with the
    passphrase of the message. With ``signer``, a certificate, the
    message inside must be signed by it. Raises VerifyError when it does
    not open or the signature does not verify."""
    data, sb, at = _c.pgpdec(opt(key, "key"), _pw(passphrase, "passphrase"),
                             opt(signer, "signer"), _in(msg, "msg"))
    return Opened(data, bool(sb), at)


def armor(kind: int, data: Bytes) -> str:
    """OpenPGP packets as ASCII armor of ``kind`` MESSAGE, PUBLICKEY,
    PRIVATEKEY or SIGNATURE."""
    return _c.pgparm(int(kind), buf(data, "data")).decode("ascii")


def dearmor(text: "Bytes | str") -> Tuple[int, bytes]:
    """(kind, packets) of one OpenPGP armor."""
    return _c.pgpdearm(_in(text, "text"))
