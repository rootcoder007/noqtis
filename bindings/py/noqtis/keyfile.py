# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""The CLI's key files (docs/guides/keys.md, docs/spec/keyfile.md): a
header line ``noqtis-key-1 <algorithm> <pub|sec>`` and the key bytes as
padded base64 in lines of 64 characters, as ``noqtis keygen`` writes
them. A signature secret key is written as ``noqtis-key-2 <algorithm>
sec`` and holds the version 2 container (``noqtis.sign.sxmake``): the key
with an integrity value that every signature checks. ``decode`` gives the
container of a version 2 file and the key S of a version 1 file, and the
signing functions take either.

``decode`` is as strict as the CLI's reader: the exact header, ``\\n`` or
``\\r\\n`` line ends and nothing else outside the base64 alphabet,
canonical padding, and the algorithm's exact key size. Python's base64
is not constant time; decode secret key files where timing is not
observable.

>>> pk, sk = noqtis.sign.keygen("ML-DSA-44")  # doctest: +SKIP
>>> noqtis.keyfile.write("me", "ML-DSA-44", "sec", sk)  # doctest: +SKIP
>>> noqtis.keyfile.read("me").alg  # doctest: +SKIP
'ML-DSA-44'

A secret key file may be kept under a passphrase (noqtis-pwkey-1, as
``noqtis keygen --pass-fd`` writes it): ``passphrase=`` to ``encode``
and ``write`` protects it, to ``decode`` and ``read`` opens it.
"""
import base64
import os
import re
from typing import NamedTuple, Optional, Union

from . import _noqtis as _c
from ._alg import KEMS, SIGS, Alg, Bytes, buf, path
from ._err import ArgError, DecodeError, FileError, UnsupportedError

MAGIC = "noqtis-key-1"
MAGIC2 = "noqtis-key-2"
"""The first word of a signature secret key in the version 2 container."""
_B64 = re.compile(rb"[A-Za-z0-9+/]*={0,2}")


class Key(NamedTuple):
    """A decoded key file: the algorithm's name, 'pub' or 'sec', the key."""

    alg: str
    kind: str
    key: bytes


def _alg(name: str) -> Alg:
    """Any algorithm by name, in any case, as the CLI finds it."""
    for a in SIGS + KEMS:
        if a.name.lower() == name.lower():
            return a
    raise UnsupportedError(-8, "unknown algorithm %r (the names "
                           "`noqtis algs` lists)" % (name,))


def _size(a: Alg, kind: str) -> int:
    return a.pk if kind == "pub" else a.sk


Pass = Union[str, Bytes]


def _pw(p: Pass) -> bytes:
    b = p.encode("utf-8") if isinstance(p, str) else buf(p, "passphrase")
    if not 1 <= len(b) <= 4096:
        raise ArgError(-1, "passphrase: 1 to 4096 bytes")
    return b


def pwenc(passphrase: Pass, sk: Bytes, ad: Bytes = b"", m: int = 0,
          t: int = 0, p: int = 0) -> bytes:
    """``sk`` under ``passphrase`` (noqtis-pwkey-1): Argon2id with ``m``
    KiB, ``t`` passes and ``p`` lanes (0: 64 MiB, 3, 4) gives the key of
    ChaCha20-Poly1305, whose associated data includes ``ad``."""
    return _c.pwenc(_pw(passphrase), buf(ad, "ad"), m, t, p, buf(sk, "sk"))


KDF_ARGON2ID = 1
"""The derivation of ``pwenc``: Argon2id."""
KDF_PBKDF2 = 2
"""PBKDF2 with HMAC-SHA-256, for places whose rules ask for it."""


def pwenc2(kdf: int, passphrase: Pass, sk: Bytes, ad: Bytes = b"",
           m: int = 0, t: int = 0, p: int = 0) -> bytes:
    """``pwenc`` under the derivation ``kdf``: ``KDF_ARGON2ID`` with ``m``,
    ``t`` and ``p`` as there, or ``KDF_PBKDF2`` with ``t`` the iteration
    count (0: 600000; 100000 to 10000000) and ``m`` and ``p`` 0.
    ``pwdec`` reads both."""
    return _c.pwenc2(int(kdf), _pw(passphrase), buf(ad, "ad"), m, t, p,
                     buf(sk, "sk"))


def pwdec(passphrase: Pass, data: Bytes, ad: Bytes = b"") -> bytes:
    """The key ``pwenc`` protected. VerifyError for a wrong passphrase or
    ``ad``, or any changed byte; LimitError for parameters over the
    limits (a file cannot ask for more memory or time)."""
    return _c.pwdec(_pw(passphrase), buf(ad, "ad"), buf(data, "data"))


def _ad(a: Alg, magic: str = MAGIC) -> bytes:
    return ("%s %s sec" % (magic, a.name)).encode("ascii")


def _sign(a: Alg) -> bool:
    return any(x.name == a.name for x in SIGS)


def encode(alg: str, kind: str, key: Bytes,
           passphrase: Optional[Pass] = None) -> str:
    """The key file text for ``key``: ``kind`` is 'pub' or 'sec'; a
    secret key with ``passphrase`` is kept under it."""
    if not isinstance(alg, str):
        raise TypeError("alg: a name such as 'ML-DSA-65'")
    a = _alg(alg)
    if kind not in ("pub", "sec"):
        raise ArgError(-1, "kind: 'pub' or 'sec'")
    k = buf(key, "key")
    magic = MAGIC
    if kind == "sec" and _sign(a):
        # a signature secret key is written in the version 2 container:
        # S becomes one, a container is taken as it is once checked
        magic = MAGIC2
        if len(k) == a.sk:
            k = _c.sxmk(a.id, k)
        elif len(k) != _c.sxsz(a.id) or _c.sxchk(a.id, k) != 0:
            raise ArgError(-1, "%s secret key: %d bytes, neither the key "
                           "(%d) nor a sound container (%d)" % (
                               a.name, len(k), a.sk, _c.sxsz(a.id)))
    elif len(k) != _size(a, kind):
        raise ArgError(-1, "%s %s key: %d bytes, not %d" % (
            a.name, kind, _size(a, kind), len(k)))
    if passphrase is not None:
        if kind != "sec":
            raise ArgError(-1, "a passphrase protects a secret key only")
        k = pwenc(passphrase, k, _ad(a, magic))
    b = base64.b64encode(k).decode("ascii")
    body = "".join(b[i:i + 64] + "\n" for i in range(0, len(b), 64))
    return "%s %s %s\n%s" % (magic, a.name, kind, body)


def decode(text: Union[str, Bytes],
           passphrase: Optional[Pass] = None) -> Key:
    """The algorithm, kind and key of key file text (str or bytes); a key
    under a passphrase needs ``passphrase``."""
    if isinstance(text, str):
        try:
            t = text.encode("ascii")
        except UnicodeEncodeError:
            raise DecodeError(-4, "not a noqtis key file: not ASCII") from None
    else:
        t = buf(text, "text")
    nl = t.find(b"\n")
    if nl < 0 or nl >= 96:
        raise DecodeError(-4, "not a noqtis key file (want a first line "
                          "\"%s <alg> <pub|sec>\")" % MAGIC)
    head = t[:nl]
    if head.endswith(b"\r"):
        head = head[:-1]
    f = head.split(b" ")
    v2 = len(f) == 3 and f[0] == MAGIC2.encode() and f[2] == b"sec"
    if len(f) != 3 or (f[0] != MAGIC.encode() and not v2) or \
            f[2] not in (b"pub", b"sec"):
        raise DecodeError(-4, "not a noqtis key file (want a first line "
                          "\"%s <alg> <pub|sec>\" or \"%s <alg> sec\")"
                          % (MAGIC, MAGIC2))
    try:
        name = f[1].decode("ascii")
    except UnicodeDecodeError:
        raise DecodeError(-4, "not a noqtis key file") from None
    a = _alg(name)
    kind = f[2].decode("ascii")
    if v2 and not _sign(a):
        raise DecodeError(-4, "a %s key has no version 2 container (only "
                          "signature keys do)" % a.name)
    want = _c.sxsz(a.id) if v2 else _size(a, kind)
    body = t[nl + 1:].replace(b"\r", b"").replace(b"\n", b"")
    bad = DecodeError(-4, "the key is not %d bytes of base64 for %s (the "
                      "file is damaged or cut short)" % (want, a.name))
    if len(body) % 4 != 0 or _B64.fullmatch(body) is None:
        raise bad
    k = base64.b64decode(body, validate=True)
    # canonical: the bits under the padding are zero
    if base64.b64encode(k) != body:
        raise bad
    if kind == "sec" and len(k) == want + 51 and k[:4] == b"NQPW":
        if passphrase is None:
            raise ArgError(-1, "the key is protected by a passphrase: give "
                           "passphrase=")
        k = pwdec(passphrase, k, _ad(a, MAGIC2 if v2 else MAGIC))
    elif passphrase is not None and kind == "sec" and len(k) == want:
        raise ArgError(-1, "the key is not protected by a passphrase")
    if len(k) != want:
        raise bad
    if v2 and _c.sxchk(a.id, k) != 0:
        raise DecodeError(-4, "the secret key is damaged: its integrity "
                          "value does not match (restore the file from a "
                          "copy)")
    return Key(a.name, kind, k)


def read(file: object, kind: Optional[str] = None,
         passphrase: Optional[Pass] = None) -> Key:
    """Reads a key file; ``kind`` 'pub' or 'sec' requires that kind;
    ``passphrase`` opens a protected secret key."""
    if kind not in (None, "pub", "sec"):
        raise ArgError(-1, "kind: None, 'pub' or 'sec'")
    try:
        with open(path(file), "rb") as fh:
            t = fh.read(1 << 20)
    except OSError as e:
        raise FileError(-7, "cannot read key file %s: %s" % (file, e)) from None
    k = decode(t, passphrase)
    if kind is not None and k.kind != kind:
        raise ArgError(-1, "%s is a %s key; give the %s key" % (
            file, "secret" if k.kind == "sec" else "public",
            "secret" if kind == "sec" else "public"))
    return k


def write(file: object, alg: str, kind: str, key: Bytes,
          force: bool = False, passphrase: Optional[Pass] = None) -> None:
    """Writes a key file. A secret key file is created owner-only, never
    through a link; an existing file is kept unless ``force``, which
    removes it first so the new one never inherits its permissions."""
    text = encode(alg, kind, key, passphrase).encode("ascii")
    p = path(file)
    if force:
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
        except OSError as e:
            raise FileError(-7, "cannot replace %s: %s" % (file, e)) from None
    fl = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fl |= getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(p, fl, 0o600 if kind == "sec" else 0o644)
    except FileExistsError:
        raise FileError(-7, "%s exists (pass force=True to replace it)" %
                        (file,)) from None
    except OSError as e:
        raise FileError(-7, "cannot write %s: %s" % (file, e)) from None
    try:
        os.write(fd, text)
    finally:
        os.close(fd)
