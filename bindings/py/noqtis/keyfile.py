# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""The CLI's key files (DESIGN.md, "Key files"): a header line
``noqtis-key-1 <algorithm> <pub|sec>`` and the key bytes as padded base64
in lines of 64 characters, as ``noqtis keygen`` writes them.

``decode`` is as strict as the CLI's reader: the exact header, ``\\n`` or
``\\r\\n`` line ends and nothing else outside the base64 alphabet,
canonical padding, and the algorithm's exact key size. Python's base64
is not constant time; decode secret key files where timing is not
observable.

>>> pk, sk = noqtis.sign.keygen("ML-DSA-44")  # doctest: +SKIP
>>> noqtis.keyfile.write("me", "ML-DSA-44", "sec", sk)  # doctest: +SKIP
>>> noqtis.keyfile.read("me").alg  # doctest: +SKIP
'ML-DSA-44'
"""
import base64
import os
import re
from typing import NamedTuple, Optional, Union

from ._alg import KEMS, SIGS, Alg, Bytes, buf, path
from ._err import ArgError, DecodeError, FileError, UnsupportedError

MAGIC = "noqtis-key-1"
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


def encode(alg: str, kind: str, key: Bytes) -> str:
    """The key file text for ``key``: ``kind`` is 'pub' or 'sec'."""
    if not isinstance(alg, str):
        raise TypeError("alg: a name such as 'ML-DSA-65'")
    a = _alg(alg)
    if kind not in ("pub", "sec"):
        raise ArgError(-1, "kind: 'pub' or 'sec'")
    k = buf(key, "key")
    if len(k) != _size(a, kind):
        raise ArgError(-1, "%s %s key: %d bytes, not %d" % (
            a.name, kind, _size(a, kind), len(k)))
    b = base64.b64encode(k).decode("ascii")
    body = "".join(b[i:i + 64] + "\n" for i in range(0, len(b), 64))
    return "%s %s %s\n%s" % (MAGIC, a.name, kind, body)


def decode(text: Union[str, Bytes]) -> Key:
    """The algorithm, kind and key of key file text (str or bytes)."""
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
    if len(f) != 3 or f[0] != MAGIC.encode() or f[2] not in (b"pub", b"sec"):
        raise DecodeError(-4, "not a noqtis key file (want a first line "
                          "\"%s <alg> <pub|sec>\")" % MAGIC)
    try:
        name = f[1].decode("ascii")
    except UnicodeDecodeError:
        raise DecodeError(-4, "not a noqtis key file") from None
    a = _alg(name)
    kind = f[2].decode("ascii")
    want = _size(a, kind)
    body = t[nl + 1:].replace(b"\r", b"").replace(b"\n", b"")
    bad = DecodeError(-4, "the key is not %d bytes of base64 for %s (the "
                      "file is damaged or cut short)" % (want, a.name))
    if len(body) % 4 != 0 or _B64.fullmatch(body) is None:
        raise bad
    k = base64.b64decode(body, validate=True)
    # canonical: the bits under the padding are zero
    if len(k) != want or base64.b64encode(k) != body:
        raise bad
    return Key(a.name, kind, k)


def read(file: object, kind: Optional[str] = None) -> Key:
    """Reads a key file; ``kind`` 'pub' or 'sec' requires that kind."""
    if kind not in (None, "pub", "sec"):
        raise ArgError(-1, "kind: None, 'pub' or 'sec'")
    try:
        with open(path(file), "rb") as fh:
            t = fh.read(1 << 20)
    except OSError as e:
        raise FileError(-7, "cannot read key file %s: %s" % (file, e)) from None
    k = decode(t)
    if kind is not None and k.kind != kind:
        raise ArgError(-1, "%s is a %s key; give the %s key" % (
            file, "secret" if k.kind == "sec" else "public",
            "secret" if kind == "sec" else "public"))
    return k


def write(file: object, alg: str, kind: str, key: Bytes,
          force: bool = False) -> None:
    """Writes a key file. A secret key file is created owner-only, never
    through a link; an existing file is kept unless ``force``, which
    removes it first so the new one never inherits its permissions."""
    text = encode(alg, kind, key).encode("ascii")
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
