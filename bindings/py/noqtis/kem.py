# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Key encapsulation: ML-KEM (FIPS 203) and HQC.

>>> from noqtis import kem
>>> pk, sk = kem.keygen("ML-KEM-768")
>>> ct, ss = kem.encap("ML-KEM-768", pk)
>>> kem.decap("ML-KEM-768", sk, ct) == ss
True
"""
from typing import Any, Optional, Tuple

from . import _noqtis as _c
from ._alg import SIGS, AlgLike, Bytes, buf, find, opt

__all__ = ["CHUNK", "Boxer", "Unboxer", "box", "decap", "encap", "keygen",
           "open", "seal", "unbox"]


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


# ---- a message or a stream sealed to an ML-KEM key ----

def seal(alg: AlgLike, pk: Bytes, msg: Bytes, ctx: Bytes = b"") -> bytes:
    """``msg`` sealed to the ML-KEM public key ``pk`` (noqtis-kseal-1):
    only the holder of the secret key opens it, with the same ``ctx``
    (at most 255 bytes)."""
    a = find(alg, "kem")
    return _c.kseal(a.id, buf(pk, "pk"), buf(ctx, "ctx"), buf(msg, "msg"))


def open(alg: AlgLike, sk: Bytes, data: Bytes, ctx: Bytes = b"") -> bytes:
    """The message ``seal`` sealed. VerifyError for a changed byte, another
    key or another ``ctx``; DecodeError for bytes that are not a sealed
    message of this algorithm."""
    a = find(alg, "kem")
    return _c.kopen(a.id, buf(sk, "sk"), buf(ctx, "ctx"), buf(data, "data"))


CHUNK = 65536  #: the default chunk size of a sealed stream (NQKFCHUNK)


class Boxer:
    """A stream sealed to an ML-KEM public key (noqtis-kstream-1), the
    format of ``noqtis box``: write ``header`` first, then ``update`` for
    each full chunk of ``chunk`` bytes and ``final`` for the last (0 to
    ``chunk`` bytes; a stream that ends on a full chunk ends with it)."""

    __slots__ = ("_c", "header", "chunk")

    def __init__(self, alg: AlgLike, pk: Bytes, ctx: Bytes = b"",
                 chunk: int = CHUNK) -> None:
        a = find(alg, "kem")
        self.chunk = int(chunk) or CHUNK
        self._c, self.header = _c.kfeini(a.id, buf(pk, "pk"), buf(ctx, "ctx"),
                                         self.chunk)

    def update(self, data: Bytes) -> bytes:
        return _c.kfupd(self._c, buf(data, "data"), False, False, self.chunk)

    def final(self, data: Bytes = b"") -> bytes:
        return _c.kfupd(self._c, buf(data, "data"), True, False, self.chunk)


class Unboxer:
    """Opens what ``Boxer`` wrote: give it the header, then each sealed
    chunk (``chunk`` + 16 bytes) to ``update`` and the last to ``final``.
    A chunk's plaintext comes back only when its tag verifies
    (VerifyError otherwise: a changed, moved, dropped or cut chunk)."""

    __slots__ = ("_c", "chunk")

    def __init__(self, alg: AlgLike, sk: Bytes, header: Bytes,
                 ctx: Bytes = b"") -> None:
        a = find(alg, "kem")
        self._c, self.chunk = _c.kfdini(a.id, buf(sk, "sk"), buf(ctx, "ctx"),
                                        buf(header, "header"))

    def update(self, data: Bytes) -> bytes:
        return _c.kfupd(self._c, buf(data, "data"), False, True, self.chunk)

    def final(self, data: Bytes) -> bytes:
        return _c.kfupd(self._c, buf(data, "data"), True, True, self.chunk)


def _fill(f: Any, n: int) -> bytes:
    out = b""
    while len(out) < n:
        b = f.read(n - len(out))
        if not b:
            break
        out += b
    return out


def _pump(f: Any, w: Any, n: int, upd: Any, fin: Any) -> None:
    # a chunk is the last when no byte follows it
    nx = b""
    while True:
        b = nx + _fill(f, n - len(nx))
        nx = _fill(f, 1) if len(b) == n else b""
        if nx:
            w.write(upd(b))
        else:
            w.write(fin(b))
            return


def box(alg: AlgLike, pk: Bytes, src: Any, dst: Any, ctx: Bytes = b"",
        chunk: int = CHUNK) -> None:
    """Seals the binary file object ``src`` to ``dst`` as ``noqtis box``
    does, the same format, one chunk in memory."""
    b = Boxer(alg, pk, ctx, chunk)
    dst.write(b.header)
    _pump(src, dst, b.chunk, b.update, b.final)


def unbox(alg: AlgLike, sk: Bytes, src: Any, dst: Any,
          ctx: Bytes = b"") -> None:
    """Opens a sealed stream from ``src`` to ``dst``, chunk by chunk; on
    VerifyError what was written before the bad chunk had verified, but
    the stream is incomplete: discard ``dst``."""
    a = find(alg, "kem")
    h = _fill(src, 17 + (a.ct or 0))
    u = Unboxer(a, sk, h, ctx)
    _pump(src, dst, u.chunk + 16, u.update, u.final)


def box_to(recipients: Any, src: Any, dst: Any, ctx: Bytes = b"",
           chunk: int = CHUNK, sender: Optional[Bytes] = None,
           sender_alg: Optional[AlgLike] = None) -> None:
    """Seals the binary file object ``src`` to ``dst`` for every recipient
    (noqtis-kstream-2, as ``noqtis box -p ... -p ...``): ``recipients`` is
    1 to 64 pairs ``(alg, pk)`` of an ML-KEM algorithm and its public key,
    and the secret key of any one of them opens the stream. With
    ``sender``, the sender's secret signature key of ``sender_alg``, the
    stream is signed: the signature is inside the encryption and covers
    the recipients. One chunk is in memory."""
    rs = [(find(a, "kem").id, bytes(buf(pk, "pk"))) for a, pk in recipients]
    sig, rec, sk = 0, 0, None
    if sender is not None:
        if sender_alg is None:
            raise TypeError("sender_alg: the algorithm of the sender's key")
        sa = find(sender_alg, "sign")
        sig, rec, sk = sa.id, (sa.sig or 0) + 16, bytes(buf(sender, "sender"))
    n = int(chunk) or CHUNK
    c, header = _c.kmeini(rs, sig, buf(ctx, "ctx"), n)
    dst.write(header)
    _pump(src, dst, n,
          lambda b: _c.kmupd(c, b, False, False, n + 16, None),
          lambda b: _c.kmupd(c, b, True, False, n + 16 + rec, sk))


def unbox_from(alg: AlgLike, sk: Bytes, src: Any, dst: Any, ctx: Bytes = b"",
               sender: Optional[Bytes] = None) -> Optional[str]:
    """Opens a stream ``box_to`` sealed, from ``src`` to ``dst``, with the
    secret key of one of its recipients. ``sender`` is the public key the
    stream must be signed with: a stream that is not signed, or is signed
    by another key, raises VerifyError. With ``sender`` None the signature
    is not checked. Returns the name of the signature algorithm the stream
    names, or None when it is not signed.

    Plaintext is written chunk by chunk, before the signature at the end
    is checked: on an error discard what ``dst`` received."""
    a = find(alg, "kem")
    fx = _fill(src, 24)
    hl, sig, _ = _c.kmpeek(fx)
    c, ch, _ = _c.kmdini(a.id, buf(sk, "sk"), buf(ctx, "ctx"),
                         fx + _fill(src, hl - 24))
    sa = next((x for x in SIGS if x.id == sig), None) if sig else None
    rec = (sa.sig or 0) + 16 if sa is not None else 0
    pk = None if sender is None else bytes(buf(sender, "sender"))
    # the window: one chunk, the record after the last, and one byte
    # more; full, its first chunk is not the last
    full = ch + 16
    win = b""
    while True:
        win += _fill(src, full + rec + 1 - len(win))
        if len(win) == full + rec + 1:
            dst.write(_c.kmupd(c, win[:full], False, True, ch, None))
            win = win[full:]
        else:
            dst.write(_c.kmupd(c, win, True, True, ch, pk))
            return sa.name if sa is not None else None
