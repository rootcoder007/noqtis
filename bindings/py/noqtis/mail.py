# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Text armor, X.509 certificates for noqtis keys, and signed and
encrypted messages with them: the Cryptographic Message Syntax (RFC 5652)
and S/MIME (RFC 8551).

>>> from noqtis import mail, sign
>>> pk, sk = sign.keygen("ML-DSA-44")
>>> cert = mail.selfcert("ML-DSA-44", sk, pk, "Ada Example",
...                      notbefore=1767225600, notafter=1798761600)
>>> s = mail.cmssign("ML-DSA-44", sk, cert, b"hello", at=1767229200)
>>> content, who = mail.cmsverify(s, [cert], at=1767229200)
>>> content, who.name
(b'hello', 'Ada Example')
"""
import time
from typing import Iterable, NamedTuple, Optional, Tuple

from . import _noqtis as _c
from ._alg import KEMS, SIGS, AlgLike, Bytes, buf, find, opt

__all__ = ["Cert", "armor", "cmsdecrypt", "cmsencrypt", "cmssign",
           "cmsverify", "dearmor", "kemcert", "readcert", "selfcert",
           "smimedecrypt", "smimeencrypt", "smimesign", "smimeverify"]


class Cert(NamedTuple):
    """What an X.509 certificate says of its key and holder. ``alg`` is
    "" for a key of a kind noqtis does not have; ``pk`` is b"" when the
    certificate was read as a signer alone."""

    alg: str
    kem: bool
    fingerprint: bytes  # SHA-256 of the certificate
    notbefore: int      # seconds since 1970
    notafter: int
    ca: bool
    name: str
    email: str
    pk: bytes


def _name(kem: int, alg: int) -> str:
    for a in (KEMS if kem else SIGS):
        if a.id == alg:
            return a.name
    return ""


def _cert(t: tuple, der: Optional[bytes] = None) -> Cert:
    kem, alg, fp, nb, na, ca, name, email, off, n = t
    return Cert(_name(kem, alg), bool(kem), fp, nb, na, bool(ca), name,
                email, b"" if der is None else der[off:off + n])


def _at(at: Optional[int]) -> int:
    return int(time.time()) if at is None else int(at)


def _text(x: "Bytes | str", what: str) -> bytes:
    return x.encode() if isinstance(x, str) else buf(x, what)


def _list(xs: Iterable[Bytes], what: str) -> Tuple[bytes, ...]:
    return tuple(buf(x, what) for x in xs)


def armor(label: str, data: Bytes) -> str:
    """``data`` as text (RFC 7468): a ``-----BEGIN label-----`` line,
    base64 in lines of 64, and the END line. The label is capitals and
    digits with single spaces between them."""
    return _c.armor(label, buf(data, "data")).decode("ascii")


def dearmor(text: "Bytes | str") -> Tuple[str, bytes]:
    """(label, data) of one armor. Text that is not exactly one
    well-formed armor raises DecodeError."""
    return _c.dearmor(_text(text, "text"))


def selfcert(alg: AlgLike, sk: Bytes, pk: Bytes, name: str,
             email: Optional[str] = None, *, notbefore: int,
             notafter: int) -> bytes:
    """A self-signed X.509 certificate (DER) for the signature key pair
    (``sk``, ``pk``), an ML-DSA, SLH-DSA or Ed25519 key, under ``name``
    and ``email``, valid from ``notbefore`` to ``notafter`` (seconds
    since 1970). It is a CA of path length 0, so that it can issue a
    :func:`kemcert`."""
    a = find(alg, "sign")
    return _c.x5self(a.id, buf(sk, "sk"), buf(pk, "pk"), name, email,
                     int(notbefore), int(notafter))


def kemcert(issueralg: AlgLike, issuersk: Bytes, issuercert: Bytes,
            alg: AlgLike, pk: Bytes, *, notbefore: int,
            notafter: int) -> bytes:
    """A certificate (DER) for the ML-KEM public key ``pk``, issued by
    the signature key ``issuersk`` under the name of its own certificate
    ``issuercert``: what others encrypt to."""
    ia = find(issueralg, "sign")
    a = find(alg, "kem")
    return _c.x5kem(ia.id, buf(issuersk, "issuersk"),
                    buf(issuercert, "issuercert"), a.id, buf(pk, "pk"),
                    int(notbefore), int(notafter))


def readcert(cert: Bytes) -> Cert:
    """What a certificate (DER) says: its key, holder and dates. It
    checks no signature; :func:`cmsverify` and :func:`smimeverify` do,
    against anchors."""
    der = buf(cert, "cert")
    return _cert(_c.x5info(der), der)


def cmssign(alg: AlgLike, sk: Bytes, cert: Bytes, msg: Bytes, *,
            detached: bool = False, at: Optional[int] = None) -> bytes:
    """A CMS SignedData (RFC 5652, DER) of ``msg``, signed with the key
    ``sk`` whose certificate is ``cert``; with ``detached`` the content
    is left out. ``at`` is the signing time (now when None)."""
    a = find(alg, "sign")
    return _c.cmssign(a.id, buf(sk, "sk"), buf(cert, "cert"),
                      buf(msg, "msg"), bool(detached), _at(at), False)


def cmsverify(cms: Bytes, anchors: Iterable[Bytes], *,
              msg: Optional[Bytes] = None,
              at: Optional[int] = None) -> Tuple[bytes, Cert]:
    """(content, signer) of a SignedData checked against ``anchors``,
    certificates (DER) the caller trusts: the signer's certificate must
    be one of them. ``msg`` is the content of a detached signature.
    Raises VerifyError when the signature does not verify or the signer
    is not an anchor."""
    out, f = _c.cmsvrfy(buf(cms, "cms"), opt(msg, "msg"),
                        _list(anchors, "anchors"), _at(at), False)
    return out, _cert(f)


def cmsencrypt(certs: Iterable[Bytes], msg: Bytes) -> bytes:
    """A CMS AuthEnvelopedData (RFC 5083, AES-256-GCM, DER) of ``msg``
    to the ML-KEM certificates ``certs`` (RFC 9629, RFC 9936): the
    secret key of any one of them opens it."""
    return _c.cmsenc(_list(certs, "certs"), buf(msg, "msg"), False)


def cmsdecrypt(alg: AlgLike, sk: Bytes, cms: Bytes, *,
               cert: Optional[Bytes] = None) -> bytes:
    """The content of an AuthEnvelopedData, opened with the ML-KEM
    secret key ``sk``; ``cert`` is the key's certificate and names the
    recipient to use. Raises VerifyError when it is not for this key or
    was changed."""
    a = find(alg, "kem")
    return _c.cmsdec(a.id, buf(sk, "sk"), opt(cert, "cert"),
                     buf(cms, "cms"), False)


def smimesign(alg: AlgLike, sk: Bytes, cert: Bytes, entity: "Bytes | str",
              *, detached: bool = False, at: Optional[int] = None) -> str:
    """An S/MIME message (RFC 8551) of the MIME ``entity`` (header
    lines, an empty line, the body), signed as :func:`cmssign` signs:
    application/pkcs7-mime, or with ``detached`` multipart/signed, which
    keeps the entity readable."""
    a = find(alg, "sign")
    return _c.cmssign(a.id, buf(sk, "sk"), buf(cert, "cert"),
                      _text(entity, "entity"), bool(detached), _at(at),
                      True).decode()


def smimeverify(mime: "Bytes | str", anchors: Iterable[Bytes], *,
                at: Optional[int] = None) -> Tuple[str, Cert]:
    """(entity, signer) of a signed S/MIME message, checked against
    ``anchors`` as :func:`cmsverify` checks."""
    out, f = _c.cmsvrfy(_text(mime, "mime"), None,
                        _list(anchors, "anchors"), _at(at), True)
    return out.decode(), _cert(f)


def smimeencrypt(certs: Iterable[Bytes], entity: "Bytes | str") -> str:
    """An encrypted S/MIME message (authEnveloped-data) of the MIME
    ``entity`` to the ML-KEM certificates ``certs``."""
    return _c.cmsenc(_list(certs, "certs"), _text(entity, "entity"),
                     True).decode()


def smimedecrypt(alg: AlgLike, sk: Bytes, mime: "Bytes | str", *,
                 cert: Optional[Bytes] = None) -> str:
    """The MIME entity inside an encrypted S/MIME message, opened as
    :func:`cmsdecrypt` opens."""
    a = find(alg, "kem")
    return _c.cmsdec(a.id, buf(sk, "sk"), opt(cert, "cert"),
                     _text(mime, "mime"), True).decode()
