# SPDX-License-Identifier: LGPL-3.0-or-later
"""Streaming signatures and hashes: the bytes of the one-call functions,
under fixed randomness, whatever the pieces."""
import io
import shutil

import pytest

import noqtis
from noqtis import sign

MSG = bytes(range(256)) * 41


def pieces(b, n):
    return [b[i:i + n] for i in range(0, len(b), n)] or [b""]


@pytest.mark.parametrize("alg,ph", [
    ("ML-DSA-44", None), ("ML-DSA-65", "SHA-512"), ("ML-DSA-87", "SHAKE256"),
    ("SLH-DSA-SHA2-128f", "SHA-256"), ("Ed25519", "SHA-512"),
    ("ML-DSA-65+Ed25519", "SHA-512")])
def test_equals_one_shot(alg, ph):
    pk, sk = sign.keygen(alg, bytes(range(64 if "+" in alg else 48))[
        :{"ML-DSA-44": 32, "ML-DSA-65": 32, "ML-DSA-87": 32,
          "SLH-DSA-SHA2-128f": 48, "Ed25519": 32,
          "ML-DSA-65+Ed25519": 64}[alg]])
    want = sign.sign(alg, sk, MSG, ctx=b"c", prehash=ph, deterministic=True)
    for n in (1, 7, 4096, len(MSG)):
        s = sign.Signer(alg, sk, ctx=b"c", prehash=ph)
        for p in pieces(MSG, n):
            s.update(p)
        assert s.finish(deterministic=True) == want
    v = sign.Verifier(alg, pk, ctx=b"c", prehash=ph)
    shutil.copyfileobj(io.BytesIO(MSG), v, 1000)
    assert v.finish(want)
    v = sign.Verifier(alg, pk, ctx=b"c", prehash=ph)
    v.update(MSG[:-1] + b"\0")
    assert not v.finish(want)


def test_rnd_and_hedged():
    pk, sk = sign.keygen("ML-DSA-44")
    r = bytes(range(32))
    s = sign.Signer("ML-DSA-44", sk)
    s.update(MSG)
    assert s.finish(rnd=r) == sign.sign("ML-DSA-44", sk, MSG, rnd=r)
    s = sign.Signer("ML-DSA-44", sk)
    s.write(MSG)
    assert sign.verify("ML-DSA-44", pk, MSG, s.finish())


def test_failures():
    pk, sk = sign.keygen("SLH-DSA-SHA2-128f")
    with pytest.raises(noqtis.UnsupportedError):
        sign.Signer("SLH-DSA-SHA2-128f", sk)  # pure SLH-DSA reads twice
    pk, sk = sign.keygen("ML-DSA-44")
    s = sign.Signer("ML-DSA-44", sk)
    s.finish()
    with pytest.raises(noqtis.StateError):
        s.update(b"x")
    with pytest.raises(noqtis.StateError):
        s.finish()


@pytest.mark.parametrize("alg", ["SHA-256", "SHA3-512", "SHA-512/224"])
def test_hasher(alg):
    h = noqtis.Hasher(alg)
    for p in pieces(MSG, 100):
        h.update(p)
    assert h.digest() == noqtis.hash(alg, MSG)


def test_hasher_shake_squeezes():
    h = noqtis.Hasher("SHAKE256")
    h.write(MSG)
    a = h.digest(10) + h.digest(22)
    assert a == noqtis.hash("SHAKE256", MSG, 32)
