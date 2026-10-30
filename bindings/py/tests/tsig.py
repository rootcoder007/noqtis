# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Signatures: every algorithm round trips; bad input is refused."""
import os

import pytest

import noqtis
from noqtis import sign

SIGS = [a.name for a in noqtis.algs("sign")]
# SLH-DSA "s" signs slowly; NQPYFULL=1 gives them the whole battery
FULL = bool(os.environ.get("NQPYFULL"))
SLOW = [] if FULL else [n for n in SIGS if n.endswith("s")]


def seedlen(alg):
    # xi || the Ed25519 key for a hybrid; the private key for Ed25519
    if alg.endswith("+Ed25519"):
        return 64
    if alg.startswith("ML-DSA") or alg == "Ed25519":
        return 32
    return sign.rndlen(alg) * 3


def test_table():
    assert len(SIGS) == 19
    a = {x.name: x for x in noqtis.algs()}
    assert (a["ML-DSA-44"].pk, a["ML-DSA-44"].sk, a["ML-DSA-44"].sig) == \
        (1312, 2560, 2420)
    assert (a["SLH-DSA-SHA2-128s"].pk, a["SLH-DSA-SHA2-128s"].sig) == \
        (32, 7856)
    assert a["ML-KEM-768"].ct == 1088 and a["ML-KEM-768"].ss == 32


@pytest.mark.parametrize("alg", SIGS)
def test_roundtrip(alg):
    a = next(x for x in noqtis.algs("sign") if x.name == alg)
    slow = alg in SLOW
    pk, sk = sign.keygen(alg, bytes(seedlen(alg)) if slow else None)
    assert (len(pk), len(sk)) == (a.pk, a.sk)
    m = b"noqtis python " + alg.encode()
    s = sign.sign(alg, sk, m, ctx=b"c", deterministic=slow)
    assert len(s) == a.sig
    assert sign.verify(alg, pk, m, s, ctx=b"c")
    assert not sign.verify(alg, pk, m + b"!", s, ctx=b"c")
    assert not sign.verify(alg, pk, m, s)  # other context
    bad = bytearray(s)
    bad[len(bad) // 2] ^= 1
    assert not sign.verify(alg, pk, m, bad, ctx=b"c")
    assert not sign.verify(alg, pk, m, s[:-1], ctx=b"c")
    if slow:
        return
    # deterministic: the same bytes twice, and they verify
    d1 = sign.sign(alg, sk, m, deterministic=True)
    assert d1 == sign.sign(alg, sk, m, rnd=bytes(sign.rndlen(alg)))
    assert sign.verify(alg, pk, m, d1)


@pytest.mark.parametrize("alg", [n for n in SIGS if n not in SLOW])
def test_seeded(alg):
    n = seedlen(alg)
    seed = bytes(range(n))
    assert sign.keygen(alg, seed) == sign.keygen(alg, bytearray(seed))
    assert sign.keygen(alg, seed) != sign.keygen(alg, bytes(n))
    with pytest.raises(noqtis.NoqtisError):
        sign.keygen(alg, seed[:-1])


@pytest.mark.parametrize("alg", ["ML-DSA-44", "ML-DSA-87",
                                 "SLH-DSA-SHAKE-128f", "SLH-DSA-SHA2-128f"])
@pytest.mark.parametrize("ph", ["SHA-256", "SHA-512", "SHA3-256",
                                "SHAKE128"])
def test_prehash(alg, ph):
    pk, sk = sign.keygen(alg, bytes(32 if alg.startswith("ML") else 48))
    s = sign.sign(alg, sk, b"m", prehash=ph, deterministic=True)
    assert sign.verify(alg, pk, b"m", s, prehash=ph)
    assert not sign.verify(alg, pk, b"m", s)
    assert not sign.verify(alg, pk, b"m", s, prehash="SHA-384")


def test_buffers():
    pk, sk = sign.keygen("ML-DSA-44")
    m = b"x" * 1000
    s = sign.sign("ml-dsa-44", bytearray(sk), memoryview(m))
    assert sign.verify("ML-DSA-44", memoryview(pk), bytearray(m),
                       memoryview(s))
    mv = memoryview(b"ab" * 500)[::2]  # not contiguous
    s = sign.sign("ML-DSA-44", sk, mv)
    assert sign.verify("ML-DSA-44", pk, b"a" * 500, s)


def test_rejections():
    pk, sk = sign.keygen("ML-DSA-44")
    s = sign.sign("ML-DSA-44", sk, b"m")
    with pytest.raises(TypeError):
        sign.sign("ML-DSA-44", sk, "text")
    with pytest.raises(TypeError):
        sign.verify("ML-DSA-44", pk, b"m", None)
    with pytest.raises(noqtis.UnsupportedError):
        sign.keygen("ML-DSA-99")
    with pytest.raises(noqtis.UnsupportedError):
        sign.keygen("ML-KEM-768")
    with pytest.raises(noqtis.UnsupportedError):
        sign.sign("ML-DSA-44", sk, b"m", prehash="MD5")
    with pytest.raises(noqtis.ArgError):
        sign.sign("ML-DSA-44", sk, b"m", ctx=bytes(256))
    with pytest.raises(noqtis.ArgError):
        sign.verify("ML-DSA-44", pk, b"m", s, ctx=bytes(256))
    assert sign.verify("ML-DSA-44", pk, b"m", sign.sign(
        "ML-DSA-44", sk, b"m", ctx=bytes(255)), ctx=bytes(255))
    with pytest.raises(noqtis.DecodeError):
        sign.verify("ML-DSA-44", pk[:-1], b"m", s)
    with pytest.raises(noqtis.DecodeError):
        sign.sign("ML-DSA-44", sk[:-1], b"m")
    with pytest.raises(noqtis.ArgError):
        sign.sign("ML-DSA-44", sk, b"m", rnd=bytes(31))
    with pytest.raises(noqtis.ArgError):
        sign.sign("ML-DSA-44", sk, b"m", deterministic=True, rnd=bytes(32))
    assert not sign.verify("ML-DSA-44", pk, b"m", b"")
    assert not sign.verify("ML-DSA-44", pk, b"m", s + b"\0")
    # another key
    pk2, _ = sign.keygen("ML-DSA-44")
    assert not sign.verify("ML-DSA-44", pk2, b"m", s)


def test_errors():
    e = noqtis.ArgError(-1, "x")
    assert isinstance(e, ValueError) and isinstance(e, noqtis.NoqtisError)
    assert e.code == -1 and str(e) == "x"
    try:
        sign.sign("ML-DSA-44", bytes(10), b"m")
    except noqtis.NoqtisError as x:
        assert x.code in (-1, -4) and str(x)
    import pickle
    y = pickle.loads(pickle.dumps(noqtis.VerifyError(-3, "v")))
    assert type(y) is noqtis.VerifyError and y.code == -3


def test_threads():
    # the GIL is released: signing from threads gives valid signatures
    import threading
    pk, sk = sign.keygen("SLH-DSA-SHAKE-128f")
    out = []

    def run(i):
        m = b"t%d" % i
        out.append((m, sign.sign("SLH-DSA-SHAKE-128f", sk, m)))

    ts = [threading.Thread(target=run, args=(i,)) for i in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(out) == 4
    for m, s in out:
        assert sign.verify("SLH-DSA-SHAKE-128f", pk, m, s)


def test_version():
    assert noqtis.__version__.count(".") >= 2
