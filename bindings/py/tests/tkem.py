# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""KEMs: round trips, determinism and implicit rejection."""
import pytest

import noqtis
from noqtis import kem

KEMS = noqtis.algs("kem")


def test_table():
    assert [a.name for a in KEMS][:3] == ["ML-KEM-512", "ML-KEM-768",
                                          "ML-KEM-1024"]
    assert len(KEMS) == 6


@pytest.mark.parametrize("a", KEMS, ids=lambda a: a.name)
def test_roundtrip(a):
    pk, sk = kem.keygen(a.name)
    assert (len(pk), len(sk)) == (a.pk, a.sk)
    ct, ss = kem.encap(a, pk)
    assert (len(ct), len(ss)) == (a.ct, a.ss)
    assert kem.decap(a.name, sk, ct) == ss
    assert kem.decap(a.name, bytearray(sk), memoryview(ct)) == ss
    ct2, ss2 = kem.encap(a.name, pk)
    assert ct2 != ct and ss2 != ss


@pytest.mark.parametrize("a", KEMS, ids=lambda a: a.name)
def test_implicit_rejection(a):
    pk, sk = kem.keygen(a.name)
    ct, ss = kem.encap(a.name, pk)
    bad = bytearray(ct)
    bad[0] ^= 1
    r1 = kem.decap(a.name, sk, bytes(bad))
    r2 = kem.decap(a.name, sk, bytes(bad))
    assert len(r1) == a.ss and r1 != ss
    assert r1 == r2  # pseudorandom, but a function of sk and ct
    bad[-1] ^= 0x80
    assert kem.decap(a.name, sk, bytes(bad)) not in (ss, r1)
    with pytest.raises(noqtis.NoqtisError):
        kem.decap(a.name, sk, ct[:-1])
    with pytest.raises(noqtis.NoqtisError):
        kem.decap(a.name, sk[:-1], ct)
    with pytest.raises(noqtis.NoqtisError):
        kem.encap(a.name, pk[:-1])


def test_seeded():
    a = "ML-KEM-768"
    k1 = kem.keygen(a, bytes(64))
    assert k1 == kem.keygen(a, bytes(64))
    assert k1 != kem.keygen(a, bytes(range(64)))
    e1 = kem.encap(a, k1[0], bytes(32))
    assert e1 == kem.encap(a, k1[0], bytes(32))
    assert kem.decap(a, k1[1], e1[0]) == e1[1]
    with pytest.raises(noqtis.NoqtisError):
        kem.keygen(a, bytes(63))


def test_rejections():
    with pytest.raises(noqtis.UnsupportedError):
        kem.keygen("ML-DSA-44")
    with pytest.raises(TypeError):
        kem.decap("ML-KEM-512", "sk", b"ct")
