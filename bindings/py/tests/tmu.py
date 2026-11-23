# SPDX-License-Identifier: LGPL-3.0-or-later
"""ML-DSA with an external mu (ACVP records of tests/vectors/acvp/mu.txt),
BLAKE2b (tests/vectors/b2b) and Argon2id (tests/vectors/argon2)."""
import pytest
from conftest import kv

import noqtis
from noqtis import sign

b = bytes.fromhex


@pytest.mark.parametrize("v", kv("acvp/mu.txt"),
                         ids=lambda v: v["alg"] + v["kind"] + v["ok"])
def test_acvp(v):
    if v["kind"] == "gen":
        assert sign.signmu(v["alg"], b(v["key"]), b(v["mu"]),
                           rnd=b(v["rnd"])) == b(v["sig"])
    else:
        assert sign.verifymu(v["alg"], b(v["key"]), b(v["mu"]),
                             b(v["sig"])) == (v["ok"] == "1")


def test_mu_is_sign():
    pk, sk = sign.keygen("ML-DSA-65")
    m = sign.mu("ML-DSA-65", pk, b"msg", b"ctx", "SHA-256")
    assert len(m) == 64
    s = sign.signmu("ML-DSA-65", sk, m, deterministic=True)
    assert s == sign.sign("ML-DSA-65", sk, b"msg", b"ctx", True, "SHA-256")
    assert sign.verify("ML-DSA-65", pk, b"msg", s, b"ctx", "SHA-256")
    with pytest.raises(noqtis.UnsupportedError):
        sign.mu("Ed25519", bytes(32), b"m")


@pytest.mark.parametrize("v", kv("b2b/kat.txt"), ids=lambda v: str(len(v["hash"])))
def test_blake2b(v):
    assert noqtis.blake2b(b(v["in"]), b(v["key"]),
                          len(v["hash"]) // 2) == b(v["hash"])


def test_blake2b_rfc():
    v = kv("b2b/rfc7693.txt")[0]
    assert noqtis.blake2b(b"abc") == b(v["abc"])
    with pytest.raises(noqtis.ArgError):
        noqtis.blake2b(b"", n=65)


@pytest.mark.parametrize("v", [v for v in kv("argon2/rfc9106.txt") +
                               kv("argon2/ossl.txt") if v["y"] == "2"])
def test_argon2id(v):
    assert noqtis.argon2id(b(v["pw"]), b(v["salt"]), int(v["t"]), int(v["m"]),
                           int(v["p"]), len(v["tag"]) // 2, b(v["key"]),
                           b(v["ad"])) == b(v["tag"])
