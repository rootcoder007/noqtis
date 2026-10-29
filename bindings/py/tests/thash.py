# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Hashes and HMAC against hashlib and hmac."""
import hashlib
import hmac as pyhmac

import pytest

import noqtis

DATA = [b"", b"abc", bytes(range(256)) * 9, b"\xa3" * 200, b"z" * 1000003]
NAMES = {
    "SHA-224": "sha224", "SHA-256": "sha256", "SHA-384": "sha384",
    "SHA-512": "sha512", "SHA-512/224": "sha512_224",
    "SHA-512/256": "sha512_256", "SHA3-224": "sha3_224",
    "SHA3-256": "sha3_256", "SHA3-384": "sha3_384", "SHA3-512": "sha3_512",
}


def _lib(n):
    try:
        return hashlib.new(n)
    except ValueError:
        pytest.skip("hashlib here has no " + n)


@pytest.mark.parametrize("nq,py", sorted(NAMES.items()))
def test_hash(nq, py):
    for d in DATA:
        h = _lib(py)
        h.update(d)
        assert noqtis.hash(nq, d) == h.digest()
        assert noqtis.hash(py, memoryview(d)) == h.digest()


@pytest.mark.parametrize("bits", [128, 256])
def test_shake(bits):
    f = getattr(hashlib, "shake_%d" % bits)
    for d in DATA:
        assert noqtis.hash("SHAKE%d" % bits, d) == f(d).digest(bits // 4)
        for n in (1, 17, 168, 500):
            assert noqtis.hash("shake_%d" % bits, d, n) == f(d).digest(n)


@pytest.mark.parametrize("nq,py", sorted(NAMES.items()))
def test_hmac(nq, py):
    _lib(py)
    for k in (b"", b"k", b"K" * 200):
        for d in DATA[:4]:
            want = pyhmac.new(k, d, py).digest()
            assert noqtis.hmac(nq, k, d) == want


def test_rejections():
    with pytest.raises(noqtis.UnsupportedError):
        noqtis.hash("MD5", b"")
    with pytest.raises(noqtis.ArgError):
        noqtis.hash("SHA-256", b"", 16)
    with pytest.raises(TypeError):
        noqtis.hash("SHA-256", "text")
    assert "SHAKE256" in noqtis.hashes()
