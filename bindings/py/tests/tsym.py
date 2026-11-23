# SPDX-License-Identifier: LGPL-3.0-or-later
"""KangarooTwelve, ChaCha20, AES-SIV and AES-GCM-SIV: an answer of each
RFC, round trips, refusals, and agreement with the cryptography package
where it is installed."""

import pytest

import noqtis

H = bytes.fromhex


def ptn(n):
    return bytes(i % 251 for i in range(n))


def test_kt_rfc9861():
    assert noqtis.kt128(b"") == H("1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5")
    assert noqtis.kt128(ptn(17)) == H("6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888")
    assert noqtis.kt128(b"\xff", custom=ptn(41)) == H(
        "d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4"
    )
    assert noqtis.kt256(b"")[:32] == H("b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404")
    # a shorter output is the start of a longer one, and a tree agrees
    # with itself whatever the output length
    big = ptn(20000)
    assert noqtis.kt128(big, 100)[:32] == noqtis.kt128(big)
    assert len(noqtis.kt256(big)) == 64
    assert noqtis.kt128(big, custom=b"a") != noqtis.kt128(big)
    with pytest.raises(noqtis.NoqtisError):
        noqtis.kt128(b"x", 0)


def test_chacha20_rfc8439():
    # appendix A.2, test vector 1
    assert noqtis.chacha20(bytes(32), bytes(12), bytes(64)) == H(
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
        "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
    )
    k, n, m = ptn(32), ptn(12), ptn(300)
    c = noqtis.chacha20(k, n, m, 7)
    assert c != m and noqtis.chacha20(k, n, c, 7) == m
    assert noqtis.chacha20(k, n, m[64:], 8) == c[64:]
    for bad in ((k[:16], n, m), (k, n[:8], m)):
        with pytest.raises(noqtis.NoqtisError):
            noqtis.chacha20(*bad)


def test_sivenc_rfc5297():
    # appendix A.1
    key = H("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    ad = H("101112131415161718191a1b1c1d1e1f2021222324252627")
    pt = H("112233445566778899aabbccddee")
    out = H("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")
    assert noqtis.sivenc(key, pt, [ad]) == out
    assert noqtis.sivdec(key, out, [ad]) == pt
    # the same input, the same output; another string, another output
    assert noqtis.sivenc(key, pt, [ad]) == out
    assert noqtis.sivenc(key, pt, [ad, b""]) != out
    assert noqtis.sivenc(key, pt) != out
    for k2 in (ptn(48), ptn(64)):
        assert noqtis.sivdec(k2, noqtis.sivenc(k2, pt, [ad, b"n"]), [ad, b"n"]) == pt
    bad = bytearray(out)
    bad[20] ^= 1
    for args in ((key, bytes(bad), [ad]), (key, out, [ad + b"x"]), (key, out, []), (ptn(32), out, [ad])):
        with pytest.raises(noqtis.NoqtisError):
            noqtis.sivdec(*args)
    with pytest.raises(noqtis.NoqtisError):
        noqtis.sivenc(ptn(40), pt)
    with pytest.raises(noqtis.NoqtisError):
        noqtis.sivdec(key, b"short")
    with pytest.raises(TypeError):
        noqtis.sivenc(key, pt, ad)  # one byte string is not a list of them
    with pytest.raises(noqtis.NoqtisError):
        noqtis.sivenc(key, pt, [b"a"] * 127)


def test_gsivenc_rfc8452():
    # appendix C.1, the second vector
    key = H("01000000000000000000000000000000")
    nonce = H("030000000000000000000000")
    pt = H("0100000000000000")
    out = H("b5d839330ac7b786578782fff6013b815b287c22493a364c")
    assert noqtis.gsivenc(key, nonce, pt) == out
    assert noqtis.gsivdec(key, nonce, out) == pt
    k2 = ptn(32)
    c = noqtis.gsivenc(k2, nonce, pt, b"header")
    assert noqtis.gsivdec(k2, nonce, c, b"header") == pt
    bad = bytearray(c)
    bad[-1] ^= 0x80
    for args in ((k2, nonce, bytes(bad), b"header"), (k2, nonce, c, b"other"), (k2, ptn(12), c, b"header")):
        with pytest.raises(noqtis.NoqtisError):
            noqtis.gsivdec(*args)
    for args in ((ptn(24), nonce, pt), (key, ptn(8), pt)):
        with pytest.raises(noqtis.NoqtisError):
            noqtis.gsivenc(*args)
    with pytest.raises(noqtis.NoqtisError):
        noqtis.gsivdec(key, nonce, b"short")


def test_against_cryptography():
    aead = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    for n in (0, 1, 16, 17, 100):
        pt = ptn(n)
        if n:
            assert noqtis.sivenc(ptn(64), pt, [b"a", b"bc"]) == aead.AESSIV(ptn(64)).encrypt(pt, [b"a", b"bc"])
        assert noqtis.gsivenc(ptn(32), ptn(12), pt, b"ad") == aead.AESGCMSIV(ptn(32)).encrypt(ptn(12), pt, b"ad")
