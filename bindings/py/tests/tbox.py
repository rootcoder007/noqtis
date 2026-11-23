# SPDX-License-Identifier: LGPL-3.0-or-later
"""Messages and streams sealed to an ML-KEM key: the known answers of
tests/vectors/kseal and kstream opened, round trips, the CLI's box
format, and every failure the format names."""
import io
import subprocess

import pytest
from conftest import cli, kv

import noqtis
from noqtis import kem, keyfile, sign

CLI = cli()
b = bytes.fromhex


@pytest.mark.parametrize("v", kv("kseal/kat.txt"), ids=lambda v: v["alg"])
def test_kseal_kat(v):
    _, sk = kem.keygen(v["alg"], b(v["kseed"]))
    assert kem.open(v["alg"], sk, b(v["out"]), b(v["ctx"])) == b(v["msg"])


def test_kseal_failures():
    v = kv("kseal/kat.txt")[-1]
    pk, sk = kem.keygen(v["alg"], b(v["kseed"]))
    out = bytearray(b(v["out"]))
    out[30] ^= 1
    with pytest.raises(noqtis.VerifyError):
        kem.open(v["alg"], sk, bytes(out), b(v["ctx"]))
    with pytest.raises(noqtis.VerifyError):
        kem.open(v["alg"], sk, b(v["out"]), b(v["ctx"]) + b"x")
    with pytest.raises(noqtis.DecodeError):
        kem.open(v["alg"], sk, b(v["out"])[:10], b(v["ctx"]))
    with pytest.raises(noqtis.UnsupportedError):
        kem.seal("HQC-128", kem.keygen("HQC-128")[0], b"m")
    c = kem.seal(v["alg"], pk, b"round", b"c")
    assert kem.open(v["alg"], sk, c, b"c") == b"round"


def opened(v, data):
    _, sk = kem.keygen(v["alg"], b(v["kseed"]))
    o = io.BytesIO()
    kem.unbox(v["alg"], sk, io.BytesIO(data), o, b(v["ctx"]))
    return o.getvalue()


KS = kv("kstream/kat.txt")


@pytest.mark.parametrize("v", KS, ids=lambda v: "%s-%s-%d" % (
    v["alg"], v["chunk"], len(v["msg"]) // 2))
def test_kstream_kat(v):
    assert opened(v, b(v["out"])) == b(v["msg"])


def chunks(v):
    a = [x for x in noqtis.algs("kem") if x.name == v["alg"]][0]
    out = b(v["out"])
    h, n = 17 + a.ct, int(v["chunk"]) + 16
    return out[:h], [out[i:i + n] for i in range(h, len(out), n)]


def test_kstream_failures():
    v = max(KS, key=lambda v: len(v["out"]))
    h, cs = chunks(v)
    assert len(cs) >= 3
    t = bytearray(b"".join([h] + cs))
    t[len(h) + 5] ^= 1
    with pytest.raises(noqtis.VerifyError):  # a changed byte
        opened(v, bytes(t))
    with pytest.raises(noqtis.VerifyError):  # cut at a chunk's end
        opened(v, b"".join([h] + cs[:-1]))
    with pytest.raises(noqtis.VerifyError):  # cut inside a chunk
        opened(v, b"".join([h] + cs)[:-3])
    with pytest.raises(noqtis.VerifyError):  # two chunks swapped
        opened(v, b"".join([h, cs[1], cs[0]] + cs[2:]))
    with pytest.raises(noqtis.VerifyError):  # bytes after the end
        opened(v, b"".join([h] + cs) + b"x")
    hh = bytearray(h)
    hh[10] ^= 1
    with pytest.raises(noqtis.NoqtisError):  # a changed header
        opened(v, bytes(hh) + b"".join(cs))


@pytest.mark.parametrize("n", [0, 1, 1023, 1024, 1025, 4096, 5000])
def test_round_trip_one_chunk_in_memory(n):
    pk, sk = kem.keygen("ML-KEM-768")
    m = bytes(i % 251 for i in range(n))
    e = io.BytesIO()
    kem.box("ML-KEM-768", pk, io.BytesIO(m), e, b"ctx", chunk=1024)
    o = io.BytesIO()
    e.seek(0)
    kem.unbox("ML-KEM-768", sk, e, o, b"ctx")
    assert o.getvalue() == m


def test_contexts():
    pk, sk = kem.keygen("ML-KEM-512")
    bx = kem.Boxer("ML-KEM-512", pk, chunk=1024)
    a = bx.update(bytes(1024))
    z = bx.final(b"end")
    u = kem.Unboxer("ML-KEM-512", sk, bx.header)
    assert u.chunk == 1024
    assert u.update(a) == bytes(1024) and u.final(z) == b"end"
    with pytest.raises(noqtis.StateError):
        u.final(z)
    with pytest.raises(noqtis.ArgError):
        kem.Boxer("ML-KEM-512", pk, chunk=100)


@pytest.mark.skipif(CLI is None, reason="no noqtis CLI built")
def test_cli_box_both_ways(tmp_path):
    pk, sk = kem.keygen("ML-KEM-768")
    keyfile.write(tmp_path / "k", "ML-KEM-768", "sec", sk)
    keyfile.write(tmp_path / "k.pub", "ML-KEM-768", "pub", pk)
    m = bytes(range(256)) * 300
    (tmp_path / "m").write_bytes(m)
    subprocess.run([CLI, "box", "-p", str(tmp_path / "k.pub"), "-o",
                    str(tmp_path / "e"), str(tmp_path / "m")], check=True,
                   stdin=subprocess.DEVNULL)
    o = io.BytesIO()
    with open(tmp_path / "e", "rb") as f:
        kem.unbox("ML-KEM-768", sk, f, o)
    assert o.getvalue() == m
    with open(tmp_path / "e2", "wb") as w:
        kem.box("ML-KEM-768", pk, io.BytesIO(m), w)
    subprocess.run([CLI, "unbox", "-k", str(tmp_path / "k"), "-o",
                    str(tmp_path / "m2"), str(tmp_path / "e2")], check=True,
                   stdin=subprocess.DEVNULL)
    assert (tmp_path / "m2").read_bytes() == m


@pytest.mark.parametrize("n", [0, 1, 1024, 1025, 5000])
@pytest.mark.parametrize("signed", [False, True])
def test_box_to_several_recipients(n, signed):
    """A stream to three keys, signed or not: each recipient opens it,
    another key does not, and the sender's key decides."""
    ks = [(a,) + kem.keygen(a)
          for a in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")]
    _, xsk = kem.keygen("ML-KEM-768")
    spk, ssk = sign.keygen("ML-DSA-44")
    opk, _ = sign.keygen("ML-DSA-44")
    m = bytes(i % 249 for i in range(n))
    e = io.BytesIO()
    kem.box_to([(a, pk) for a, pk, _ in ks], io.BytesIO(m), e, b"ctx",
               chunk=1024, sender=ssk if signed else None,
               sender_alg="ML-DSA-44" if signed else None)
    data = e.getvalue()
    assert data[:4] == b"NQKM"
    for a, _, sk in ks:
        o = io.BytesIO()
        name = kem.unbox_from(a, sk, io.BytesIO(data), o, b"ctx",
                              sender=spk if signed else None)
        assert o.getvalue() == m
        assert name == ("ML-DSA-44" if signed else None)
    o = io.BytesIO()
    with pytest.raises(noqtis.VerifyError):  # not a recipient
        kem.unbox_from("ML-KEM-768", xsk, io.BytesIO(data), o, b"ctx")
    with pytest.raises(noqtis.VerifyError):  # another context
        kem.unbox_from(ks[0][0], ks[0][2], io.BytesIO(data), o)
    with pytest.raises(noqtis.VerifyError):  # another sender, or not signed
        kem.unbox_from(ks[1][0], ks[1][2], io.BytesIO(data), o, b"ctx",
                       sender=opk)
    # not asked who sent it: it opens, signed or not
    kem.unbox_from(ks[2][0], ks[2][2], io.BytesIO(data), o, b"ctx")
    bad = bytearray(data)
    bad[-3] ^= 1
    with pytest.raises(noqtis.VerifyError):
        kem.unbox_from(ks[0][0], ks[0][2], io.BytesIO(bytes(bad)), o, b"ctx")


def test_box_to_refusals():
    pk, sk = kem.keygen("ML-KEM-768")
    spk, ssk = sign.keygen("ML-DSA-44")
    e = io.BytesIO()
    with pytest.raises(noqtis.ArgError):
        kem.box_to([], io.BytesIO(b""), e)
    with pytest.raises(TypeError):
        kem.box_to([("ML-KEM-768", pk)], io.BytesIO(b""), e, sender=ssk)
    with pytest.raises(noqtis.UnsupportedError):
        kem.box_to([("ML-DSA-44", spk)], io.BytesIO(b""), e)
    with pytest.raises(noqtis.ArgError):
        kem.box_to([("ML-KEM-768", pk)], io.BytesIO(b""), e, chunk=100)
    with pytest.raises(noqtis.DecodeError):
        kem.unbox_from("ML-KEM-768", sk, io.BytesIO(b"NQKM"), e)
    with pytest.raises(noqtis.DecodeError):
        kem.unbox_from("ML-KEM-768", sk, io.BytesIO(bytes(40)), e)
