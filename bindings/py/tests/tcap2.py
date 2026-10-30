# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Capsule format 2, proofs, partial checks, lineage, key statements and
DSSE envelopes."""
import json

import pytest

import noqtis
from noqtis import dsse, sign

T0 = 1700000000


def mk(d, n=3):
    (d / "sub").mkdir(parents=True)
    for i in range(n):
        (d / ("f%d.csv" % i)).write_bytes(b"a,b\n%d,2\n" % i)
    (d / "sub" / "y.bin").write_bytes(bytes(range(256)))
    return d


def rows(r, name):
    return [x for x in r if x.check == name]


@pytest.fixture
def key():
    return sign.keygen("ML-DSA-44")


def test_format2(tmp_path, key):
    pk, sk = key
    d = mk(tmp_path / "c")
    noqtis.seal(d, sk, pk, meta={"p": 1}, format=2)
    assert json.loads((d / "noqtis.sig").read_text())["format"] == \
        "noqtis-seal-2"
    r = noqtis.check(d, pk)
    assert r.ok, str(r)
    i = noqtis.capid(d)
    assert isinstance(i, bytes) and len(i) == 32
    assert noqtis.capid(str(d)) == i
    fs = noqtis.files(d)
    assert sorted(f.path for f in fs) == ["f0.csv", "f1.csv", "f2.csv",
                                          "sub/y.bin"]
    y = next(f for f in fs if f.path == "sub/y.bin")
    assert y.size == 256 and y.sha256 == noqtis.hash("SHA-256",
                                                     bytes(range(256))).hex()
    (d / "f1.csv").write_bytes(b"x")
    assert not noqtis.check(d, pk).ok


def test_format_args(tmp_path, key):
    pk, sk = key
    d = mk(tmp_path / "c")
    with pytest.raises(noqtis.ArgError):
        noqtis.seal(d, sk, pk, format=3)
    with pytest.raises(noqtis.ArgError):
        noqtis.seal(d, sk, pk, format=1, inputs=[d])
    with pytest.raises(noqtis.ArgError):
        noqtis.seal(d, sk, pk, inputs=[("x", b"short")])
    with pytest.raises(noqtis.FileError):
        noqtis.capid(d)  # not sealed yet
    with pytest.raises(noqtis.NoqtisError):
        noqtis.files(d)


def test_prove(tmp_path, key):
    pk, sk = key
    d = mk(tmp_path / "c")
    noqtis.seal(d, sk, pk, format=2)
    p = noqtis.prove(d, ["f1.csv", "sub/y.bin"])
    j = json.loads(p)
    assert "f0.csv" not in p.decode() and "f2.csv" not in p.decode()
    assert j["format"] == "noqtis-proof-1"
    r = noqtis.check(proof=p, pk=pk)
    assert r.ok, str(r)
    assert len(rows(r, "proof.entry")) == 2
    # with the files: checked against their entries
    r = noqtis.check(d, pk, proof=p)
    assert r.ok, str(r)
    pf = tmp_path / "p.json"
    pf.write_bytes(p)
    assert noqtis.check(proof=pf, pk=pk).ok
    assert noqtis.check(proof=str(pf)).ok
    (d / "f1.csv").write_bytes(b"x")
    assert not noqtis.check(d, pk, proof=p).ok
    assert noqtis.check(proof=p, pk=pk).ok  # the proof alone still holds
    pk2, _ = sign.keygen("ML-DSA-44")
    assert not noqtis.check(proof=p, pk=pk2).ok
    bad = p.replace(b"f1.csv", b"f9.csv")
    assert not noqtis.check(proof=bad, pk=pk).ok
    assert noqtis.prove(d, "f2.csv")  # one path as a str
    with pytest.raises(noqtis.FileError):
        noqtis.prove(d, ["nope"])
    with pytest.raises(noqtis.ArgError):
        noqtis.prove(d, [])
    with pytest.raises(noqtis.ArgError):
        noqtis.check(d, pk, proof=p, only=["f1.csv"])
    with pytest.raises(noqtis.ArgError):
        noqtis.check()
    e = mk(tmp_path / "v1")
    noqtis.seal(e, sk, pk)
    with pytest.raises(noqtis.UnsupportedError):
        noqtis.prove(e, ["f0.csv"])


@pytest.mark.parametrize("fmt", [1, 2])
def test_only(tmp_path, key, fmt):
    pk, sk = key
    d = mk(tmp_path / "c")
    noqtis.seal(d, sk, pk, format=fmt)
    (d / "f0.csv").write_bytes(b"changed")
    (d / "sub" / "y.bin").unlink()
    assert not noqtis.check(d, pk).ok
    r = noqtis.check(d, pk, only=["f1.csv", "f2.csv"])
    assert r.ok, str(r)
    assert rows(r, "partial")
    assert noqtis.check(d, pk, only="f1.csv").ok
    assert not noqtis.check(d, pk, only=["f0.csv"]).ok
    assert not noqtis.check(d, pk, only=["missing.csv"]).ok


def test_lineage(tmp_path, key):
    pk, sk = key
    a = mk(tmp_path / "raw")
    noqtis.seal(a, sk, pk)
    b = mk(tmp_path / "clean")
    noqtis.seal(b, sk, pk, inputs=[a])  # format 2 implied
    c = mk(tmp_path / "model")
    noqtis.seal(c, sk, pk, inputs=[("cleaned", b),
                                   ("raw-id", noqtis.capid(a))])
    m = json.loads((c / "noqtis.json").read_text())
    assert sorted(x["name"] for x in m["inputs"]) == ["cleaned", "raw-id"]
    r = noqtis.check(c, pk, lineage=[a, b])
    assert r.ok, str(r)
    assert len(rows(r, "lineage")) >= 2
    r = noqtis.check(b, pk, lineage=a)
    assert r.ok and rows(r, "lineage")
    # an input not found, or changed since, fails its lineage row
    assert not noqtis.check(c, pk, lineage=[b]).ok
    (a / "f0.csv").write_bytes(b"changed")
    r = noqtis.check(c, pk, lineage=[a, b])
    assert not r.ok
    assert any(not x.ok for x in rows(r, "lineage"))


def test_keys(tmp_path):
    pk1, sk1 = sign.keygen("ML-DSA-44")
    pk2, sk2 = sign.keygen("ML-DSA-65")
    st = noqtis.rotate(sk1, pk1, sk2, pk2, at=T0, reason="yearly")
    j = json.loads(st)
    assert j["format"] == "noqtis-keys-1"
    d = mk(tmp_path / "new")
    noqtis.seal(d, sk2, pk2)
    assert not noqtis.check(d, pk1).ok
    r = noqtis.check(d, pk1, keys=[st])
    assert r.ok, str(r)
    assert rows(r, "keys")
    f = tmp_path / "rot.json"
    f.write_bytes(st)
    assert noqtis.check(d, pk1, keys=[f]).ok
    # a seal by a revoked key needs a timestamp from before the revocation
    rv = noqtis.revoke(sk1, pk1, at=T0)
    assert json.loads(rv)["format"] == "noqtis-keys-1"
    e = mk(tmp_path / "old")
    noqtis.seal(e, sk1, pk1)
    assert noqtis.check(e, pk1).ok
    r = noqtis.check(e, pk1, keys=[rv])
    assert not r.ok
    assert any(not x.ok for x in rows(r, "key.time"))
    with pytest.raises(noqtis.ArgError):
        noqtis.check(e, keys=[rv])  # statements need a trusted key
    with pytest.raises(noqtis.ArgError):
        noqtis.rotate(sk1, pk1, sk1, pk1, at=T0)  # the same key
    with pytest.raises(TypeError):
        noqtis.revoke(sk1, pk1, at="now")
    pe, se = sign.keygen("Ed25519")
    with pytest.raises(noqtis.UnsupportedError):
        noqtis.revoke(se, pe, at=T0, alg="Ed25519")


def test_keys_datetime():
    import datetime
    pk, sk = sign.keygen("ML-DSA-44")
    t = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
    a = json.loads(noqtis.revoke(sk, pk, at=t))
    assert "2026-01-02T03:04:05Z" in json.dumps(a)
    with pytest.raises(noqtis.ArgError):
        noqtis.revoke(sk, pk, at=t.replace(tzinfo=None))


@pytest.mark.parametrize("alg", ["ML-DSA-65", "Ed25519", "ML-DSA-44+Ed25519",
                                 "SLH-DSA-SHAKE-128f"])
def test_dsse(alg):
    pk, sk = sign.keygen(alg)
    t = "application/vnd.in-toto+json"
    env = dsse.sign(alg, sk, pk, t, b'{"_type":"x"}')
    j = json.loads(env)
    assert j["payloadType"] == t and len(j["signatures"]) == 1
    assert j["signatures"][0]["keyid"] == noqtis.hash("SHA-256", pk).hex()
    v = dsse.verify(alg, pk, env)
    assert v == (t, b'{"_type":"x"}') and v.type == t
    assert dsse.verify(alg, pk, env.decode()) == v
    assert dsse.sign(alg, sk, pk, "text/plain", "") is not None
    pk2, _ = sign.keygen(alg)
    assert dsse.verify(alg, pk2, env) is None
    j["payload"] = "e30="  # {}
    assert dsse.verify(alg, pk, json.dumps(j)) is None


def test_dsse_refusals():
    pk, sk = sign.keygen("ML-DSA-44")
    with pytest.raises(noqtis.DecodeError):
        dsse.verify("ML-DSA-44", pk, b"not json")
    with pytest.raises(noqtis.ArgError):
        dsse.sign("ML-DSA-44", sk, pk, "has space", b"x")
    with pytest.raises(noqtis.ArgError):
        dsse.sign("ML-DSA-44", sk, pk, "", b"x")
    pk2, _ = sign.keygen("ML-DSA-44")
    with pytest.raises(noqtis.ArgError):
        dsse.sign("ML-DSA-44", sk, pk2, "t", b"x")  # not a pair
    with pytest.raises(TypeError):
        dsse.sign("ML-DSA-44", sk, pk, b"t", b"x")


def test_hybrid_seal(tmp_path):
    pk, sk = sign.keygen("ML-DSA-65+Ed25519")
    d = mk(tmp_path / "c")
    noqtis.seal(d, sk, pk, format=2)
    assert json.loads((d / "noqtis.sig").read_text())["alg"] == \
        "ML-DSA-65+Ed25519"
    assert noqtis.check(d, pk).ok
    pe, se = sign.keygen("Ed25519")
    e = mk(tmp_path / "e")
    with pytest.raises(noqtis.UnsupportedError):
        noqtis.seal(e, se, pe, alg="Ed25519")
