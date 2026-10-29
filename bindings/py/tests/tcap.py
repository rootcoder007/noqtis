# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Capsules: the golden capsule checks, tampering fails, round trips."""
import json

import pytest
from conftest import GOLD, GSEED, GTIME

import noqtis


def gkey():
    return noqtis.sign.keygen("ML-DSA-44", GSEED)


def test_golden(gold):
    pk, _ = gkey()
    r = noqtis.check(gold, pk)
    assert r.ok, str(r)
    assert bool(r) and len(r) == len(r.rows) and not r.failed
    assert any(x.check == "file" and "data/deep/c.bin" in x.detail
               for x in r)
    # without a key the seal's own key is trusted, and a row says so
    r = noqtis.check(str(gold))
    assert r.ok, str(r)
    assert "<noqtis.Report ok=True" in repr(r)


def test_golden_reseal(gold, tmp_path, monkeypatch):
    # sealing the golden files again gives the committed manifest
    pk, sk = gkey()
    monkeypatch.setenv("SOURCE_DATE_EPOCH", GTIME)
    d = tmp_path / "again"
    d.mkdir()
    for f in ("a.txt", "empty", "data/b.csv", "data/deep/c.bin"):
        (d / f).parent.mkdir(parents=True, exist_ok=True)
        (d / f).write_bytes((gold / f).read_bytes())
    meta = '{"project":"golden","n":1.50,"tags":["a","b"]}'
    noqtis.seal(d, sk, pk, meta=meta)
    assert (d / "noqtis.json").read_bytes() == \
        (GOLD / "noqtis.json").read_bytes()
    # nqseal signs with fresh randomness: all but the signature is equal
    a = json.loads((d / "noqtis.sig").read_text())
    b = json.loads((GOLD / "noqtis.sig").read_text())
    assert a.pop("signature") != b.pop("signature")
    assert a == b
    assert noqtis.check(d, pk).ok


def test_tampered(gold):
    pk, _ = gkey()
    (gold / "a.txt").write_bytes(b"other\n")
    r = noqtis.check(gold, pk)
    assert not r.ok and r.failed
    assert any("a.txt" in x.detail or "a.txt" in x.check for x in r.failed)


def test_added_file(gold):
    pk, _ = gkey()
    (gold / "new.txt").write_bytes(b"x")
    assert not noqtis.check(gold, pk).ok


def test_removed_file(gold):
    pk, _ = gkey()
    (gold / "data" / "b.csv").unlink()
    assert not noqtis.check(gold, pk).ok


def test_tampered_seal(gold):
    pk, _ = gkey()
    s = json.loads((gold / "noqtis.sig").read_text())
    sig = bytearray(s["signature"].encode())
    sig[10] = ord("A") if sig[10] != ord("A") else ord("B")
    s["signature"] = sig.decode()
    (gold / "noqtis.sig").write_text(json.dumps(s, separators=(",", ":")))
    assert not noqtis.check(gold, pk).ok


def test_wrong_key(gold):
    pk2, _ = noqtis.sign.keygen("ML-DSA-44")
    assert not noqtis.check(gold, pk2).ok
    pk3, _ = noqtis.sign.keygen("ML-DSA-65")
    assert not noqtis.check(gold, pk3).ok


@pytest.mark.parametrize("alg", ["ML-DSA-65", "SLH-DSA-SHAKE-128f",
                                 "SLH-DSA-SHA2-128f"])
def test_roundtrip(tmp_path, alg):
    pk, sk = noqtis.sign.keygen(alg)
    d = tmp_path / "cap"
    (d / "sub").mkdir(parents=True)
    (d / "x.csv").write_bytes(b"a,b\n1,2\n")
    (d / "sub" / "y.bin").write_bytes(bytes(range(256)))
    noqtis.seal(str(d), bytearray(sk), memoryview(pk),
                meta={"project": "py", "n": 3, "ok": True})
    r = noqtis.check(d, pk)
    assert r.ok, str(r)
    m = json.loads((d / "noqtis.json").read_text())
    assert m.get("meta", m).get("project", "py") == "py"
    s = json.loads((d / "noqtis.sig").read_text())
    assert s["alg"] == alg  # the key pair picked the algorithm
    (d / "sub" / "y.bin").write_bytes(b"changed")
    assert not noqtis.check(d, pk).ok


def test_seal_rejections(tmp_path):
    pk, sk = gkey()
    d = tmp_path / "c"
    d.mkdir()
    (d / "f").write_bytes(b"1")
    with pytest.raises(noqtis.NoqtisError):
        noqtis.seal(d, sk, pk, meta="not json")
    with pytest.raises(TypeError):
        noqtis.seal(d, sk, pk, meta=3)
    with pytest.raises(noqtis.ArgError):
        noqtis.seal(d, sk[:-1], pk)
    with pytest.raises(noqtis.NoqtisError):
        noqtis.seal(tmp_path / "missing", sk, pk)
    with pytest.raises(noqtis.UnsupportedError):
        noqtis.seal(d, sk, pk, alg="ML-KEM-512")


def test_check_missing(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "f").write_bytes(b"1")
    try:
        r = noqtis.check(d)
    except noqtis.NoqtisError:
        return
    assert not r.ok


def test_anchor_without_timestamp(gold):
    pk, _ = gkey()
    ta = GOLD.parent / "tsa" / "root.der"
    if not ta.is_file():
        pytest.skip("no TSA anchor here")
    r = noqtis.check(gold, pk, anchors=[ta.read_bytes()])
    assert not r.ok
    assert len(r.failed) == 1
