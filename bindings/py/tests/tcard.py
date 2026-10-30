# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Identity cards: made and checked, every field's refusals, changed
cards, another key, and a card kept apart from seals and statements."""
import json

import pytest

import noqtis
from noqtis import sign

T0 = 1767225600  # 2026-01-01T00:00:00Z


@pytest.fixture
def key():
    return sign.keygen("ML-DSA-44")


def test_round_trip(tmp_path, key):
    pk, sk = key
    c = noqtis.idcard(sk, pk, "Ada Lovelace",
                      orcid="https://orcid.org/0000-0002-1694-233x",
                      email="ada@example.org", url="https://example.org/ada",
                      affil="AES", at=T0)
    j = json.loads(c)
    assert j["format"] == "noqtis-idcard-1"
    assert j["orcid"] == "0000-0002-1694-233X"
    assert j["created"] == "2026-01-01T00:00:00Z"
    r = noqtis.idcheck(c)
    assert r is not None
    assert (r.name, r.orcid, r.email, r.url, r.affil) == (
        "Ada Lovelace", "0000-0002-1694-233X", "ada@example.org",
        "https://example.org/ada", "AES")
    assert r.alg == "ML-DSA-44" and r.pk == pk
    assert r.key_sha256 == noqtis.hash("SHA-256", pk).hex()
    assert noqtis.idcheck(c, pk) == r
    f = tmp_path / "ada.card"
    f.write_bytes(c)
    assert noqtis.idcheck(f) == r
    assert noqtis.idcheck(str(f)) == r
    # only the fields given; non-ASCII text is kept
    m = noqtis.idcard(sk, pk, "Adéle 李", at=T0)
    r = noqtis.idcheck(m)
    assert r.name == "Adéle 李" and r.orcid is None
    assert "orcid" not in json.loads(m)


@pytest.mark.parametrize("field,value", [
    ("orcid", "0000-0002-1825-0098"), ("orcid", "0000-0002-1825"),
    ("orcid", "https://example.org/0000-0002-1825-0097"),
    ("email", "ada"), ("email", "a@b"), ("email", "a b@c.d"),
    ("url", "http://example.org"), ("url", "https://"),
    ("affil", ""), ("affil", " U"), ("affil", "U\u009b"),
])
def test_field_refused(key, field, value):
    pk, sk = key
    with pytest.raises(noqtis.ArgError):
        noqtis.idcard(sk, pk, "A", at=T0, **{field: value})


def test_refusals(key):
    pk, sk = key
    for n in ["", " A", "A ", "A\nB", "A\u0085B", "x" * 256]:
        with pytest.raises(noqtis.ArgError):
            noqtis.idcard(sk, pk, n, at=T0)
    with pytest.raises(noqtis.ArgError):
        noqtis.idcard(sk, pk, "A\0B", at=T0)
    assert noqtis.idcard(sk, pk, "x" * 255, at=T0)
    with pytest.raises(TypeError):
        noqtis.idcard(sk, pk, b"A", at=T0)
    with pytest.raises(TypeError):
        noqtis.idcard(sk, pk, "A", orcid=1, at=T0)
    pk2, sk2 = sign.keygen("ML-DSA-44")
    with pytest.raises(noqtis.ArgError):
        noqtis.idcard(sk2, pk, "A", at=T0)  # not a pair
    pe, se = sign.keygen("Ed25519")
    with pytest.raises(noqtis.UnsupportedError):
        noqtis.idcard(se, pe, "A", at=T0, alg="Ed25519")


def test_changed(key):
    pk, sk = key
    c = noqtis.idcard(sk, pk, "Ada Lovelace", orcid="0000-0002-1825-0097",
                      at=T0)
    assert noqtis.idcheck(c.replace(b"Ada Lovelace", b"Ada Lovelacf")) is None
    assert noqtis.idcheck(c.replace(b"1825-0097", b"1694-233X")) is None
    pk2, sk2 = sign.keygen("ML-DSA-44")
    assert noqtis.idcheck(c, pk2) is None  # another key
    j = json.loads(c)
    other = json.loads(noqtis.idcard(sk2, pk2, "Ada Lovelace",
                                     orcid="0000-0002-1825-0097", at=T0))
    j["signature"] = other["signature"]
    forged = json.dumps(j, separators=(",", ":"), sort_keys=True).encode()
    assert noqtis.idcheck(forged) is None
    with pytest.raises(noqtis.DecodeError):
        noqtis.idcheck(b" " + c)  # not canonical
    with pytest.raises(noqtis.DecodeError):
        noqtis.idcheck(b"{}")
    with pytest.raises(noqtis.LimitError):
        noqtis.idcheck(b"[" * ((256 << 10) + 1))


def test_not_a_seal_or_statement(tmp_path, key):
    pk, sk = key
    st = noqtis.revoke(sk, pk, at=T0)
    with pytest.raises(noqtis.DecodeError):
        noqtis.idcheck(st)
    d = tmp_path / "c"
    d.mkdir()
    (d / "a.txt").write_text("a\n")
    noqtis.seal(d, sk, pk)
    with pytest.raises(noqtis.DecodeError):
        noqtis.idcheck(d / "noqtis.sig")
    (d / "noqtis.sig").write_bytes(noqtis.idcard(sk, pk, "A", at=T0))
    assert not noqtis.check(d, pk).ok
