# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""inspect, sealwhy and the timestamp requests from Python, on the golden
capsule (tests/vectors/cap/sample)."""
import os
import shutil

import pytest
from conftest import GOLD

import noqtis
from noqtis import sign


@pytest.fixture
def gold(tmp_path):
    d = tmp_path / "g"
    shutil.copytree(GOLD, d)
    return d


def test_inspect(gold):
    r = noqtis.inspect(gold)
    assert r.ok
    info = {x.check: x.detail for x in r}
    assert info["info.alg"] == "ML-DSA-44"
    assert info["info.timestamp"] == "none"


def test_sealwhy(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "a").write_text("a")
    assert noqtis.sealwhy(d) is None
    if hasattr(os, "symlink"):
        try:
            os.symlink("a", d / "l")
        except OSError:
            pytest.skip("no symbolic links here")
        pk, sk = sign.keygen("ML-DSA-44")
        with pytest.raises(noqtis.ArgError):
            noqtis.seal(d, sk, pk)
        assert noqtis.sealwhy(d) == ("link", "l")


def test_tsreq(gold):
    q = noqtis.tsreq(gold, nonce=b"\x01\x02")
    assert q[0] == 0x30 and len(q) <= 128
    assert noqtis.tsreq(gold) != q
    e = noqtis.ersreq(gold)
    assert e[0] == 0x30
    with pytest.raises(noqtis.NoqtisError):
        noqtis.tsput(gold, b"\x30\x00")
    with pytest.raises(noqtis.NoqtisError):
        noqtis.ersput(gold, b"\x30\x00")


def test_seal_default_is_format_3(tmp_path):
    pk, sk = noqtis.sign.keygen("ML-DSA-44")
    for fmt, want in ((None, "noqtis-capsule-3"), (1, "noqtis-capsule-1")):
        d = tmp_path / ("f%s" % fmt)
        d.mkdir()
        (d / "a.txt").write_text("a\n")
        if fmt is None:
            noqtis.seal(d, sk, pk)
        else:
            noqtis.seal(d, sk, pk, format=fmt)
        rows = {r.check: r.detail for r in noqtis.inspect(d).rows}
        assert rows["info.format"] == want
        assert noqtis.check(d, pk).ok
