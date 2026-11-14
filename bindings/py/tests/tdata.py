# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""The data layer from Python: the record, schemas, drift and diff, on
the repository's vectors (tests/vectors/nqd)."""
import os
import shutil

import pytest

from noqtis import data
from noqtis import DecodeError, FileError

from conftest import REPO

V = REPO / "tests" / "vectors" / "nqd"


@pytest.fixture
def cap(tmp_path):
    d = tmp_path / "cap"
    (d / "data").mkdir(parents=True)
    for f in ("a.csv", "b.csv"):
        shutil.copy(V / "cap" / "data" / f, d / "data" / f)
    return d


def test_record_is_the_vector(cap, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1767225600")
    data.add(cap, "data/a.csv", url="https://example.org/a.csv",
             publisher="City of Example", licence="OGL-Canada-2.0",
             retrieved="now")
    data.add(cap, "data/b.csv", synthetic=True)
    want = (V / "cap" / "noqtis.data.json").read_bytes()
    assert (cap / "noqtis.data.json").read_bytes() == want
    assert data.text(cap).encode() == want
    r = data.check(cap)
    assert r.ok and [x.check for x in r.rows] == ["record", "source",
                                                  "source"]
    assert "[synthetic]" in r.rows[2].detail


def test_refusals(cap):
    data.add(cap, "data/a.csv")
    with pytest.raises(DecodeError, match="must be one of pass, warn, fail"):
        data.put(cap, "checks", {"name": "x", "status": "maybe"})
    with pytest.raises(Exception, match="not a path a capsule holds"):
        data.add(cap, "../x")
    data.put(cap, "checks", {"name": "x", "status": "fail"})
    assert data.check(cap).rows[-1].check == "recorded"
    data.delete(cap, "checks", "x")
    assert "checks" not in data.load(cap)
    with open(cap / "data" / "a.csv", "ab") as f:
        f.write(b"4,dan,1,2024-04-01\r\n")
    r = data.check(cap)
    assert not r.ok and "SHA-256 is" in r.rows[1].detail


def test_schema(cap):
    s = data.schema(cap, "data/a.csv", put=True, ranges=True)
    assert s[0]["columns"][2] == {"max": 4, "min": 3.5, "name": "score",
                                  "nulls": True, "type": "real"}
    assert data.schemacheck(cap).ok
    with open(cap / "data" / "a.csv", "ab") as f:
        f.write(b"9,dan,9,2024-04-01\r\n")
    r = data.schemacheck(cap, ["data/a.csv"])
    assert not r.ok and any("outside its range" in x.detail for x in r.rows)


def test_drift_matches_r(tmp_path):
    d = tmp_path / "dft"
    d.mkdir()
    shutil.copy(V / "drift" / "ref.csv", d / "a.csv")
    data.pin(d, ["a.csv"])
    assert data.drift(d).level == "ok"
    r = data.drift(d, ["a.csv"], [V / "drift" / "cur.csv"], minn=1)
    assert r.level == "fail"
    ex = dict(line.split() for line in
              (V / "drift" / "expect.txt").read_text().splitlines())
    x = [row.stats for row in r.rows if row.stats and row.stats["name"] ==
         "x"][0]
    assert abs(x["ksd"] - float(ex["ks.d"])) < 1e-14
    assert abs(x["ksp"] / float(ex["ks.p"]) - 1) < 1e-9
    c = [row.stats for row in r.rows if row.stats and row.stats["name"] ==
         "c"][0]
    assert abs(c["chisqp"] / float(ex["chi.p"]) - 1) < 1e-10


def test_diff(cap, tmp_path):
    data.add(cap, "data/a.csv")
    b = tmp_path / "b"
    shutil.copytree(cap, b)
    assert data.diff(cap, b).ok
    data.add(b, "data/a.csv", url="https://example.org/a.csv")
    r = data.diff(cap, b)
    assert not r.ok and any(x.check == "source" and "url" in x.detail
                            for x in r.rows)


SRC = V / "src"
SOC = {"base": "https://data.example.org", "id": "abcd-1234",
       "kind": "socrata"}


def test_sources(cap):
    a = (V / "cap" / "data" / "a.csv").read_bytes()
    data.add(cap, "data/a.csv", url="https://example.org/a.csv")
    data.put(cap, "sources", {**data.load(cap)["sources"][0],
                              "mirrors": ["https://m.example.net/a.csv"],
                              "resolver": SOC})
    assert data.addrs(cap, "data/a.csv") == [
        ("url", "https://example.org/a.csv"),
        ("portal", "https://data.example.org/api/views/abcd-1234.json"),
        ("mirror", "https://m.example.net/a.csv")]
    assert data.verify(cap, "data/a.csv", a)
    assert not data.verify(cap, "data/a.csv", a + b"\n")
    assert data.field(cap, "sources", 0, "url") == "https://example.org/a.csv"
    assert data.field(cap, "sources", 0, "title") is None
    with pytest.raises(FileError):
        data.addrs(cap, "none.csv")


def test_resolvers():
    assert data.request(SOC) == \
        "https://data.example.org/api/views/abcd-1234.json"
    assert data.reply(SOC, (SRC / "soc.json").read_bytes()) == (
        "https://data.example.org/api/views/abcd-1234/rows.csv?"
        "accessType=DOWNLOAD", "")
    wb = {"base": "https://example.org/a.csv", "kind": "wayback"}
    assert data.reply(wb, (SRC / "wb.json").read_bytes()) == (
        "https://web.archive.org/web/20240102030405id_/https://example.org/"
        "a.csv", "2024-01-02T03:04:05Z")
    with pytest.raises(DecodeError, match="no copy"):
        data.reply(wb, (SRC / "wb-none.json").read_bytes())
    with pytest.raises(ValueError):
        data.request({"base": "https://x.org/a", "kind": "direct"})
    assert data.wayback("http://web.archive.org/web/2024/https://x.org/a") \
        == "https://web.archive.org/web/2024id_/https://x.org/a"
