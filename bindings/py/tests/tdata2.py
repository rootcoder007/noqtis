# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""The rest of the data layer from Python: environment, commitments,
citation, report, synthetic stand-ins, calibration, chunk digests,
bundles and chains, on the repository's vectors (tests/vectors/nqd)."""
import json
import os
import shutil

import pytest
from conftest import GOLD, REPO

import noqtis
from noqtis import data, sign

V = REPO / "tests" / "vectors" / "nqd"


@pytest.fixture
def cap(tmp_path):
    d = tmp_path / "cap"
    (d / "data").mkdir(parents=True)
    for f in ("a.csv", "b.csv"):
        shutil.copy(V / "cap" / "data" / f, d / "data" / f)
    data.add(d, ["data/a.csv", "data/b.csv"])
    return d


def test_parse():
    t = (V / "full.json").read_text()
    c = data.parse(t)
    assert data.parse(c) == c and json.loads(c) == json.loads(t)
    with pytest.raises(noqtis.DecodeError, match="format"):
        data.parse('{"format":"x"}')


def test_env(cap, monkeypatch):
    (cap / "uv.lock").write_bytes(b"lock\n")
    monkeypatch.setenv("TZ", "UTC")
    e = data.env(cap, rng="Mersenne-Twister", seed=42)
    r = data.load(cap)["env"]
    assert r == e and r["tz"] == "UTC" and r["noqtis"] == noqtis.__version__
    rt = r["runtime"]
    assert rt["language"] == "python" and rt["version"].count(".") == 2
    names = [p["name"] for p in rt["packages"]]
    assert names == sorted(names) and "noqtis" in names
    assert r["locks"] == [{"path": "uv.lock", "sha256": noqtis.hash(
        "SHA-256", b"lock\n").hex()}]
    assert r["rng"] == {"kind": "Mersenne-Twister", "seed": 42}
    assert data.check(cap).ok
    with pytest.raises(ValueError):
        data.env(cap, locks=["nope.lock"])
    with pytest.raises(ValueError):
        data.env(cap, seed=1)


def test_commit_and_reveal(cap):
    plan = b"arm A: 1, 4, 5\narm B: 2, 3, 6\n"
    salt = data.commit(cap, plan, kind="randomisation", label="trial",
                       after="2027-01-01T00:00:00Z")
    c = data.load(cap)["commits"][0]
    assert c["digest"] == data.commitment(salt, plan) and c["label"] == "trial"
    assert data.reveal(cap, plan, salt) == 0
    assert data.reveal(cap, plan + b" ", salt) is None
    assert data.reveal(cap, plan, bytes(32)) is None
    with pytest.raises(noqtis.ArgError):
        data.commitment(b"short", plan)


def test_cite(cap):
    with pytest.raises(noqtis.FileError):
        data.cite(cap)
    data.put(cap, "cite", {"title": "T", "authors": ["A. Author"],
                           "year": 2026, "doi": "10.1234/x"})
    assert 'title: "T"' in data.cite(cap)
    assert "doi = {10.1234/x}" in data.cite(cap, "bib")


def test_report(cap):
    pk, sk = sign.keygen("ML-DSA-44")
    noqtis.seal(cap, sk, pk)
    md = data.report(cap, pk=pk)
    assert md.startswith("#") and "data/a.csv" in md
    txt = data.report(cap, "txt")
    assert "data/a.csv" in txt and "|" not in txt.splitlines()[0]
    with open(cap / "data" / "a.csv", "ab") as f:
        f.write(b"x")
    assert "fail" in data.report(cap, "txt").lower()


def test_synth(tmp_path):
    d = tmp_path / "s"
    (d / "data").mkdir(parents=True)
    data.put(d, "schemas", (V / "syn" / "schema.json").read_text())
    data.synth(d, "data/s.csv", seed=7, rows=16)
    assert (d / "data" / "s.csv").read_bytes() == \
        (V / "syn" / "s7.csv").read_bytes()
    assert data.load(d)["sources"][0]["synthetic"] is True
    assert data.check(d).ok


def test_synth_never_replaces_data(cap):
    data.schema(cap, "data/a.csv", put=True)
    with pytest.raises(noqtis.ArgError):
        data.synth(cap, "data/a.csv", seed=1)


def test_calibrate(cap):
    data.pin(cap, "data/a.csv")
    e = data.calibrate(cap, "data/a.csv", [cap / "data" / "a.csv"])
    assert all("cal" in c for c in e["columns"])
    assert data.load(cap)["stats"][0] == e
    assert data.drift(cap).ok


def test_chunks_and_piece(cap, tmp_path):
    big = bytes(i % 253 for i in range(5000))
    (cap / "big.bin").write_bytes(big)
    e = data.chunks(cap, "big.bin", 1024)
    assert e["size"] == 5000 and len(e["digests"]) == 5
    p = tmp_path / "piece"
    p.write_bytes(big[2048:])
    assert data.piece(cap, "big.bin", p, 2048).ok
    p.write_bytes(big[2048:3072] + b"x" + big[3073:])
    r = data.piece(cap, "big.bin", p, 2048)
    assert not r.ok and r.rows[0].check == "chunk"
    with pytest.raises(noqtis.ArgError):
        data.chunks(cap, "big.bin", 10)


def test_checkschema(cap):
    s = data.schema(cap, "data/a.csv")[0]
    assert data.checkschema(cap, s).ok
    s["columns"][0]["type"] = "bool"
    assert not data.checkschema(cap, s).ok


def test_pack_unpack_checkpack(cap, tmp_path):
    pk, sk = sign.keygen("ML-DSA-44")
    noqtis.seal(cap, sk, pk)
    f = tmp_path / "c.nqb"
    noqtis.pack(cap, f)
    f2 = tmp_path / "c2.nqb"
    noqtis.pack(cap, f2)
    assert f.read_bytes() == f2.read_bytes()
    assert noqtis.checkpack(f, pk).ok
    noqtis.unpack(f, tmp_path / "u")
    assert noqtis.check(tmp_path / "u", pk).ok
    with pytest.raises(noqtis.FileError):
        noqtis.unpack(f, tmp_path / "u")
    b = f.read_bytes()
    (tmp_path / "cut.nqb").write_bytes(b[:-10])
    with pytest.raises(noqtis.DecodeError):
        noqtis.unpack(tmp_path / "cut.nqb", tmp_path / "v")
    assert not os.path.exists(tmp_path / "v")


def test_chain(tmp_path):
    pk, sk = sign.keygen("ML-DSA-44")
    dirs = []
    for i in range(3):
        d = tmp_path / ("l%d" % i)
        d.mkdir()
        (d / "log.txt").write_text("entry %d\n" % i)
        if dirs:
            noqtis.seal(d, sk, pk, inputs=[dirs[-1]])
        else:
            noqtis.seal(d, sk, pk, format=2)
        dirs.append(d)
    r, head = noqtis.chain(dirs, pk)
    assert r.ok and head == noqtis.capid(dirs[-1])
    r, head = noqtis.chain([dirs[0], dirs[2]], pk)
    assert not r.ok and head is None
