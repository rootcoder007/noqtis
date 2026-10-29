# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""The binding against the noqtis CLI, when one is built (NQCLI, PATH or
the repository's build*/cli/)."""
import base64
import subprocess

import pytest
from conftest import cli

import noqtis

CLI = cli()
pytestmark = pytest.mark.skipif(CLI is None, reason="no noqtis CLI built")


def run(*a, ok=(0,)):
    p = subprocess.run([CLI] + [str(x) for x in a], stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       check=False)
    assert p.returncode in ok, p.stderr.decode(errors="replace")
    return p


def rdkey(path):
    with open(str(path), encoding="ascii") as f:
        lines = f.read().split("\n")
    assert lines[0].startswith("noqtis-key-1 ")
    return base64.b64decode("".join(lines[1:]))


@pytest.mark.parametrize("alg", ["ML-DSA-44", "SLH-DSA-SHAKE-128f",
                                 "ML-KEM-768"])
def test_keygen_seed(tmp_path, alg):
    kind = "kem" if "KEM" in alg else "sign"
    n = 64 if kind == "kem" else (32 if alg.startswith("ML") else 48)
    seed = bytes(range(n))
    k = tmp_path / "k"
    run("keygen", "-a", alg, "-o", k, "--seed", seed.hex())
    mod = noqtis.kem if kind == "kem" else noqtis.sign
    pk, sk = mod.keygen(alg, seed)
    assert rdkey(str(k) + ".pub") == pk
    assert rdkey(k) == sk


def test_sign_both_ways(tmp_path):
    k = tmp_path / "k"
    run("keygen", "-a", "ML-DSA-65", "-o", k)
    pk, sk = rdkey(str(k) + ".pub"), rdkey(k)
    f = tmp_path / "f.txt"
    f.write_bytes(b"cross check\n")
    run("sign", "-k", k, "-c", "ctx", "-o", tmp_path / "f.sig", f)
    s = (tmp_path / "f.sig").read_bytes()
    assert noqtis.sign.verify("ML-DSA-65", pk, f.read_bytes(), s, ctx=b"ctx")
    run("sign", "-k", k, "-d", "-o", tmp_path / "d.sig", f)
    assert (tmp_path / "d.sig").read_bytes() == noqtis.sign.sign(
        "ML-DSA-65", sk, f.read_bytes(), deterministic=True)
    s2 = noqtis.sign.sign("ML-DSA-65", sk, f.read_bytes(), prehash="SHA-512")
    (tmp_path / "p.sig").write_bytes(s2)
    run("verify", "-p", str(k) + ".pub", "-s", tmp_path / "p.sig", "--ph",
        "sha512", "-q", f)
    run("verify", "-p", str(k) + ".pub", "-s", tmp_path / "p.sig", "-q", f,
        ok=(1,))


def test_kem_both_ways(tmp_path):
    k = tmp_path / "k"
    run("keygen", "-a", "ML-KEM-512", "-o", k)
    pk, sk = rdkey(str(k) + ".pub"), rdkey(k)
    run("enc", "-p", str(k) + ".pub", "-o", tmp_path / "ct", tmp_path / "ss")
    ct = (tmp_path / "ct").read_bytes()
    assert noqtis.kem.decap("ML-KEM-512", sk, ct) == \
        (tmp_path / "ss").read_bytes()
    ct2, ss2 = noqtis.kem.encap("ML-KEM-512", pk)
    (tmp_path / "ct2").write_bytes(ct2)
    p = run("dec", "-k", k, "--stdout", tmp_path / "ct2")
    assert p.stdout.decode().strip() == ss2.hex()


def test_hash(tmp_path):
    f = tmp_path / "h"
    f.write_bytes(b"abc" * 1000)
    for a, cl in (("SHA-256", "sha256"), ("SHA3-512", "sha3-512"),
                  ("SHAKE256", "shake256")):
        p = run("hash", "-a", cl, f)
        assert p.stdout.decode().split()[0] == \
            noqtis.hash(a, f.read_bytes()).hex()


def test_capsule(tmp_path):
    pk, sk = noqtis.sign.keygen("ML-DSA-44")
    d = tmp_path / "cap"
    d.mkdir()
    (d / "x").write_bytes(b"1")
    noqtis.seal(d, sk, pk, meta={"by": "python"})
    run("check", d)
    (d / "x").write_bytes(b"2")
    run("check", d, ok=(1,))
