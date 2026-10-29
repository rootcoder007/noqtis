# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""noqtis.keyfile: the CLI's key file text, both ways."""
import base64
import os
import subprocess
import sys

import pytest
from conftest import cli

import noqtis
from noqtis import keyfile

CLI = cli()


def run(*a):
    p = subprocess.run([CLI] + [str(x) for x in a], stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       check=False)
    assert p.returncode == 0, p.stderr.decode(errors="replace")


@pytest.mark.skipif(CLI is None, reason="no noqtis CLI built")
@pytest.mark.parametrize("alg", ["ML-DSA-44", "SLH-DSA-SHAKE-128f",
                                 "ML-KEM-768", "HQC-128"])
def test_cli_keys_round_trip(tmp_path, alg):
    k = tmp_path / "k"
    run("keygen", "-a", alg, "-o", k)
    for f, kind in ((k, "sec"), (str(k) + ".pub", "pub")):
        with open(str(f), "rb") as fh:
            text = fh.read()
        got = keyfile.decode(text)
        assert (got.alg, got.kind) == (alg, kind)
        # the bytes the CLI wrote, exactly
        assert keyfile.encode(alg, kind, got.key).encode() == text
        assert keyfile.read(f, kind) == got


@pytest.mark.skipif(CLI is None, reason="no noqtis CLI built")
def test_python_keys_work_in_the_cli(tmp_path):
    pk, sk = noqtis.sign.keygen("ML-DSA-65")
    keyfile.write(tmp_path / "me", "ML-DSA-65", "sec", sk)
    keyfile.write(tmp_path / "me.pub", "ML-DSA-65", "pub", pk)
    f = tmp_path / "f.txt"
    f.write_bytes(b"signed by a key Python wrote\n")
    run("sign", "-k", tmp_path / "me", "-o", tmp_path / "f.sig", f)
    assert noqtis.sign.verify("ML-DSA-65", pk, f.read_bytes(),
                              (tmp_path / "f.sig").read_bytes())


def keytext(alg="ML-DSA-44", kind="pub"):
    pk, sk = noqtis.sign.keygen(alg)
    return keyfile.encode(alg, kind, pk if kind == "pub" else sk)


def test_crlf_and_any_case():
    t = keytext()
    k = keyfile.decode(t.replace("\n", "\r\n"))
    assert k.alg == "ML-DSA-44"
    k2 = keyfile.decode(t.replace("ML-DSA-44", "ml-dsa-44", 1))
    assert k2 == k  # the name as the CLI spells it
    assert keyfile.decode(t.encode()) == k


@pytest.mark.parametrize("bad", [
    "",
    "noqtis-key-1 ML-DSA-44 pub",              # no line end
    "noqtis-key-2 ML-DSA-44 pub\nAAAA\n",      # magic
    "noqtis-key-1 ML-DSA-44 pub extra\nAAAA\n",
    "noqtis-key-1  ML-DSA-44 pub\nAAAA\n",     # two spaces
    "noqtis-key-1 ML-DSA-44 key\nAAAA\n",      # kind
    "noqtis-key-1 ML-DSA-44\nAAAA\n",
    "noqtis-key-1 ML-DSA-44 pub\nAAAA\n",      # far too short
])
def test_bad_headers_and_sizes(bad):
    with pytest.raises(noqtis.DecodeError):
        keyfile.decode(bad)


def test_unknown_algorithm():
    with pytest.raises(noqtis.UnsupportedError):
        keyfile.decode("noqtis-key-1 RSA-2048 pub\nAAAA\n")


def test_strict_base64():
    t = keytext()
    head, body = t.split("\n", 1)
    k = keyfile.decode(t).key
    # a space, a tab, a '-' or a stray '=' inside the base64
    for b in (body.replace("\n", " \n", 1), body.replace("\n", "\t\n", 1),
              body.replace("A", "-", 1), "=" + body):
        with pytest.raises(noqtis.DecodeError):
            keyfile.decode(head + "\n" + b)
    # non-canonical padding: a bit set under the '=' (ML-DSA-44's
    # 1312-byte key ends in "==")
    raw = base64.b64encode(k).decode()
    p = len(raw) - len(raw.rstrip("="))
    assert p in (1, 2)
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = raw[-p - 1]
    nc = alpha[alpha.index(last) | 1]
    assert nc != last
    with pytest.raises(noqtis.DecodeError):
        keyfile.decode(head + "\n" + raw[:-p - 1] + nc + "=" * p + "\n")
    # one byte short, one byte long
    for kk in (k[:-1], k + b"\0"):
        with pytest.raises(noqtis.DecodeError):
            keyfile.decode(head + "\n" + base64.b64encode(kk).decode() + "\n")


def test_encode_refuses():
    pk, _sk = noqtis.sign.keygen("ML-DSA-44")
    with pytest.raises(noqtis.ArgError):
        keyfile.encode("ML-DSA-44", "sec", pk)  # a public key as secret
    with pytest.raises(noqtis.ArgError):
        keyfile.encode("ML-DSA-44", "both", pk)
    with pytest.raises(noqtis.UnsupportedError):
        keyfile.encode("ML-DSA-99", "pub", pk)


def test_read_kind_and_write(tmp_path):
    _pk, sk = noqtis.sign.keygen("ML-DSA-44")
    p = tmp_path / "k"
    keyfile.write(p, "ML-DSA-44", "sec", sk)
    if sys.platform != "win32":
        assert (os.stat(str(p)).st_mode & 0o777) == 0o600
    with pytest.raises(noqtis.FileError):
        keyfile.write(p, "ML-DSA-44", "sec", sk)  # never overwritten
    keyfile.write(p, "ML-DSA-44", "sec", sk, force=True)
    assert keyfile.read(p, "sec").key == sk
    with pytest.raises(noqtis.ArgError):
        keyfile.read(p, "pub")
    with pytest.raises(noqtis.FileError):
        keyfile.read(tmp_path / "missing")
