# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Passphrase key files (noqtis-pwkey-1): the known answers of
tests/vectors/pwk, round trips, the CLI's key files, and the failures."""
import base64
import subprocess

import pytest
from conftest import cli, kv

import noqtis
from noqtis import keyfile, sign

CLI = cli()
KAT = kv("pwk/kat.txt")


@pytest.mark.parametrize("v", KAT, ids=lambda v: "t%s" % v["t"])
def test_kat_opens(v):
    b = bytes.fromhex
    assert keyfile.pwdec(b(v["pw"]), b(v["out"]), b(v["ad"])) == b(v["sk"])


def test_kat_failures():
    v = KAT[0]
    b = bytes.fromhex
    out = bytearray(b(v["out"]))
    with pytest.raises(noqtis.VerifyError):
        keyfile.pwdec(b(v["pw"]) + b"x", bytes(out), b(v["ad"]))
    with pytest.raises(noqtis.VerifyError):
        keyfile.pwdec(b(v["pw"]), bytes(out), b(v["ad"]) + b"x")
    out[-1] ^= 1
    with pytest.raises(noqtis.VerifyError):
        keyfile.pwdec(b(v["pw"]), bytes(out), b(v["ad"]))
    with pytest.raises(noqtis.DecodeError):
        keyfile.pwdec(b(v["pw"]), b"NQPX" + bytes(out[4:]), b(v["ad"]))
    with pytest.raises(noqtis.DecodeError):
        keyfile.pwdec(b(v["pw"]), bytes(out[:40]), b(v["ad"]))


def test_round_trip_and_params():
    sk = bytes(range(64))
    e = keyfile.pwenc("pass", sk, b"ad", m=8192, t=1, p=1)
    assert len(e) == len(sk) + 51 and e[:4] == b"NQPW"
    assert keyfile.pwdec("pass", e, b"ad") == sk
    assert keyfile.pwenc("pass", sk, b"ad", m=8192, t=1, p=1) != e  # salt
    with pytest.raises(noqtis.ArgError):
        keyfile.pwenc("pass", sk, m=1024, t=1, p=1)  # under 8 MiB
    with pytest.raises(noqtis.ArgError):
        keyfile.pwenc("", sk)


def test_pbkdf2():
    # RFC 7914 section 11: "passwd", "salt", 1 iteration, 64 bytes
    want = bytes.fromhex(
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
    assert noqtis.pbkdf2("SHA-256", b"passwd", b"salt", 1, 64) == want
    with pytest.raises(noqtis.ArgError):
        noqtis.pbkdf2("SHA-256", b"passwd", b"salt", 0, 64)
    with pytest.raises(noqtis.ArgError):
        noqtis.pbkdf2("SHA-256", b"passwd", b"salt", 1, 0)


def test_pbkdf2_key_file():
    # a secret key file under PBKDF2, as keygen --kdf pbkdf2 writes one,
    # opens with keyfile.decode
    _, sk = sign.keygen("ML-DSA-44")
    ad = b"noqtis-key-1 ML-DSA-44 sec"
    e = keyfile.pwenc2(keyfile.KDF_PBKDF2, "pass", sk, ad, t=100000)
    assert e[:4] == b"NQPW" and e[5] == keyfile.KDF_PBKDF2
    assert keyfile.pwdec("pass", e, ad) == sk
    b = base64.b64encode(e).decode("ascii")
    txt = ad.decode("ascii") + "\n" + "".join(
        b[i:i + 64] + "\n" for i in range(0, len(b), 64))
    assert keyfile.decode(txt, "pass").key == sk
    with pytest.raises(noqtis.VerifyError):
        keyfile.decode(txt, "wrong")
    with pytest.raises(noqtis.ArgError):
        keyfile.pwenc2(keyfile.KDF_PBKDF2, "pass", sk, t=99999)
    with pytest.raises(noqtis.ArgError):
        keyfile.pwenc2(3, "pass", sk)


def test_secret_never_in_messages():
    e = keyfile.pwenc("s3cret-pass", b"K" * 32, m=8192, t=1, p=1)
    try:
        keyfile.pwdec("wrong-pass", e)
    except noqtis.VerifyError as x:
        assert "s3cret" not in str(x) and "wrong-pass" not in str(x)
    else:
        raise AssertionError("no error")


def test_key_file_text(tmp_path):
    pk, sk = sign.keygen("ML-DSA-44")
    # a signature secret key: the version 2 container, under the
    # passphrase with the rest
    x = sign.sxmake("ML-DSA-44", sk)
    t = keyfile.encode("ML-DSA-44", "sec", sk, passphrase="pw")
    assert t.startswith("noqtis-key-2 ML-DSA-44 sec\n")
    assert keyfile.decode(t, "pw").key == x
    with pytest.raises(noqtis.ArgError):
        keyfile.decode(t)
    with pytest.raises(noqtis.VerifyError):
        keyfile.decode(t, "no")
    with pytest.raises(noqtis.ArgError):
        keyfile.encode("ML-DSA-44", "pub", pk, passphrase="pw")
    f = tmp_path / "k"
    keyfile.write(f, "ML-DSA-44", "sec", sk, passphrase=b"pw")
    assert keyfile.read(f, "sec", passphrase="pw").key == x


@pytest.mark.skipif(CLI is None, reason="no noqtis CLI built")
def test_cli_reads_and_writes_them(tmp_path):
    k = tmp_path / "k"
    subprocess.run([CLI, "keygen", "-a", "ML-DSA-44", "-o", str(k),
                    "--pass-env", "NQPW"], env={"NQPW": "cli-pass"},
                   check=True, stdin=subprocess.DEVNULL)
    sk = keyfile.read(k, "sec", passphrase="cli-pass").key
    pk = keyfile.read(str(k) + ".pub").key
    msg = tmp_path / "m"
    msg.write_bytes(b"hello")
    k2 = tmp_path / "k2"
    keyfile.write(k2, "ML-DSA-44", "sec", sk, passphrase="py-pass")
    subprocess.run([CLI, "sign", "-k", str(k2), "--pass-env", "NQPW",
                    "-o", str(tmp_path / "s"), str(msg)],
                   env={"NQPW": "py-pass"}, check=True,
                   stdin=subprocess.DEVNULL)
    assert sign.verify("ML-DSA-44", pk, b"hello",
                       (tmp_path / "s").read_bytes())
