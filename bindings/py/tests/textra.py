# SPDX-License-Identifier: LGPL-3.0-or-later
"""Armor, certificates, CMS and S/MIME, OpenPGP, the key store, and (with
NQTOKPATH naming the software token of tests/p11) keys on a token."""
import os

import pytest

import noqtis
from noqtis import kem, mail, pgp, sign, store
from noqtis.token import Token

T0 = 1767225600  # 2026-01-01T00:00:00Z
YEAR = 365 * 86400


def test_armor():
    data = b"some bytes \x00\x01\xff to carry as text"
    a = mail.armor("NOQTIS TEST", data)
    assert a.startswith("-----BEGIN NOQTIS TEST-----\n")
    assert mail.dearmor(a) == ("NOQTIS TEST", data)
    assert mail.dearmor(a.encode()) == ("NOQTIS TEST", data)
    with pytest.raises(noqtis.DecodeError):
        mail.dearmor("not armor")
    with pytest.raises(noqtis.ArgError):
        mail.armor("lower case", data)


@pytest.fixture(scope="module")
def certs():
    pk, sk = sign.keygen("ML-DSA-44")
    cert = mail.selfcert("ML-DSA-44", sk, pk, "Ada Example",
                         "ada@example.org", notbefore=T0,
                         notafter=T0 + YEAR)
    kpk, ksk = kem.keygen("ML-KEM-768")
    kc = mail.kemcert("ML-DSA-44", sk, cert, "ML-KEM-768", kpk,
                      notbefore=T0, notafter=T0 + YEAR)
    return pk, sk, cert, kpk, ksk, kc


def test_certs(certs):
    pk, _, cert, kpk, _, kc = certs
    c = mail.readcert(cert)
    assert (c.alg, c.kem, c.ca) == ("ML-DSA-44", False, True)
    assert (c.name, c.email) == ("Ada Example", "ada@example.org")
    assert c.pk == pk and c.notbefore == T0 and len(c.fingerprint) == 32
    k = mail.readcert(kc)
    assert (k.alg, k.kem, k.name) == ("ML-KEM-768", True, "Ada Example")
    assert k.pk == kpk
    with pytest.raises(noqtis.DecodeError):
        mail.readcert(b"not a certificate")


@pytest.mark.parametrize("detached", [False, True])
def test_cms_sign(certs, detached):
    _, sk, cert, _, _, kc = certs
    msg = b"a message to sign"
    s = mail.cmssign("ML-DSA-44", sk, cert, msg, detached=detached,
                     at=T0 + 3600)
    m = msg if detached else None
    out, who = mail.cmsverify(s, [cert], msg=m, at=T0 + 3600)
    assert out == msg and who.name == "Ada Example"
    with pytest.raises(noqtis.VerifyError):
        mail.cmsverify(s, [kc], msg=m, at=T0 + 3600)
    with pytest.raises(noqtis.ArgError):
        mail.cmsverify(s, [], msg=m, at=T0 + 3600)  # nothing is trusted


def test_cms_encrypt(certs):
    _, _, _, _, ksk, kc = certs
    msg = b"a message to seal" * 100
    e = mail.cmsencrypt([kc], msg)
    assert mail.cmsdecrypt("ML-KEM-768", ksk, e, cert=kc) == msg
    assert mail.cmsdecrypt("ML-KEM-768", ksk, e) == msg
    _, other = kem.keygen("ML-KEM-768")
    with pytest.raises(noqtis.VerifyError):
        mail.cmsdecrypt("ML-KEM-768", other, e)


def test_smime(certs):
    _, sk, cert, _, ksk, kc = certs
    ent = "Content-Type: text/plain\r\n\r\nhello, mail\r\n"
    sm = mail.smimesign("ML-DSA-44", sk, cert, ent, detached=True,
                        at=T0 + 3600)
    assert "multipart/signed" in sm and "hello, mail" in sm
    back, who = mail.smimeverify(sm, [cert], at=T0 + 3600)
    assert back == ent and who.email == "ada@example.org"
    with pytest.raises(noqtis.VerifyError):
        mail.smimeverify(sm.replace("hello", "jello", 1), [cert],
                         at=T0 + 3600)
    op = mail.smimesign("ML-DSA-44", sk, cert, ent, at=T0 + 3600)
    assert "signed-data" in op
    assert mail.smimeverify(op, [cert], at=T0 + 3600)[0] == ent
    se = mail.smimeencrypt([kc], ent)
    assert mail.smimedecrypt("ML-KEM-768", ksk, se, cert=kc) == ent


def test_pgp():
    pw = "a passphrase"
    sec, cert = pgp.generate("Ada Example <ada@example.org>",
                             passphrase=pw, created=T0)
    k = pgp.info(cert)
    assert (k.alg, k.encalg) == (pgp.MLDSA65, pgp.MLKEM768)
    assert not k.secret and k.expires is None and k.created == T0
    assert k.userid == "Ada Example <ada@example.org>"
    assert len(k.fingerprint) == 32 and len(k.encfingerprint) == 32
    ks = pgp.info(sec)
    assert ks.secret and ks.locked
    a = pgp.armor(pgp.PUBLICKEY, cert)
    assert a.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")
    assert pgp.dearmor(a) == (pgp.PUBLICKEY, cert)
    msg = b"signed text\nof two lines\n"
    for mode in (pgp.INLINE, pgp.DETACHED, pgp.CLEAR):
        s = pgp.sign(sec, msg, mode, passphrase=pw, at=T0 + 60)
        v = pgp.verify(cert, s, msg if mode == pgp.DETACHED else None)
        assert v.at == T0 + 60
        if mode != pgp.CLEAR:
            assert v.data == msg
    with pytest.raises(noqtis.VerifyError):
        pgp.sign(sec, msg, passphrase="wrong")
    e = pgp.encrypt(msg, [cert], passphrase="open sesame", signer=sec,
                    signerpass=pw, at=T0 + 60)
    o = pgp.decrypt(e, sec, passphrase=pw, signer=cert)
    assert o == (msg, True, T0 + 60)
    o = pgp.decrypt(pgp.armor(pgp.MESSAGE, e), passphrase="open sesame")
    assert o.data == msg and not o.signed
    with pytest.raises(noqtis.VerifyError):
        pgp.decrypt(e, passphrase="open sesam")


def test_pgp_sign_only():
    sec, cert = pgp.generate("Sig <sig@example.org>", pgp.ED25519, None)
    assert pgp.info(cert).encalg == 0
    assert pgp.info(cert).encfingerprint is None
    with pytest.raises(noqtis.ArgError):
        pgp.encrypt(b"x", [cert])
    with pytest.raises(noqtis.UnsupportedError):
        pgp.generate("X", 99)


def test_store(tmp_path):
    d = tmp_path / "keys"
    d.mkdir()
    pk, sk = sign.keygen("ML-DSA-44")
    kpk, _ = kem.keygen("ML-KEM-768")
    pk2, _ = kem.keygen("ML-KEM-768")
    card = noqtis.idcard(sk, pk, "Me Myself", email="me@example.org", at=T0)
    # my signature key by its card, my KEM key under the same name
    me = store.add(d, "ML-DSA-44", pk, card=card)
    own = store.add(d, "ML-KEM-768", kpk, "Me Myself", "me@example.org")
    bob = store.add(d, "ML-KEM-768", pk2, "Bob Other", "bob@example.org")
    assert len(me) == 32 and len(store.keys(d)) == 3
    ks = store.keys(d, "bob@example.org")
    assert len(ks) == 1 and ks[0].kem and ks[0].alg == "ML-KEM-768"
    assert ks[0].valid == store.VALID_NONE and ks[0].fingerprint == bob
    assert store.get(d, bob) == ("ML-KEM-768", pk2)
    store.trust(d, me, store.TRUST_ULTIMATE)
    c = store.certify(d, "ML-DSA-44", sk, pk, bob, at=T0)
    assert c
    ks = store.keys(d, "bob@example.org")
    assert ks[0].valid == store.VALID_FULL and ks[0].certs == 1
    store.certify(d, "ML-DSA-44", sk, pk, own, at=T0)
    # a bundle carries my card and my KEM key to another store
    b = store.export(d, me)
    with pytest.raises(noqtis.ArgError):
        store.export(d, bob)  # a key without a card has no bundle
    d2 = tmp_path / "other"
    d2.mkdir()
    fp, n = store.imports(d2, b, "me@example.org")
    assert fp == me and n == 2
    with pytest.raises(noqtis.NoqtisError):
        store.imports(d2, b, "eve@example.org")
    store.delete(d, bob)
    assert len(store.keys(d)) == 2
    with pytest.raises(noqtis.ArgError):
        store.trust(d, b"short", store.TRUST_FULL)
    assert store.url("Ada@Example.org").startswith(
        "https://example.org/.well-known/noqtis/")
    with pytest.raises(noqtis.ArgError):
        store.url("no address")


def test_token_module():
    with pytest.raises(noqtis.ArgError):
        Token("nqtok")  # a bare name is not searched for
    with pytest.raises(noqtis.FileError):
        Token("./no/such/module.so")


def test_token():
    mod = os.environ.get("NQTOKPATH")
    if not mod:
        pytest.skip("NQTOKPATH is not set")
    with Token(mod) as t:
        ts = t.tokens()
        assert len(ts) == 1 and ts[0].label == "noqtis test token"
        assert ts[0].login
        with pytest.raises(noqtis.VerifyError):
            t.login(ts[0].slot, "0000")
        t.login(ts[0].slot, "1234")
        k = t.generate("ML-DSA-65", "py-sig")
        assert (k.alg, k.kem, k.label) == ("ML-DSA-65", False, "py-sig")
        pk = t.publickey(k)
        sig = t.sign(k, b"signed on the token", b"ctx")
        assert sign.verify("ML-DSA-65", pk, b"signed on the token", sig,
                           b"ctx")
        assert not sign.verify("ML-DSA-65", pk, b"signed on the token", sig)
        kk = t.generate("ML-KEM-768", "py-kem")
        ct, ss = kem.encap("ML-KEM-768", t.publickey(kk))
        assert t.decap(kk, ct) == ss
        with pytest.raises(noqtis.UnsupportedError):
            t.generate("HQC-128", "x")
        assert len(t.keys()) >= 2
    with pytest.raises(noqtis.StateError):
        t.tokens()  # closed
    t.close()  # twice is fine
