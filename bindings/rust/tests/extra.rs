// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! Armor, certificates, CMS and S/MIME, OpenPGP, the key store, and (with
//! NQTOKPATH naming the software token of tests/p11) keys on a token.

use noqtis::{card, kem, mail, pgp, sign, store, token::Token, Code};

const T0: i64 = 1767225600; // 2026-01-01T00:00:00Z
const YEAR: i64 = 365 * 86400;

#[test]
fn armor() {
    let data = b"some bytes \x00\x01\xff to carry as text";
    let a = mail::armor("NOQTIS TEST", data).unwrap();
    assert!(a.starts_with("-----BEGIN NOQTIS TEST-----\n"));
    let (lab, back) = mail::dearmor(&a).unwrap();
    assert_eq!(lab, "NOQTIS TEST");
    assert_eq!(back, data);
    assert_eq!(mail::dearmor("not armor").unwrap_err().kind(), Code::Decode);
    assert_eq!(
        mail::armor("lower case", data).unwrap_err().kind(),
        Code::Arg
    );
}

#[test]
fn certs_cms_smime() {
    let (pk, sk) = sign::keygen("ML-DSA-44", None).unwrap();
    let cert = mail::selfcert(
        "ML-DSA-44",
        &sk,
        &pk,
        "Ada Example",
        Some("ada@example.org"),
        T0,
        T0 + YEAR,
    )
    .unwrap();
    let ci = mail::readcert(&cert).unwrap();
    assert_eq!(ci.alg, "ML-DSA-44");
    assert!(!ci.kem && ci.ca);
    assert_eq!(ci.name, "Ada Example");
    assert_eq!(ci.email, "ada@example.org");
    assert_eq!(ci.pk, pk);
    assert_eq!(ci.not_before, T0);
    let (kpk, ksk) = kem::keygen("ML-KEM-768", None).unwrap();
    let kc = mail::kemcert("ML-DSA-44", &sk, &cert, "ML-KEM-768", &kpk, T0, T0 + YEAR).unwrap();
    let ki = mail::readcert(&kc).unwrap();
    assert!(ki.kem && ki.alg == "ML-KEM-768" && ki.name == "Ada Example");
    let msg = b"a message to sign and to seal";
    let at = Some(T0 + 3600);
    for det in [false, true] {
        let s = mail::cmssign("ML-DSA-44", &sk, &cert, msg, det, at).unwrap();
        let m = det.then_some(&msg[..]);
        let (out, who) = mail::cmsverify(&s, m, &[&cert], at).unwrap();
        assert_eq!(out, msg);
        assert_eq!(who.name, "Ada Example");
        assert_eq!(
            mail::cmsverify(&s, m, &[&kc], at).unwrap_err().kind(),
            Code::Verify
        );
    }
    let e = mail::cmsencrypt(&[&kc], msg).unwrap();
    assert_eq!(
        mail::cmsdecrypt("ML-KEM-768", &ksk, Some(&kc), &e).unwrap(),
        msg
    );
    let (_, ksk2) = kem::keygen("ML-KEM-768", None).unwrap();
    assert_eq!(
        mail::cmsdecrypt("ML-KEM-768", &ksk2, None, &e)
            .unwrap_err()
            .kind(),
        Code::Verify
    );
    let ent = "Content-Type: text/plain\r\n\r\nhello, mail\r\n";
    let sm = mail::smimesign("ML-DSA-44", &sk, &cert, ent, true, at).unwrap();
    assert!(sm.contains("multipart/signed") && sm.contains("hello, mail"));
    let (back, who) = mail::smimeverify(&sm, &[&cert], at).unwrap();
    assert_eq!(back, ent);
    assert_eq!(who.email, "ada@example.org");
    let bad = sm.replacen("hello", "jello", 1);
    assert_eq!(
        mail::smimeverify(&bad, &[&cert], at).unwrap_err().kind(),
        Code::Verify
    );
    let se = mail::smimeencrypt(&[&kc], ent).unwrap();
    assert_eq!(
        mail::smimedecrypt("ML-KEM-768", &ksk, Some(&kc), &se).unwrap(),
        ent
    );
}

#[test]
fn openpgp() {
    let pw: &[u8] = b"a passphrase";
    let (sec, cert) = pgp::generate(
        pgp::MLDSA65,
        pgp::MLKEM768,
        "Ada Example <ada@example.org>",
        Some(T0),
        Some(pw),
    )
    .unwrap();
    let k = pgp::info(&cert).unwrap();
    assert_eq!((k.alg, k.encalg), (pgp::MLDSA65, pgp::MLKEM768));
    assert!(!k.secret && k.expires.is_none() && k.encfingerprint.is_some());
    assert_eq!(k.userid, "Ada Example <ada@example.org>");
    assert_eq!(k.created, T0);
    let ks = pgp::info(&sec).unwrap();
    assert!(ks.secret && ks.locked);
    let a = pgp::armor(pgp::Armor::PublicKey, &cert).unwrap();
    assert!(a.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"));
    let (kind, back) = pgp::dearmor(&a).unwrap();
    assert_eq!(kind, pgp::Armor::PublicKey);
    assert_eq!(back, cert);
    let msg = b"signed text\nof two lines\n";
    let at = Some(T0 + 60);
    for mode in [pgp::Mode::Inline, pgp::Mode::Detached, pgp::Mode::Clear] {
        let s = pgp::sign(&sec, Some(pw), msg, mode, at).unwrap();
        let m = (mode == pgp::Mode::Detached).then_some(&msg[..]);
        let (out, when) = pgp::verify(&cert, &s, m).unwrap();
        assert_eq!(when, T0 + 60);
        if mode != pgp::Mode::Clear {
            assert_eq!(out, msg);
        }
    }
    assert_eq!(
        pgp::sign(&sec, Some(b"wrong"), msg, pgp::Mode::Inline, at)
            .unwrap_err()
            .kind(),
        Code::Verify
    );
    let e = pgp::encrypt(
        &[&cert],
        Some(b"open sesame"),
        Some((&sec, Some(pw))),
        msg,
        at,
    )
    .unwrap();
    let o = pgp::decrypt(Some(&sec), Some(pw), Some(&cert), &e).unwrap();
    assert!(o.signed && o.at == T0 + 60);
    assert_eq!(o.data, msg);
    let o = pgp::decrypt(None, Some(b"open sesame"), None, &e).unwrap();
    assert!(!o.signed);
    assert_eq!(o.data, msg);
    assert_eq!(
        pgp::decrypt(None, Some(b"open sesam"), None, &e)
            .unwrap_err()
            .kind(),
        Code::Verify
    );
}

#[test]
fn keystore() {
    let base = std::env::temp_dir().join(format!("nqrs-store-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let dir = base.join("a").to_string_lossy().into_owned();
    let dir2 = base.join("b").to_string_lossy().into_owned();
    std::fs::create_dir_all(base.join("a")).unwrap();
    std::fs::create_dir_all(base.join("b")).unwrap();
    let (pk, sk) = sign::keygen("ML-DSA-44", None).unwrap();
    let (kpk, _) = kem::keygen("ML-KEM-768", None).unwrap();
    let (pk2, _) = kem::keygen("ML-KEM-768", None).unwrap();
    let f = card::Fields {
        email: Some("me@example.org"),
        ..card::Fields::new("Me Myself")
    };
    let c = card::make("ML-DSA-44", &sk, &pk, &f, Some(T0)).unwrap();
    // my signature key by its card, my KEM key under the same name
    let me = store::add(&dir, "ML-DSA-44", &pk, None, None, Some(&c)).unwrap();
    let own = store::add(
        &dir,
        "ML-KEM-768",
        &kpk,
        Some("Me Myself"),
        Some("me@example.org"),
        None,
    )
    .unwrap();
    let bob = store::add(
        &dir,
        "ML-KEM-768",
        &pk2,
        Some("Bob Other"),
        Some("bob@example.org"),
        None,
    )
    .unwrap();
    assert_eq!(store::list(&dir, None).unwrap().len(), 3);
    let ks = store::list(&dir, Some("bob@example.org")).unwrap();
    assert!(
        ks.len() == 1 && ks[0].kem && ks[0].alg == "ML-KEM-768" && ks[0].valid == store::VALID_NONE
    );
    let (alg, got) = store::get(&dir, &bob).unwrap();
    assert_eq!(alg, "ML-KEM-768");
    assert_eq!(got, pk2);
    store::trust(&dir, &me, store::TRUST_ULTIMATE).unwrap();
    let cert = store::certify(&dir, "ML-DSA-44", &sk, &pk, &bob, Some(T0)).unwrap();
    assert!(!cert.is_empty());
    let ks = store::list(&dir, Some("bob@example.org")).unwrap();
    assert!(ks[0].valid == store::VALID_FULL && ks[0].certs == 1);
    store::certify(&dir, "ML-DSA-44", &sk, &pk, &own, Some(T0)).unwrap();
    // a bundle carries my card and my KEM key to another store
    let b = store::export(&dir, &me).unwrap();
    assert_eq!(store::export(&dir, &bob).unwrap_err().kind(), Code::Arg);
    let (fp, n) = store::import(&dir2, &b, Some("me@example.org")).unwrap();
    assert!(n == 2 && fp == me);
    assert!(store::import(&dir2, &b, Some("eve@example.org")).is_err());
    store::delete(&dir, &bob).unwrap();
    assert_eq!(store::list(&dir, None).unwrap().len(), 2);
    let u = store::url("Ada@Example.org").unwrap();
    assert!(u.starts_with("https://example.org/.well-known/noqtis/"));
    assert_eq!(store::url("no address").unwrap_err().kind(), Code::Arg);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn token() {
    assert_eq!(Token::open("nqtok").err().unwrap().kind(), Code::Arg);
    assert_eq!(
        Token::open("./no/such/module.so").err().unwrap().kind(),
        Code::Io
    );
    let Ok(module) = std::env::var("NQTOKPATH") else {
        return; // the software token is not built
    };
    let mut t = Token::open(&module).unwrap();
    let ts = t.tokens().unwrap();
    assert!(ts.len() == 1 && ts[0].label == "noqtis test token" && ts[0].login);
    assert_eq!(
        t.login(ts[0].slot, Some("0000")).unwrap_err().kind(),
        Code::Verify
    );
    t.login(ts[0].slot, Some("1234")).unwrap();
    let k = t.generate("ML-DSA-65", "rs-sig").unwrap();
    assert!(k.alg == "ML-DSA-65" && !k.kem && k.label == "rs-sig");
    let pk = t.public_key(&k).unwrap();
    let msg = b"signed on the token";
    let sig = t.sign(&k, msg, b"ctx").unwrap();
    let o = sign::Opts {
        ctx: b"ctx",
        ..sign::Opts::default()
    };
    assert!(sign::verify("ML-DSA-65", &pk, msg, &sig, &o).unwrap());
    let kk = t.generate("ML-KEM-768", "rs-kem").unwrap();
    let kpk = t.public_key(&kk).unwrap();
    let (ct, ss) = kem::encap("ML-KEM-768", &kpk, None).unwrap();
    assert_eq!(t.decap(&kk, &ct).unwrap(), ss);
    assert_eq!(
        t.generate("HQC-128", "x").unwrap_err().kind(),
        Code::Unsupported
    );
    assert!(t.keys().unwrap().len() >= 2);
}
