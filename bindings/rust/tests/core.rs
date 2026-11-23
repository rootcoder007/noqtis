// SPDX-License-Identifier: LGPL-3.0-or-later
//! Passphrase key files, streaming signatures and hashes, messages and
//! streams sealed to an ML-KEM key, external mu, BLAKE2b and Argon2id,
//! against the known answers of tests/vectors (pwk, kseal, kstream,
//! acvp/mu.txt, b2b, argon2) and the failures their formats name.

use noqtis::{kem, keyfile, sign, Code};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// the records of a key=value vector file, None outside the repository
fn kv(name: &str) -> Option<Vec<HashMap<String, String>>> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors")
        .join(name);
    let t = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(_) => {
            eprintln!("skipped: no {name} here");
            return None;
        }
    };
    let mut out = Vec::new();
    let mut cur = HashMap::new();
    for l in t.lines().chain(std::iter::once("")) {
        if l.starts_with('#') {
            continue;
        }
        if l.is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let (k, v) = l.split_once('=').unwrap();
        cur.insert(k.to_string(), v.to_string());
    }
    Some(out)
}

fn code<T: std::fmt::Debug>(r: noqtis::Result<T>) -> Code {
    r.unwrap_err().kind()
}

#[test]
fn pwk_known_answers_and_failures() {
    let Some(v) = kv("pwk/kat.txt") else { return };
    for r in &v {
        let (pw, ad, out) = (unhex(&r["pw"]), unhex(&r["ad"]), unhex(&r["out"]));
        assert_eq!(keyfile::pwdec(&pw, &out, &ad).unwrap(), unhex(&r["sk"]));
    }
    let r = &v[0];
    let (pw, ad, mut out) = (unhex(&r["pw"]), unhex(&r["ad"]), unhex(&r["out"]));
    assert_eq!(code(keyfile::pwdec(b"wrong", &out, &ad)), Code::Verify);
    assert_eq!(code(keyfile::pwdec(&pw, &out, b"other")), Code::Verify);
    assert_eq!(code(keyfile::pwdec(&pw, &out[..40], &ad)), Code::Decode);
    *out.last_mut().unwrap() ^= 1;
    assert_eq!(code(keyfile::pwdec(&pw, &out, &ad)), Code::Verify);
}

#[test]
fn pw_key_files() {
    let (_, sk) = sign::keygen("ML-DSA-44", None).unwrap();
    let e = keyfile::pwenc(b"pw", &sk, b"ad", 8192, 1, 1).unwrap();
    assert_eq!(e.len(), sk.len() + 51);
    assert_eq!(keyfile::pwdec(b"pw", &e, b"ad").unwrap(), sk);
    assert_eq!(code(keyfile::pwenc(b"pw", &sk, b"", 1024, 1, 1)), Code::Arg);
    let t = keyfile::encodep("ML-DSA-44", "sec", &sk, Some(b"pass")).unwrap();
    assert!(t.starts_with("noqtis-key-2 ML-DSA-44 sec\n"));
    assert_eq!(
        keyfile::decodep(t.as_bytes(), Some(b"pass")).unwrap().key,
        sign::sxmake("ML-DSA-44", &sk).unwrap()
    );
    assert_eq!(code(keyfile::decode(t.as_bytes())), Code::Arg);
    let e = keyfile::decodep(t.as_bytes(), Some(b"nope")).unwrap_err();
    assert_eq!(e.kind(), Code::Verify);
    assert!(!e.to_string().contains("pass") && !e.to_string().contains("nope"));
}

#[test]
fn streaming_equals_one_shot() {
    let msg: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    for (alg, ph, seed) in [
        ("ML-DSA-44", None, 32),
        ("ML-DSA-65", Some("SHA-512"), 32),
        ("SLH-DSA-SHA2-128f", Some("SHA-256"), 48),
        ("Ed25519", Some("SHA-512"), 32),
        ("ML-DSA-65+Ed25519", Some("SHA-512"), 64),
    ] {
        let s: Vec<u8> = (0..seed as u8).collect();
        let (pk, sk) = sign::keygen(alg, Some(&s)).unwrap();
        let o = sign::Opts {
            ctx: b"c",
            prehash: ph,
            deterministic: true,
            ..Default::default()
        };
        let want = sign::sign(alg, &sk, &msg, &o).unwrap();
        for n in [1, 7, 4096, msg.len()] {
            let mut st = sign::Signer::new(alg, &sk, &o).unwrap();
            for p in msg.chunks(n) {
                st.update(p).unwrap();
            }
            assert_eq!(st.finish(&o).unwrap(), want, "{alg} {n}");
        }
        let mut v = sign::Verifier::new(alg, &pk, &o).unwrap();
        std::io::copy(&mut &msg[..], &mut v).unwrap();
        assert!(v.finish(&want).unwrap());
        let mut v = sign::Verifier::new(alg, &pk, &o).unwrap();
        v.update(&msg[1..]).unwrap();
        assert!(!v.finish(&want).unwrap());
    }
    let (_, sk) = sign::keygen("SLH-DSA-SHA2-128f", None).unwrap();
    let o = sign::Opts::default();
    assert_eq!(
        code(sign::Signer::new("SLH-DSA-SHA2-128f", &sk, &o)),
        Code::Unsupported
    );
}

#[test]
fn hasher() {
    let msg = vec![7u8; 5000];
    for a in ["SHA-256", "SHA3-384", "SHA-512/224"] {
        let mut h = noqtis::Hasher::new(a).unwrap();
        h.write_all(&msg).unwrap();
        assert_eq!(
            h.finish(None).unwrap(),
            noqtis::hash(a, &msg, None).unwrap()
        );
    }
    let mut h = noqtis::Hasher::new("SHAKE128").unwrap();
    h.update(&msg).unwrap();
    let mut a = h.finish(Some(5)).unwrap();
    a.extend(h.finish(Some(27)).unwrap());
    assert_eq!(a, noqtis::hash("SHAKE128", &msg, Some(32)).unwrap());
}

#[test]
fn kseal_known_answers_and_failures() {
    let Some(v) = kv("kseal/kat.txt") else { return };
    for r in &v {
        let (_, sk) = kem::keygen(&r["alg"], Some(&unhex(&r["kseed"]))).unwrap();
        let m = kem::open(&r["alg"], &sk, &unhex(&r["out"]), &unhex(&r["ctx"])).unwrap();
        assert_eq!(m, unhex(&r["msg"]));
    }
    let r = v.last().unwrap();
    let (pk, sk) = kem::keygen(&r["alg"], Some(&unhex(&r["kseed"]))).unwrap();
    let mut out = unhex(&r["out"]);
    out[30] ^= 1;
    assert_eq!(
        code(kem::open(&r["alg"], &sk, &out, &unhex(&r["ctx"]))),
        Code::Verify
    );
    assert_eq!(
        code(kem::open(&r["alg"], &sk, &out[..10], b"")),
        Code::Decode
    );
    let c = kem::seal(&r["alg"], &pk, b"round", b"x").unwrap();
    assert_eq!(kem::open(&r["alg"], &sk, &c, b"x").unwrap(), b"round");
    assert_eq!(code(kem::open(&r["alg"], &sk, &c, b"y")), Code::Verify);
}

fn unboxed(r: &HashMap<String, String>, data: &[u8]) -> noqtis::Result<Vec<u8>> {
    let (_, sk) = kem::keygen(&r["alg"], Some(&unhex(&r["kseed"]))).unwrap();
    let mut o = Vec::new();
    kem::unbox(&r["alg"], &sk, &mut &data[..], &mut o, &unhex(&r["ctx"]))?;
    Ok(o)
}

#[test]
fn kstream_known_answers_and_failures() {
    let Some(v) = kv("kstream/kat.txt") else {
        return;
    };
    for r in &v {
        assert_eq!(unboxed(r, &unhex(&r["out"])).unwrap(), unhex(&r["msg"]));
    }
    let r = v.iter().max_by_key(|r| r["out"].len()).unwrap();
    let a = noqtis::alg(&r["alg"]).unwrap();
    let out = unhex(&r["out"]);
    let (h, n) = (17 + a.ct, r["chunk"].parse::<usize>().unwrap() + 16);
    let cs: Vec<&[u8]> = out[h..].chunks(n).collect();
    assert!(cs.len() >= 3);
    let join = |p: &[&[u8]]| {
        [&out[..h]]
            .iter()
            .chain(p)
            .flat_map(|x| x.iter().copied())
            .collect::<Vec<u8>>()
    };
    let mut t = out.clone();
    t[h + 5] ^= 1;
    assert_eq!(code(unboxed(r, &t)), Code::Verify);
    assert_eq!(code(unboxed(r, &join(&cs[..cs.len() - 1]))), Code::Verify);
    assert_eq!(code(unboxed(r, &out[..out.len() - 3])), Code::Verify);
    let mut sw = cs.clone();
    sw.swap(0, 1);
    assert_eq!(code(unboxed(r, &join(&sw))), Code::Verify);
    let mut x = out.clone();
    x.push(0);
    assert_eq!(code(unboxed(r, &x)), Code::Verify);
}

#[test]
fn box_round_trips() {
    let (pk, sk) = kem::keygen("ML-KEM-768", None).unwrap();
    for n in [0usize, 1, 1023, 1024, 1025, 4096, 5000] {
        let m: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        let mut e = Vec::new();
        kem::enbox("ML-KEM-768", &pk, &mut &m[..], &mut e, b"ctx", 1024).unwrap();
        let mut o = Vec::new();
        kem::unbox("ML-KEM-768", &sk, &mut &e[..], &mut o, b"ctx").unwrap();
        assert_eq!(o, m);
    }
    let mut b = kem::Boxer::new(
        "ML-KEM-512",
        &kem::keygen("ML-KEM-512", None).unwrap().0,
        b"",
        0,
    )
    .unwrap();
    assert_eq!(b.chunk(), 65536);
    assert_eq!(code(b.update(&[0u8; 5])), Code::Arg);
    assert_eq!(
        code(kem::Boxer::new("ML-KEM-512", &pk, b"", 100)),
        Code::Arg
    );
}

#[test]
fn external_mu() {
    let Some(v) = kv("acvp/mu.txt") else { return };
    for r in &v {
        let (k, mu, sig) = (unhex(&r["key"]), unhex(&r["mu"]), unhex(&r["sig"]));
        if r["kind"] == "gen" {
            let rnd = unhex(&r["rnd"]);
            let o = sign::Opts {
                rnd: Some(&rnd),
                ..Default::default()
            };
            assert_eq!(sign::signmu(&r["alg"], &k, &mu, &o).unwrap(), sig);
        } else {
            assert_eq!(
                sign::verifymu(&r["alg"], &k, &mu, &sig).unwrap(),
                r["ok"] == "1"
            );
        }
    }
    let (pk, sk) = sign::keygen("ML-DSA-65", None).unwrap();
    let o = sign::Opts {
        ctx: b"c",
        deterministic: true,
        ..Default::default()
    };
    let m = sign::mu("ML-DSA-65", &pk, b"msg", &o).unwrap();
    assert_eq!(
        sign::signmu("ML-DSA-65", &sk, &m, &o).unwrap(),
        sign::sign("ML-DSA-65", &sk, b"msg", &o).unwrap()
    );
    assert_eq!(
        code(sign::mu("Ed25519", &[0; 32], b"m", &o)),
        Code::Unsupported
    );
}

#[test]
fn pbkdf2_and_pwenc2() {
    // RFC 7914 section 11: "passwd", "salt", 1 iteration, 64 bytes
    let want = unhex(
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
         49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
    );
    assert_eq!(
        noqtis::pbkdf2("SHA-256", b"passwd", b"salt", 1, 64).unwrap(),
        want
    );
    assert_eq!(
        code(noqtis::pbkdf2("SHA-256", b"passwd", b"salt", 0, 64)),
        Code::Arg
    );
    assert_eq!(code(noqtis::pbkdf2("SHA-256", b"", b"", 1, 0)), Code::Arg);
    // a key under PBKDF2, with a key file's first line as ad, opens again
    let (_, sk) = sign::keygen("ML-DSA-44", None).unwrap();
    let ad = b"noqtis-key-1 ML-DSA-44 sec";
    let e = keyfile::pwenc2(keyfile::KDF_PBKDF2, b"pass", &sk, ad, 0, 100000, 0).unwrap();
    assert_eq!(e[5], keyfile::KDF_PBKDF2 as u8);
    assert_eq!(keyfile::pwdec(b"pass", &e, ad).unwrap(), sk);
    assert_eq!(code(keyfile::pwdec(b"wrong", &e, ad)), Code::Verify);
    assert_eq!(
        code(keyfile::pwenc2(
            keyfile::KDF_PBKDF2,
            b"pass",
            &sk,
            ad,
            0,
            99999,
            0
        )),
        Code::Arg
    );
    assert_eq!(
        code(keyfile::pwenc2(3, b"pass", &sk, ad, 0, 0, 0)),
        Code::Arg
    );
}

#[test]
fn blake2b_and_argon2id() {
    let Some(v) = kv("b2b/kat.txt") else { return };
    for r in &v {
        let h = unhex(&r["hash"]);
        assert_eq!(
            noqtis::blake2b(&unhex(&r["in"]), &unhex(&r["key"]), h.len()).unwrap(),
            h
        );
    }
    assert_eq!(code(noqtis::blake2b(b"", b"", 65)), Code::Arg);
    let mut a = kv("argon2/rfc9106.txt").unwrap();
    a.extend(kv("argon2/ossl.txt").unwrap());
    for r in a.iter().filter(|r| r["y"] == "2") {
        let c = noqtis::Cost {
            t: r["t"].parse().unwrap(),
            m: r["m"].parse().unwrap(),
            p: r["p"].parse().unwrap(),
        };
        let tag = unhex(&r["tag"]);
        let got = noqtis::argon2id(
            &unhex(&r["pw"]),
            &unhex(&r["salt"]),
            c,
            tag.len(),
            &unhex(&r["key"]),
            &unhex(&r["ad"]),
        );
        assert_eq!(got.unwrap(), tag);
    }
    assert!(
        noqtis::cteq(b"abc", b"abc") && !noqtis::cteq(b"abc", b"abd") && !noqtis::cteq(b"a", b"ab")
    );
    let mut w = vec![1u8; 9];
    noqtis::wipe(&mut w);
    assert_eq!(w, [0u8; 9]);
}

// a stream to several recipients, signed or not: each recipient opens
// it, another key does not, and the sender's key decides
#[test]
fn box_to() {
    use noqtis::sign;
    let ks: Vec<(&str, Vec<u8>, Vec<u8>)> = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
        .iter()
        .map(|a| {
            let (pk, sk) = kem::keygen(a, None).unwrap();
            (*a, pk, sk)
        })
        .collect();
    let (_, xsk) = kem::keygen("ML-KEM-768", None).unwrap();
    let (spk, ssk) = sign::keygen("ML-DSA-44", None).unwrap();
    let (opk, _) = sign::keygen("ML-DSA-44", None).unwrap();
    let rcps: Vec<(&str, &[u8])> = ks.iter().map(|k| (k.0, &k.1[..])).collect();
    for n in [0usize, 1, 1024, 1025, 5000] {
        let m: Vec<u8> = (0..n).map(|i| (i % 249) as u8).collect();
        for signed in [false, true] {
            let mut e = Vec::new();
            let snd = signed.then_some(("ML-DSA-44", &ssk[..]));
            kem::enbox_to(&rcps, snd, &mut &m[..], &mut e, b"ctx", 1024).unwrap();
            assert_eq!(&e[..4], b"NQKM");
            for k in &ks {
                let mut o = Vec::new();
                let name = kem::unbox_from(
                    k.0,
                    &k.2,
                    signed.then_some(&spk[..]),
                    &mut &e[..],
                    &mut o,
                    b"ctx",
                )
                .unwrap();
                assert_eq!(o, m);
                assert_eq!(name.as_deref(), signed.then_some("ML-DSA-44"));
            }
            let mut o = Vec::new();
            let c = |r: noqtis::Result<Option<String>>| r.unwrap_err().kind();
            assert_eq!(
                c(kem::unbox_from(
                    "ML-KEM-768",
                    &xsk,
                    None,
                    &mut &e[..],
                    &mut o,
                    b"ctx"
                )),
                Code::Verify
            );
            assert_eq!(
                c(kem::unbox_from(
                    ks[0].0,
                    &ks[0].2,
                    None,
                    &mut &e[..],
                    &mut o,
                    b""
                )),
                Code::Verify
            );
            // another sender's key; a key asked of a stream not signed
            assert_eq!(
                c(kem::unbox_from(
                    ks[1].0,
                    &ks[1].2,
                    Some(&opk),
                    &mut &e[..],
                    &mut o,
                    b"ctx"
                )),
                Code::Verify
            );
            // not asked: it opens, signed or not
            kem::unbox_from(ks[2].0, &ks[2].2, None, &mut &e[..], &mut o, b"ctx").unwrap();
            let mut b = e.clone();
            let l = b.len();
            b[l - 3] ^= 1;
            assert_eq!(
                c(kem::unbox_from(
                    ks[0].0,
                    &ks[0].2,
                    None,
                    &mut &b[..],
                    &mut o,
                    b"ctx"
                )),
                Code::Verify
            );
        }
    }
    let mut e = Vec::new();
    let no: &[(&str, &[u8])] = &[];
    assert!(kem::enbox_to(no, None, &mut &b""[..], &mut e, b"", 0).is_err());
    assert!(kem::enbox_to(
        &rcps,
        Some(("ML-DSA-44", b"")),
        &mut &b""[..],
        &mut e,
        b"",
        0
    )
    .is_err());
    assert!(kem::enbox_to(&rcps, None, &mut &b""[..], &mut e, b"", 100).is_err());
    assert!(kem::enbox_to(
        &[("ML-DSA-44", &spk[..])],
        None,
        &mut &b""[..],
        &mut e,
        b"",
        0
    )
    .is_err());
    assert_eq!(
        kem::unbox_from("ML-KEM-768", &xsk, None, &mut &b"NQKM"[..], &mut e, b"")
            .unwrap_err()
            .kind(),
        Code::Decode
    );
    assert_eq!(
        kem::unbox_from("ML-KEM-768", &xsk, None, &mut &[0u8; 40][..], &mut e, b"")
            .unwrap_err()
            .kind(),
        Code::Decode
    );
}
