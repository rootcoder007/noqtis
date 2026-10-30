// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! The binding against known answers (NIST ACVP, RFC 8032, RFC 4231, the
//! repository's golden capsule) and round trips of every algorithm.

use noqtis::{cap, kem, keyfile, sign, Code};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn sha256(b: &[u8]) -> String {
    hex(&noqtis::hash("SHA-256", b, None).unwrap())
}

fn tmp(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "nqrs-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

// the golden capsule (tests/vectors/cap/sample), when the crate is in the
// repository: copied, so a test may change it
fn gold() -> Option<PathBuf> {
    let g = repo()
        .join("tests")
        .join("vectors")
        .join("cap")
        .join("sample");
    if !g.join("noqtis.sig").is_file() {
        return None;
    }
    let d = tmp("gold");
    for f in [
        "a.txt",
        "empty",
        "data/b.csv",
        "data/deep/c.bin",
        "noqtis.json",
        "noqtis.sig",
    ] {
        let t = d.join(f);
        fs::create_dir_all(t.parent().unwrap()).unwrap();
        fs::copy(g.join(f), t).unwrap();
    }
    Some(d)
}

const NODET: sign::Opts = sign::Opts {
    ctx: b"",
    deterministic: true,
    prehash: None,
    rnd: None,
};

#[test]
fn version_and_table() {
    assert_eq!(noqtis::version(), env!("CARGO_PKG_VERSION"));
    let a = noqtis::algs();
    let s: Vec<_> = a.iter().filter(|x| x.kind == noqtis::Kind::Sign).collect();
    let k: Vec<_> = a.iter().filter(|x| x.kind == noqtis::Kind::Kem).collect();
    assert_eq!((s.len(), k.len()), (19, 6));
    let m = noqtis::alg("ml-dsa-44").unwrap();
    assert_eq!(
        (m.name.as_str(), m.pk, m.sk, m.sig),
        ("ML-DSA-44", 1312, 2560, 2420)
    );
    let m = noqtis::alg("ML-KEM-768").unwrap();
    assert_eq!((m.pk, m.sk, m.ct, m.ss), (1184, 2400, 1088, 32));
    assert_eq!(noqtis::hashes().len(), 12);
    assert_eq!(noqtis::alg("nope").unwrap_err().kind(), Code::Unsupported);
}

#[test]
fn hashes() {
    let h = |a, d: &[u8]| hex(&noqtis::hash(a, d, None).unwrap());
    assert_eq!(
        h("SHA-256", b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(h("sha256", b"abc"), h("SHA-256", b"abc"));
    assert_eq!(
        h("SHA3-256", b"abc"),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
    assert_eq!(
        h("SHAKE128", b""),
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
    );
    assert_eq!(
        noqtis::hash("shake_256", b"x", Some(100)).unwrap().len(),
        100
    );
    assert_eq!(
        noqtis::hash("SHA-256", b"x", Some(5)).unwrap_err().kind(),
        Code::Arg
    );
    // RFC 4231 test case 2
    assert_eq!(
        hex(&noqtis::hmac("SHA-256", b"Jefe", b"what do ya want for nothing?").unwrap()),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    assert_eq!(noqtis::hash("MD5", b"", None).unwrap_err().code(), -8);
    let r = noqtis::random(32).unwrap();
    assert_eq!(r.len(), 32);
    assert_ne!(r, noqtis::random(32).unwrap());
}

#[test]
fn sign_kats() {
    // ACVP ML-DSA-keyGen-FIPS204, tcId 1 (digests of the expected keys)
    let (pk, sk) = sign::keygen(
        "ML-DSA-44",
        Some(&unhex(
            "7194b13c95231010afd2c909992bd2003ba6f437c3886bdbe3f6b867a14ba161",
        )),
    )
    .unwrap();
    assert_eq!(
        sha256(&pk),
        "838b88b6ac41e2c60698173e08ca173d0b0d2839205806e56a8a3d53195f3a03"
    );
    assert_eq!(
        sha256(&sk),
        "1c911d163cd0a5563e06f22403f7e16334fee17c2abb66f11ddf39ca6307ec58"
    );
    // ACVP SLH-DSA-keyGen-FIPS205, tcId 21
    let (pk, _) = sign::keygen(
        "SLH-DSA-SHA2-128f",
        Some(&unhex(
            "c42bcb3b5a6f331f5cce899253c6d9e29ff2b7ead7a04bab1794db8cc659c3b4\
             a868f1bd5debc12d4c9fad66aabd0a94",
        )),
    )
    .unwrap();
    assert_eq!(
        hex(&pk),
        "a868f1bd5debc12d4c9fad66aabd0a94b546df247be4c457f3d467cdfcfabd39"
    );
    // RFC 8032 section 7.1, test 1
    let (pk, sk) = sign::keygen(
        "Ed25519",
        Some(&unhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )),
    )
    .unwrap();
    assert_eq!(
        hex(&pk),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let s = sign::sign("Ed25519", &sk, b"", &sign::Opts::default()).unwrap();
    assert_eq!(
        hex(&s),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065\
         224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24\
         655141438e7a100b"
    );
    assert!(sign::verify("Ed25519", &pk, b"", &s, &sign::Opts::default()).unwrap());
}

#[test]
fn sign_round_trips() {
    for a in noqtis::algs() {
        if a.kind != noqtis::Kind::Sign || a.name.ends_with('s') {
            continue; // SLH-DSA "s" signs slowly; see sign_slow
        }
        let n = &a.name;
        let (pk, sk) = sign::keygen(n, None).unwrap();
        assert_eq!((pk.len(), sk.len()), (a.pk, a.sk), "{n}");
        let o = sign::Opts {
            ctx: b"c",
            ..sign::Opts::default()
        };
        let m = format!("noqtis rust {n}");
        let s = sign::sign(n, &sk, m.as_bytes(), &o).unwrap();
        assert_eq!(s.len(), a.sig, "{n}");
        assert!(sign::verify(n, &pk, m.as_bytes(), &s, &o).unwrap(), "{n}");
        assert!(!sign::verify(n, &pk, b"other", &s, &o).unwrap(), "{n}");
        assert!(
            !sign::verify(n, &pk, m.as_bytes(), &s, &sign::Opts::default()).unwrap(),
            "{n}"
        );
        let mut bad = s.clone();
        bad[s.len() / 2] ^= 1;
        assert!(
            !sign::verify(n, &pk, m.as_bytes(), &bad, &o).unwrap(),
            "{n}"
        );
        assert!(
            !sign::verify(n, &pk, m.as_bytes(), &s[..s.len() - 1], &o).unwrap(),
            "{n}"
        );
        // deterministic: the same bytes twice, and the explicit zero rnd
        let d1 = sign::sign(n, &sk, m.as_bytes(), &NODET).unwrap();
        assert_eq!(d1, sign::sign(n, &sk, m.as_bytes(), &NODET).unwrap(), "{n}");
        let z = vec![0u8; sign::rndlen(n).unwrap()];
        let e = sign::Opts {
            rnd: Some(&z),
            ..sign::Opts::default()
        };
        assert_eq!(d1, sign::sign(n, &sk, m.as_bytes(), &e).unwrap(), "{n}");
        // a key pair from a seed is the same twice
        let sl = if n.ends_with("+Ed25519") {
            64
        } else if n.starts_with("ML-DSA") || n == "Ed25519" {
            32
        } else {
            3 * sign::rndlen(n).unwrap()
        };
        let seed: Vec<u8> = (0..sl as u8).collect();
        assert_eq!(
            sign::keygen(n, Some(&seed)).unwrap(),
            sign::keygen(n, Some(&seed)).unwrap()
        );
        assert!(sign::keygen(n, Some(&seed[1..])).is_err(), "{n}");
    }
}

#[test]
fn sign_slow() {
    // one SLH-DSA "s" set, deterministic from a seed
    let n = "SLH-DSA-SHAKE-128s";
    let (pk, sk) = sign::keygen(n, Some(&[7u8; 48])).unwrap();
    let s = sign::sign(n, &sk, b"m", &NODET).unwrap();
    assert!(sign::verify(n, &pk, b"m", &s, &sign::Opts::default()).unwrap());
}

#[test]
fn prehash_and_errors() {
    for n in ["ML-DSA-44", "SLH-DSA-SHA2-128f", "Ed25519"] {
        let (pk, sk) = sign::keygen(n, None).unwrap();
        for h in ["SHA-256", "SHA-512", "SHAKE128"] {
            let o = sign::Opts {
                prehash: Some(h),
                ..sign::Opts::default()
            };
            match sign::sign(n, &sk, b"m", &o) {
                Ok(s) => {
                    assert!(sign::verify(n, &pk, b"m", &s, &o).unwrap(), "{n} {h}");
                    assert!(!sign::verify(n, &pk, b"m", &s, &sign::Opts::default()).unwrap());
                }
                // Ed25519ph is SHA-512 alone
                Err(e) => assert!(n == "Ed25519" && h != "SHA-512", "{n} {h}: {e}"),
            }
        }
    }
    let (pk, sk) = sign::keygen("ML-DSA-44", None).unwrap();
    let long = [0u8; 256];
    let o = sign::Opts {
        ctx: &long,
        ..sign::Opts::default()
    };
    let e = sign::sign("ML-DSA-44", &sk, b"m", &o).unwrap_err();
    assert_eq!(e.kind(), Code::Arg);
    assert_eq!(e.code(), -1);
    assert!(!e.message().is_empty());
    assert!(e.to_string().starts_with("noqtis: "));
    let e = sign::verify("ML-DSA-44", &pk[1..], b"m", b"s", &sign::Opts::default());
    assert_eq!(e.unwrap_err().kind(), Code::Decode);
    assert_eq!(
        sign::sign("ML-KEM-768", &sk, b"m", &sign::Opts::default())
            .unwrap_err()
            .kind(),
        Code::Unsupported
    );
    let both = sign::Opts {
        deterministic: true,
        rnd: Some(&[0u8; 32]),
        ..sign::Opts::default()
    };
    assert_eq!(
        sign::sign("ML-DSA-44", &sk, b"m", &both)
            .unwrap_err()
            .kind(),
        Code::Arg
    );
}

#[test]
fn kem_kats_and_round_trips() {
    // ACVP ML-KEM-keyGen-FIPS203, tcId 26 (digests of the expected keys)
    let (ek, dk) = kem::keygen(
        "ML-KEM-768",
        Some(&unhex(
            "e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0\
             1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0",
        )),
    )
    .unwrap();
    assert_eq!(
        sha256(&ek),
        "4158f6afb5e516c99f1da07da8c651348422b17c1f4e9a08ad73fb1f91249b3e"
    );
    assert_eq!(
        sha256(&dk),
        "7aab35839207f72b310abe36e2daa1cc7ff6f7fa8941e439967cd47d9b437079"
    );
    let (c1, s1) = kem::encap("ML-KEM-768", &ek, Some(&[1u8; 32])).unwrap();
    assert_eq!(
        (c1.clone(), s1.clone()),
        kem::encap("ML-KEM-768", &ek, Some(&[1u8; 32])).unwrap()
    );
    assert_eq!(kem::decap("ML-KEM-768", &dk, &c1).unwrap(), s1);
    for a in noqtis::algs() {
        if a.kind != noqtis::Kind::Kem {
            continue;
        }
        let n = &a.name;
        let (pk, sk) = kem::keygen(n, None).unwrap();
        let (ct, ss) = kem::encap(n, &pk, None).unwrap();
        assert_eq!((ct.len(), ss.len()), (a.ct, a.ss), "{n}");
        assert_eq!(kem::decap(n, &sk, &ct).unwrap(), ss, "{n}");
        // implicit rejection: another secret, the same one twice
        let mut bad = ct.clone();
        bad[0] ^= 1;
        let r = kem::decap(n, &sk, &bad).unwrap();
        assert_ne!(r, ss, "{n}");
        assert_eq!(r, kem::decap(n, &sk, &bad).unwrap(), "{n}");
        assert!(kem::decap(n, &sk, &ct[1..]).is_err(), "{n}");
        assert!(kem::encap(n, &pk[1..], None).is_err(), "{n}");
    }
}

fn files(d: &Path) {
    fs::create_dir_all(d.join("data")).unwrap();
    fs::write(d.join("a.txt"), "hello\n").unwrap();
    fs::write(d.join("data").join("b.csv"), "x,y\n1,2\n").unwrap();
}

#[test]
fn golden_capsule() {
    let Some(g) = gold() else {
        eprintln!("skipped: no tests/vectors/cap/sample here");
        return;
    };
    // tests/tcap.c: the ML-DSA-44 key from the seed 0, 1, ..., 31
    let seed: Vec<u8> = (0..32).collect();
    let (pk, _) = sign::keygen("ML-DSA-44", Some(&seed)).unwrap();
    let o = cap::Opts {
        trust: Some(pk.clone()),
        ..cap::Opts::default()
    };
    let r = cap::check(&g, &o).unwrap();
    assert!(r.ok(), "{r}");
    assert!(r
        .rows
        .iter()
        .any(|x| x.check == "file" && x.detail.contains("data/deep/c.bin")));
    assert!(cap::check(&g, &cap::Opts::default()).unwrap().ok());
    assert_eq!(
        hex(&cap::capid(&g).unwrap()),
        "0b79bb292652444787adf22b993d9926f2a9fa29a2107a18e7a56941592ee25c"
    );
    let i = cap::inspect(&g).unwrap();
    assert_eq!(i.get("info.alg").unwrap().detail, "ML-DSA-44");
    assert_eq!(i.get("info.files").unwrap().detail, "4");
    assert_eq!(i.get("info.format").unwrap().detail, "noqtis-capsule-1");
    let f = cap::files(&g).unwrap();
    assert_eq!(f.rows.iter().filter(|x| x.check == "info.file").count(), 4);
    // another key fails the key row
    let (other, _) = sign::keygen("ML-DSA-44", None).unwrap();
    let r = cap::check(
        &g,
        &cap::Opts {
            trust: Some(other),
            ..cap::Opts::default()
        },
    )
    .unwrap();
    assert!(!r.ok() && r.code == -3);
    // a changed file fails
    fs::write(g.join("a.txt"), "other\n").unwrap();
    let r = cap::check(&g, &o).unwrap();
    assert!(!r.ok());
    assert!(r.failed().iter().any(|x| x.detail.contains("a.txt")));
    fs::remove_dir_all(&g).unwrap();
}

#[test]
fn seal_and_check() {
    let d = tmp("cap1");
    files(&d);
    let (pk, sk) = sign::keygen("ML-DSA-65", None).unwrap();
    cap::seal(&d, "ML-DSA-65", &sk, &pk, Some(r#"{"project":"rust"}"#)).unwrap();
    let o = cap::Opts {
        trust: Some(pk.clone()),
        ..cap::Opts::default()
    };
    let r = cap::check(&d, &o).unwrap();
    assert!(r.ok(), "{r}");
    assert!(r.to_string().contains("ok"));
    let i = cap::inspect(&d).unwrap();
    assert_eq!(i.get("info.meta").unwrap().detail, r#"{"project":"rust"}"#);
    // only one file
    let p = cap::Opts {
        only: vec!["a.txt".into()],
        ..o.clone()
    };
    assert!(cap::check(&d, &p)
        .unwrap()
        .rows
        .iter()
        .any(|x| x.check.starts_with("partial")));
    fs::write(d.join("new.txt"), "x").unwrap();
    assert!(!cap::check(&d, &o).unwrap().ok());
    // bad meta, a missing folder, the wrong algorithm
    assert!(cap::seal(&d, "ML-DSA-65", &sk, &pk, Some("[1]")).is_err());
    assert!(cap::check(d.join("nope"), &o)
        .map(|r| !r.ok())
        .unwrap_or(true));
    assert_eq!(
        cap::seal(&d, "ML-KEM-512", &sk, &pk, None)
            .unwrap_err()
            .kind(),
        Code::Unsupported
    );
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn seal2_prove_lineage() {
    let (pk, sk) = sign::keygen("ML-DSA-44", None).unwrap();
    let a = tmp("in");
    files(&a);
    cap::seal2(&a, "ML-DSA-44", &sk, &pk, None, &[]).unwrap();
    let id = cap::capid(&a).unwrap();
    let b = tmp("out");
    files(&b);
    let inp = [cap::Input {
        id,
        name: "raw".into(),
    }];
    cap::seal2(&b, "ML-DSA-44", &sk, &pk, Some(r#"{"step":2}"#), &inp).unwrap();
    let o = cap::Opts {
        trust: Some(pk.clone()),
        lineage: vec![a.clone()],
        ..cap::Opts::default()
    };
    let r = cap::check(&b, &o).unwrap();
    assert!(r.ok(), "{r}");
    assert!(r.rows.iter().any(|x| x.check == "lineage"), "{r}");
    assert_eq!(
        cap::inspect(&b).unwrap().get("info.format").unwrap().detail,
        "noqtis-capsule-2"
    );
    // a proof of one file
    let pf = cap::prove(&b, &["data/b.csv"]).unwrap();
    assert!(pf.starts_with(b"{"));
    let o = cap::Opts {
        trust: Some(pk.clone()),
        ..cap::Opts::default()
    };
    let r = cap::checkp(&pf, &o, None).unwrap();
    assert!(r.ok(), "{r}");
    assert!(cap::checkp(&pf, &o, Some(&b)).unwrap().ok());
    let mut bad = pf.clone();
    let i = bad.len() / 2;
    bad[i] = if bad[i] == b'0' { b'1' } else { b'0' };
    assert!(cap::checkp(&bad, &o, None).map(|r| !r.ok()).unwrap_or(true));
    // a format 1 capsule has no proofs; a path it does not list
    let c = tmp("f1");
    files(&c);
    cap::seal(&c, "ML-DSA-44", &sk, &pk, None).unwrap();
    assert_eq!(
        cap::prove(&c, &["a.txt"]).unwrap_err().kind(),
        Code::Unsupported
    );
    assert_eq!(cap::prove(&b, &["nope"]).unwrap_err().kind(), Code::Io);
    for d in [a, b, c] {
        fs::remove_dir_all(d).unwrap();
    }
}

#[test]
fn key_files() {
    let (pk, sk) = sign::keygen("ML-DSA-44", None).unwrap();
    let t = keyfile::encode("ml-dsa-44", "pub", &pk).unwrap();
    assert!(t.starts_with("noqtis-key-1 ML-DSA-44 pub\n"));
    assert!(t.lines().skip(1).all(|l| l.len() <= 64));
    let k = keyfile::decode(t.as_bytes()).unwrap();
    assert_eq!(
        (k.alg.as_str(), k.kind.as_str(), &k.key),
        ("ML-DSA-44", "pub", &pk)
    );
    let crlf = t.replace('\n', "\r\n");
    assert_eq!(keyfile::decode(crlf.as_bytes()).unwrap().key, pk);
    // strict: one changed padding bit, a space, a short key, bad headers
    for bad in [
        t.replace("noqtis-key-1", "noqtis-key-2"),
        t.replace(" pub\n", " pub \n"),
        t.replace(" pub\n", " both\n"),
        t[..t.len() - 10].to_string() + "\n",
        t.replacen('A', " ", 1),
        String::new(),
    ] {
        assert!(keyfile::decode(bad.as_bytes()).is_err(), "{bad:?}");
    }
    // Ed25519 keys are 32 bytes: base64 ends "=" with two zero bits
    let (ep, _) = sign::keygen("Ed25519", None).unwrap();
    let et = keyfile::encode("Ed25519", "pub", &ep).unwrap();
    let line = et.lines().nth(1).unwrap().to_string();
    let last = line.as_bytes()[line.len() - 2];
    let al = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let v = al.iter().position(|&c| c == last).unwrap();
    assert_eq!(v % 4, 0);
    let mut l2 = line[..line.len() - 2].to_string();
    l2.push(al[v + 1] as char);
    l2.push('=');
    assert!(keyfile::decode(et.replace(&line, &l2).as_bytes()).is_err());
    assert_eq!(
        keyfile::encode("ML-DSA-44", "pub", &sk).unwrap_err().kind(),
        Code::Arg
    );
    assert_eq!(
        keyfile::encode("nope", "pub", &pk).unwrap_err().kind(),
        Code::Unsupported
    );
    // a file the CLI wrote
    let p = repo().join("tests/vectors/interop/bl/mldsa.pub");
    if p.is_file() {
        let k = keyfile::read(&p, Some("pub")).unwrap();
        assert_eq!(k.alg, "ML-DSA-65");
        assert_eq!(
            keyfile::encode(&k.alg, "pub", &k.key).unwrap().as_bytes(),
            fs::read(&p).unwrap()
        );
        assert_eq!(
            keyfile::read(&p, Some("sec")).unwrap_err().kind(),
            Code::Arg
        );
    }
    // write: no overwrite unless forced, owner-only secret keys
    let d = tmp("keys");
    let f = d.join("me");
    keyfile::write(&f, "ML-DSA-44", "sec", &sk, false).unwrap();
    assert_eq!(
        keyfile::write(&f, "ML-DSA-44", "sec", &sk, false)
            .unwrap_err()
            .kind(),
        Code::Io
    );
    keyfile::write(&f, "ML-DSA-44", "sec", &sk, true).unwrap();
    assert_eq!(keyfile::read(&f, None).unwrap().key, sk);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        keyfile::read(d.join("nope"), None).unwrap_err().kind(),
        Code::Io
    );
    fs::remove_dir_all(&d).unwrap();
}
