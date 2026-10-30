// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! Identity cards: made and checked, each field refused, changed cards,
//! another key, and a card kept apart from seals.

use noqtis::{cap, card, sign, Code};
use std::fs;

const T0: i64 = 1767225600; // 2026-01-01T00:00:00Z

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn round_trip() {
    let (pk, sk) = sign::keygen("ML-DSA-44", None).unwrap();
    let f = card::Fields {
        name: "Ada Lovelace",
        orcid: Some("https://orcid.org/0000-0002-1694-233x"),
        email: Some("ada@example.org"),
        url: Some("https://example.org/ada"),
        affil: Some("AES"),
    };
    let c = card::make("ML-DSA-44", &sk, &pk, &f, Some(T0)).unwrap();
    let t = String::from_utf8(c.clone()).unwrap();
    assert!(t.contains("\"format\":\"noqtis-idcard-1\""));
    assert!(t.contains("\"orcid\":\"0000-0002-1694-233X\""));
    let v = card::verify(&c, None).unwrap().unwrap();
    assert_eq!(v.name, "Ada Lovelace");
    assert_eq!(v.orcid.as_deref(), Some("0000-0002-1694-233X"));
    assert_eq!(v.email.as_deref(), Some("ada@example.org"));
    assert_eq!(v.url.as_deref(), Some("https://example.org/ada"));
    assert_eq!(v.affil.as_deref(), Some("AES"));
    assert_eq!(v.created, "2026-01-01T00:00:00Z");
    assert_eq!(v.alg, "ML-DSA-44");
    assert_eq!(v.pk, pk);
    assert_eq!(
        v.key_sha256,
        hex(&noqtis::hash("SHA-256", &pk, None).unwrap())
    );
    assert_eq!(card::verify(&c, Some(&pk)).unwrap(), Some(v));
    let m = card::make(
        "ML-DSA-44",
        &sk,
        &pk,
        &card::Fields::new("Ad\u{e9}le"),
        None,
    )
    .unwrap();
    let m = card::verify(&m, None).unwrap().unwrap();
    assert_eq!(m.name, "Ad\u{e9}le");
    assert!(m.orcid.is_none() && m.affil.is_none());
}

#[test]
fn refusals() {
    let (pk, sk) = sign::keygen("ML-DSA-44", None).unwrap();
    let mk = |f: card::Fields| card::make("ML-DSA-44", &sk, &pk, &f, Some(T0));
    let long = "x".repeat(256);
    let bad = [
        card::Fields {
            orcid: Some("0000-0002-1825-0098"),
            ..card::Fields::new("A")
        },
        card::Fields {
            email: Some("ada"),
            ..card::Fields::new("A")
        },
        card::Fields {
            url: Some("http://example.org"),
            ..card::Fields::new("A")
        },
        card::Fields {
            affil: Some(""),
            ..card::Fields::new("A")
        },
        card::Fields::new(" A"),
        card::Fields::new("A\nB"),
        card::Fields::new("A\u{9b}B"),
        card::Fields::new(""),
        card::Fields::new(&long),
        card::Fields::new("A\0B"),
    ];
    for f in bad {
        assert_eq!(mk(f.clone()).unwrap_err().kind(), Code::Arg, "{f:?}");
    }
    assert!(mk(card::Fields::new(&long[..255])).is_ok());
    let (pk2, sk2) = sign::keygen("ML-DSA-44", None).unwrap();
    let e = card::make("ML-DSA-44", &sk2, &pk, &card::Fields::new("A"), Some(T0));
    assert_eq!(e.unwrap_err().kind(), Code::Arg);
    let (pe, se) = sign::keygen("Ed25519", None).unwrap();
    let e = card::make("Ed25519", &se, &pe, &card::Fields::new("A"), Some(T0));
    assert_eq!(e.unwrap_err().kind(), Code::Unsupported);
    let _ = (pk2, sk2);
}

#[test]
fn changed_and_other_formats() {
    let (pk, sk) = sign::keygen("ML-DSA-44", None).unwrap();
    let (pk2, _) = sign::keygen("ML-DSA-44", None).unwrap();
    let c = card::make(
        "ML-DSA-44",
        &sk,
        &pk,
        &card::Fields::new("Ada Lovelace"),
        Some(T0),
    )
    .unwrap();
    let t = String::from_utf8(c.clone()).unwrap();
    let ch = t.replace("Ada Lovelace", "Ada Lovelacf");
    assert_eq!(card::verify(ch.as_bytes(), None).unwrap(), None);
    assert_eq!(card::verify(&c, Some(&pk2)).unwrap(), None);
    let sp = format!(" {t}");
    assert_eq!(
        card::verify(sp.as_bytes(), None).unwrap_err().kind(),
        Code::Decode
    );
    assert_eq!(card::verify(b"{}", None).unwrap_err().kind(), Code::Decode);
    let big = vec![b'['; 256 * 1024 + 1];
    assert_eq!(card::verify(&big, None).unwrap_err().kind(), Code::Limit);
    let d = std::env::temp_dir().join(format!("nqrs-card-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join("a.txt"), "a\n").unwrap();
    cap::seal(&d, "ML-DSA-44", &sk, &pk, None).unwrap();
    let s = fs::read(d.join("noqtis.sig")).unwrap();
    assert_eq!(card::verify(&s, None).unwrap_err().kind(), Code::Decode);
    fs::write(d.join("noqtis.sig"), &c).unwrap();
    let o = cap::Opts {
        trust: Some(pk.clone()),
        ..cap::Opts::default()
    };
    assert!(!cap::check(&d, &o).unwrap().ok());
    fs::remove_dir_all(&d).unwrap();
}
