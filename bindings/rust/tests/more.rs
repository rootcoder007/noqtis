// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! The rest of the capsule and data functions: sealwhy, timestamp
//! requests, key statements, DSSE, bundles, chains, the environment,
//! commitments, citation, report, synthetic data, calibration and chunk
//! digests, on tests/vectors/nqd.

use noqtis::{cap, data, dsse, sign, Code};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

fn vec() -> Option<PathBuf> {
    let v = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/nqd");
    if v.join("full.json").is_file() {
        Some(v)
    } else {
        eprintln!("skipped: no tests/vectors/nqd here");
        None
    }
}

fn tmp(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "nqrsm-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn cap(v: &Path) -> PathBuf {
    let d = tmp("cap").join("c");
    fs::create_dir_all(d.join("data")).unwrap();
    for f in ["data/a.csv", "data/b.csv"] {
        fs::copy(v.join("cap").join(f), d.join(f)).unwrap();
    }
    data::add(&d, &["data/a.csv", "data/b.csv"], &data::Src::default()).unwrap();
    d
}

fn key() -> (Vec<u8>, Vec<u8>) {
    sign::keygen("ML-DSA-44", None).unwrap()
}

#[test]
fn sealwhy_and_timestamps() {
    let d = tmp("why");
    fs::write(d.join("a"), b"a").unwrap();
    assert_eq!(cap::sealwhy(&d).unwrap(), None);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("a", d.join("l")).unwrap();
        let (pk, sk) = key();
        assert_eq!(
            cap::seal(&d, "ML-DSA-44", &sk, &pk, None)
                .unwrap_err()
                .kind(),
            Code::Arg
        );
        assert_eq!(
            cap::sealwhy(&d).unwrap(),
            Some((cap::Why::Link, "l".to_string()))
        );
        fs::remove_file(d.join("l")).unwrap();
    }
    let (pk, sk) = key();
    cap::seal(&d, "ML-DSA-44", &sk, &pk, None).unwrap();
    let q = cap::tsreq(&d, Some(&[1, 2])).unwrap();
    assert_eq!(q[0], 0x30);
    assert_ne!(cap::tsreq(&d, None).unwrap(), q);
    assert_eq!(cap::ersreq(&d, None, None).unwrap()[0], 0x30);
    assert!(cap::tsput(&d, &[0x30, 0], None, &[]).is_err());
    assert!(cap::ersput(&d, &[0x30, 0], None, None, &[]).is_err());
}

#[test]
fn key_statements_and_dsse() {
    let (pk, sk) = key();
    let (npk, nsk) = sign::keygen("ML-DSA-65", None).unwrap();
    let r = cap::rotate(
        "ML-DSA-44",
        &sk,
        &pk,
        "ML-DSA-65",
        &nsk,
        &npk,
        1_800_000_000,
        Some("new key"),
    )
    .unwrap();
    assert!(String::from_utf8(r).unwrap().contains("noqtis-keys-1"));
    let v = cap::revoke("ML-DSA-44", &sk, &pk, 1_800_000_000, None).unwrap();
    assert!(String::from_utf8(v).unwrap().contains("noqtis-keys-1"));
    let x = cap::expire("ML-DSA-44", &sk, &pk, 1_800_000_000, Some("yearly")).unwrap();
    assert!(String::from_utf8(x)
        .unwrap()
        .contains("\"kind\":\"expire\""));
    assert!(cap::expire("ML-DSA-44", &sk, &npk, 0, None).is_err());
    assert_eq!(
        cap::revoke("ML-DSA-44", &sk, &npk, 0, None)
            .unwrap_err()
            .kind(),
        Code::Arg
    );
    let e = dsse::sign("ML-DSA-44", &sk, &pk, "text/plain", b"hello").unwrap();
    assert_eq!(
        dsse::verify("ML-DSA-44", &pk, &e).unwrap(),
        Some(("text/plain".into(), b"hello".to_vec()))
    );
    let (opk, _) = key();
    assert_eq!(dsse::verify("ML-DSA-44", &opk, &e).unwrap(), None);
    assert_eq!(
        dsse::verify("ML-DSA-44", &pk, b"{}").unwrap_err().kind(),
        Code::Decode
    );
}

#[test]
fn bundles_and_chains() {
    let Some(v) = vec() else { return };
    let c = cap(&v);
    let (pk, sk) = key();
    cap::seal(&c, "ML-DSA-44", &sk, &pk, None).unwrap();
    let t = tmp("pack");
    data::pack(&c, t.join("a.nqb"), true).unwrap();
    data::pack(&c, t.join("b.nqb"), true).unwrap();
    assert_eq!(
        fs::read(t.join("a.nqb")).unwrap(),
        fs::read(t.join("b.nqb")).unwrap()
    );
    let o = cap::Opts {
        trust: Some(pk.clone()),
        ..Default::default()
    };
    assert!(data::checkpack(t.join("a.nqb"), &o).unwrap().ok());
    data::unpack(t.join("a.nqb"), t.join("u")).unwrap();
    assert!(cap::check(t.join("u"), &o).unwrap().ok());
    assert_eq!(
        data::unpack(t.join("a.nqb"), t.join("u"))
            .unwrap_err()
            .kind(),
        Code::Io
    );
    let b = fs::read(t.join("a.nqb")).unwrap();
    fs::write(t.join("cut.nqb"), &b[..b.len() - 10]).unwrap();
    assert_eq!(
        data::unpack(t.join("cut.nqb"), t.join("v"))
            .unwrap_err()
            .kind(),
        Code::Decode
    );
    assert!(!t.join("v").exists());
    let mut ds: Vec<PathBuf> = Vec::new();
    for i in 0..3 {
        let d = t.join(format!("l{i}"));
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("log.txt"), format!("entry {i}\n")).unwrap();
        let ins: Vec<cap::Input> = match ds.last() {
            Some(p) => vec![cap::Input {
                id: cap::capid(p).unwrap(),
                name: "prev".into(),
            }],
            None => vec![],
        };
        cap::seal2(&d, "ML-DSA-44", &sk, &pk, None, &ins).unwrap();
        ds.push(d);
    }
    let all: Vec<&Path> = ds.iter().map(|p| p.as_path()).collect();
    let (r, h) = data::chain(&all, Some(&pk), &[]).unwrap();
    assert!(r.ok());
    assert_eq!(h, Some(cap::capid(&ds[2]).unwrap()));
    let (r, h) = data::chain(&[all[0], all[2]], Some(&pk), &[]).unwrap();
    assert!(!r.ok() && h.is_none());
}

#[test]
fn env_commit_cite_report() {
    let Some(v) = vec() else { return };
    let c = cap(&v);
    fs::write(c.join("Cargo.lock"), "version = 3\n\n[[package]]\nname = \"zed\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n").unwrap();
    let e = data::env(
        &c,
        &data::Env {
            rng: Some(("ChaCha20".into(), Some("42".into()))),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        e.contains("\"language\":\"rust\"")
            && e.contains("\"name\":\"app\",\"version\":\"0.1.0\",\"source\":\"local\"")
    );
    assert!(e.contains("\"path\":\"Cargo.lock\""));
    let r = data::text(&c).unwrap();
    assert!(r.contains("\"rng\":{\"kind\":\"ChaCha20\",\"seed\":\"42\"}"));
    assert!(data::check(&c).unwrap().ok());
    #[cfg(unix)]
    {
        // a lock file is read inside the folder, never through a link
        let (l, o) = (c.join("Cargo.lock"), c.with_extension("lock"));
        fs::rename(&l, &o).unwrap();
        std::os::unix::fs::symlink(&o, &l).unwrap();
        let e = data::env(&c, &data::Env::default()).unwrap_err();
        assert!(
            e.kind() == Code::Arg && e.to_string().contains("refused"),
            "{e}"
        );
        fs::remove_file(&l).unwrap();
        fs::rename(&o, &l).unwrap();
    }
    let plan = b"arm A: 1, 4\n";
    let s = data::commit(
        &c,
        plan,
        &data::Commit {
            kind: Some("randomisation".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(data::reveal(&c, plan, &s).unwrap(), Some(0));
    assert_eq!(data::reveal(&c, b"other", &s).unwrap(), None);
    assert!(r.len() < data::text(&c).unwrap().len());
    assert!(data::text(&c)
        .unwrap()
        .contains(&data::commitment(&s, plan).unwrap()));
    assert_eq!(
        data::commitment(b"short", plan).unwrap_err().kind(),
        Code::Arg
    );
    assert_eq!(data::cite(&c, false).unwrap_err().kind(), Code::Io);
    data::put(
        &c,
        "cite",
        "{\"title\":\"T\",\"authors\":[\"A. Author\"],\"year\":2026,\"doi\":\"10.1234/x\"}",
    )
    .unwrap();
    assert!(data::cite(&c, false).unwrap().contains("title: \"T\""));
    assert!(data::cite(&c, true).unwrap().contains("doi = {10.1234/x}"));
    let (pk, sk) = key();
    cap::seal(&c, "ML-DSA-44", &sk, &pk, None).unwrap();
    let md = data::report(&c, Some(&pk), false).unwrap();
    assert!(md.starts_with('#') && md.contains("data/a.csv"));
    assert!(data::report(&c, None, true).unwrap().contains("data/a.csv"));
}

#[test]
fn synth_calibrate_chunks_schema() {
    let Some(v) = vec() else { return };
    let d = tmp("syn");
    fs::create_dir_all(d.join("data")).unwrap();
    data::put(
        &d,
        "schemas",
        &fs::read_to_string(v.join("syn/schema.json")).unwrap(),
    )
    .unwrap();
    data::synth(&d, "data/s.csv", 7, 16).unwrap();
    assert_eq!(
        fs::read(d.join("data/s.csv")).unwrap(),
        fs::read(v.join("syn/s7.csv")).unwrap()
    );
    assert!(data::check(&d).unwrap().ok());
    let c = cap(&v);
    let s = data::schema(&c, "data/a.csv", &data::Csv::default()).unwrap();
    assert!(data::checkschema(&c, &s).unwrap().ok());
    assert!(
        !data::checkschema(&c, &s.replacen("\"int\"", "\"bool\"", 1))
            .unwrap()
            .ok()
    );
    data::put(&c, "schemas", &s).unwrap();
    assert_eq!(
        data::synth(&c, "data/a.csv", 1, 0).unwrap_err().kind(),
        Code::Arg
    );
    data::pin(&c, &["data/a.csv"], &data::Csv::default()).unwrap();
    let a = c.join("data/a.csv");
    let e = data::calibrate(&c, "data/a.csv", &[a.as_path()], &data::Csv::default()).unwrap();
    assert!(e.contains("\"cal\""));
    let big: Vec<u8> = (0..5000u32).map(|i| (i % 253) as u8).collect();
    fs::write(c.join("big.bin"), &big).unwrap();
    let e = data::chunks(&c, "big.bin", 1024).unwrap();
    assert!(e.contains("\"size\":5000"));
    let p = c.join("piece");
    fs::write(&p, &big[2048..]).unwrap();
    assert!(data::piece(&c, "big.bin", &p, 2048).unwrap().ok());
    let mut bad = big[2048..].to_vec();
    bad[1100] ^= 1;
    fs::write(&p, &bad).unwrap();
    let r = data::piece(&c, "big.bin", &p, 2048).unwrap();
    assert!(!r.ok() && r.rows[0].check == "chunk");
    assert_eq!(
        data::chunks(&c, "big.bin", 10).unwrap_err().kind(),
        Code::Arg
    );
}
