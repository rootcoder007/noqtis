// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! The data layer against the values the C tests check
//! (tests/nqd/tdrec.c, tdcsv.c, tddft.c on tests/vectors/nqd): a record
//! made here is the one the library made there, byte for byte.

use noqtis::data;
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
        "nqrsd-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(d.join("data")).unwrap();
    d
}

// a copy of vectors/nqd/cap (with its record when rec)
fn cap(v: &Path, rec: bool) -> PathBuf {
    let d = tmp("cap");
    let mut fs_ = vec!["data/a.csv", "data/b.csv"];
    if rec {
        fs_.push("noqtis.data.json");
    }
    for f in fs_ {
        fs::copy(v.join("cap").join(f), d.join(f)).unwrap();
    }
    d
}

// the number after "key": in the JSON text j
fn num(j: &str, key: &str) -> f64 {
    let k = format!("\"{key}\":");
    let s = &j[j.find(&k).unwrap() + k.len()..];
    let e = s.find([',', '}']).unwrap();
    s[..e].parse().unwrap()
}

// the value of key in vectors/nqd/drift/expect.txt (written by drift.R)
fn ex(v: &Path, key: &str) -> f64 {
    let t = fs::read_to_string(v.join("drift/expect.txt")).unwrap();
    let l = t
        .lines()
        .find(|l| l.split(' ').next() == Some(key))
        .unwrap();
    l.split(' ').nth(1).unwrap().parse().unwrap()
}

fn near(a: f64, b: f64, tol: f64, what: &str) {
    let e = (a - b).abs() / if b.abs() > 1e-300 { b.abs() } else { 1.0 };
    assert!(e <= tol, "{what}: {a:e}, expected {b:e}");
}

#[test]
fn record() {
    let Some(v) = vec() else { return };
    // every member, in canonical form, reads back to the same bytes
    let full = fs::read_to_string(v.join("full.json")).unwrap();
    let c = data::canon(&full).unwrap();
    assert_eq!(data::canon(&c).unwrap(), c);
    assert_eq!(data::canon("{\"format\":\"x\"}").unwrap_err().code(), -4);
    // the record the C tests check, read and checked
    let d = cap(&v, true);
    let want = fs::read_to_string(d.join("noqtis.data.json")).unwrap();
    assert_eq!(data::text(&d).unwrap(), want);
    let r = data::check(&d).unwrap();
    assert!(r.ok() && r.rows.len() >= 3, "{r:?}");
    // the same source element, made here
    let n = cap(&v, false);
    let s = data::Src {
        url: Some("https://example.org/a.csv".into()),
        publisher: Some("City of Example".into()),
        licence: Some("OGL-Canada-2.0".into()),
        retrieved: Some("2026-01-01T00:00:00Z".into()),
        ..Default::default()
    };
    data::add(&n, &["data/a.csv"], &s).unwrap();
    let e = data::key(&n, "sources", "data/a.csv").unwrap().unwrap();
    assert_eq!(Some(e), data::key(&d, "sources", "data/a.csv").unwrap());
    assert!(data::text(&n).unwrap().contains(
        "\"sha256\":\"7a1668480cde19db0b76c7a36e6fee9a82afd9937f5d03cec3dae1705ce173e2\",\"size\":89"
    ));
    assert_eq!(
        data::add(&n, &["../x"], &data::Src::default())
            .unwrap_err()
            .code(),
        -1
    );
    // put, key and del
    data::put(&n, "checks", "{\"name\":\"x\",\"status\":\"fail\"}").unwrap();
    assert!(!data::check(&n).unwrap().ok());
    assert!(data::put(&n, "checks", "{\"name\":\"x\",\"status\":\"maybe\"}").is_err());
    data::del(&n, "checks", Some("x")).unwrap();
    assert_eq!(data::key(&n, "checks", "x").unwrap(), None);
    assert!(data::check(&n).unwrap().ok());
    assert_eq!(data::text(v.join("drift")).unwrap_err().code(), -7);
}

#[test]
fn schema() {
    let Some(v) = vec() else { return };
    let d = cap(&v, true);
    let want = concat!(
        "{\"columns\":[{\"name\":\"id\",\"nulls\":false,\"type\":\"int\"},",
        "{\"name\":\"name\",\"nulls\":true,\"type\":\"text\"},",
        "{\"name\":\"score\",\"nulls\":true,\"type\":\"real\"},",
        "{\"name\":\"when\",\"nulls\":false,\"type\":\"date\"}],",
        "\"kind\":\"csv\",\"path\":\"data/a.csv\",\"rows\":{\"max\":3,",
        "\"min\":3}}"
    );
    let o = data::Csv::default();
    assert_eq!(data::schema(&d, "data/a.csv", &o).unwrap(), want);
    let r = data::Csv {
        ranges: true,
        ..Default::default()
    };
    let s = data::schema(&d, "data/a.csv", &r).unwrap();
    assert!(s.contains("\"max\":4,\"min\":3.5"));
    assert!(s.contains("\"max\":\"2024-03-01\",\"min\":\"2024-01-02\""));
    data::put(&d, "schemas", &s).unwrap();
    assert!(data::schemacheck(&d, &[]).unwrap().ok());
    fs::write(
        d.join("data/a.csv"),
        "id,name,score,when\n1,ann,9.5,2024-01-02\n",
    )
    .unwrap();
    let k = data::schemacheck(&d, &["data/a.csv"]).unwrap();
    assert!(!k.ok() && !k.rows.is_empty());
    assert_eq!(data::schema(&d, "nope.csv", &o).unwrap_err().code(), -7);
}

#[test]
fn drift() {
    let Some(v) = vec() else { return };
    let d = tmp("drift");
    fs::copy(v.join("drift/ref.csv"), d.join("ref.csv")).unwrap();
    data::pin(&d, &["ref.csv"], &data::Csv::default()).unwrap();
    // the same file has not drifted
    let r = data::drift(&d, &[], &[], &data::Csv::default(), &data::Drift::default()).unwrap();
    assert_eq!(r.level(), "ok", "{r:?}");
    let cur = vec![v.join("drift/cur.csv")];
    let r = data::drift(
        &d,
        &["ref.csv"],
        &cur,
        &data::Csv::default(),
        &data::Drift::default(),
    )
    .unwrap();
    // fewer than 1,000 values: PSI warns, never fails
    assert_eq!(r.level(), "warn", "{r:?}");
    let col = |n: &str| {
        r.rows
            .iter()
            .filter_map(|x| x.stats.clone())
            .find(|j| j.contains(&format!("\"name\":\"{n}\"")))
            .unwrap()
    };
    let x = col("x");
    near(num(&x, "ksd"), ex(&v, "ks.d"), 1e-14, "ks.d");
    near(num(&x, "ksp"), ex(&v, "ks.p"), 1e-9, "ks.p");
    near(num(&x, "psi"), ex(&v, "psi"), 1e-12, "psi");
    near(num(&x, "js"), ex(&v, "js"), 1e-12, "js");
    let c = col("c");
    near(num(&c, "chisq"), ex(&v, "chi.x2"), 1e-12, "chi.x2");
    near(num(&c, "df"), ex(&v, "chi.df"), 0.0, "chi.df");
    near(num(&c, "chisqp"), ex(&v, "chi.p"), 1e-10, "chi.p");
    near(num(&c, "psi"), ex(&v, "cat.psi"), 1e-12, "cat.psi");
    let e = data::drift(
        &d,
        &["cur.csv"],
        &[],
        &data::Csv::default(),
        &data::Drift::default(),
    );
    assert!(e.unwrap_err().to_string().contains("no summary of cur.csv"));
}

#[test]
fn diff() {
    let Some(v) = vec() else { return };
    let (a, b) = (cap(&v, true), cap(&v, true));
    let r = data::diff(&a, &b).unwrap();
    // unsealed: one passing "manifest" row says the files were not compared
    assert!(r.same() && r.rows.iter().all(|x| x.ok), "{r:?}");
    let s = data::Src {
        url: Some("https://example.org/a2.csv".into()),
        ..Default::default()
    };
    data::add(&b, &["data/a.csv"], &s).unwrap();
    let r = data::diff(&a, &b).unwrap();
    assert!(!r.same());
    assert!(
        r.rows
            .iter()
            .any(|x| x.check == "source" && !x.ok && x.detail.contains("url")),
        "{r:?}"
    );
}
