// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
use noqtis::{cap, sign};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // a folder with some results
    let d = std::env::temp_dir().join("noqtis-rust-demo");
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(d.join("data"))?;
    fs::write(d.join("data").join("in.csv"), "a,b\n1,2\n")?;
    fs::write(d.join("report.txt"), "r\n")?;

    // seal it, then check it with the public key pinned
    let (pk, sk) = sign::keygen("ML-DSA-65", None)?;
    cap::seal(&d, "ML-DSA-65", &sk, &pk, Some(r#"{"project":"tutorial"}"#))?;
    let o = cap::Opts {
        trust: Some(pk),
        ..cap::Opts::default()
    };
    let r = cap::check(&d, &o)?;
    println!("check: {} ({} checks)", r.ok(), r.rows.len());

    // change a file: the check fails and says why
    fs::write(d.join("report.txt"), "r\nedited\n")?;
    let r = cap::check(&d, &o)?;
    println!("after edit: {}", r.ok());
    for row in r.failed() {
        println!("FAIL {} {}", row.check, row.detail);
    }
    fs::remove_dir_all(&d)?;
    Ok(())
}
