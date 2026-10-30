// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! Compiles the noqtis C library into the crate: every .c file of every
//! module folder under src/ (the set CMake's src/*/*.c glob takes), from
//! the repository when the crate sits in it, else from vendor/ (a copy
//! made by tools/vendor.sh, which `cargo package` ships).

use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    let me = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let top = me.join("..").join("..");
    if top.join("include").join("noqtis.h").is_file() && top.join("src").join("core").is_dir() {
        return top;
    }
    let v = me.join("vendor");
    if !v.join("include").join("noqtis.h").is_file() {
        panic!("noqtis: vendor/ is missing and ../../src is not here (run tools/vendor.sh)");
    }
    v
}

fn sources(src: &Path) -> Vec<PathBuf> {
    let mut mods: Vec<PathBuf> = fs::read_dir(src)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    mods.sort();
    let mut out = Vec::new();
    for m in mods {
        let mut fs: Vec<PathBuf> = fs::read_dir(&m)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "c"))
            .collect();
        fs.sort();
        out.extend(fs);
    }
    out
}

fn main() {
    let top = root();
    let src = top.join("src");
    let inc = top.join("include");
    let files = sources(&src);
    let mut b = cc::Build::new();
    b.include(&inc)
        .include(&src)
        .define("NQBUILD", None)
        .warnings(false);
    if b.get_compiler().is_like_msvc() {
        b.flag_if_supported("/std:c11")
            .define("_CRT_SECURE_NO_WARNINGS", None);
    } else {
        b.flag("-std=c11").flag("-fvisibility=hidden");
    }
    // SLH-DSA signs far too slowly unoptimised: a debug build of the
    // crate still gets an optimised library
    if std::env::var("OPT_LEVEL").as_deref() == Ok("0") {
        b.opt_level(2);
    }
    b.files(&files);
    b.compile("noqtis");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // BCryptGenRandom, the CSPRNG nqrand uses on Windows
        println!("cargo:rustc-link-lib=bcrypt");
    }
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", inc.join("noqtis.h").display());
}
