---
title: Use from Rust
description: The noqtis Rust crate - seal and check a folder, sign and verify, encapsulate and hash, with the C library compiled in.
---

The `noqtis` crate compiles the C library into itself with the `cc`
crate: it needs a C11 compiler and nothing else (no bindgen, no system
`libnoqtis`). It builds on Linux, macOS and Windows.

## Seal and check a folder

This is `examples/seal.rs` in the crate (`cargo run --example seal`):

```rust
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
```

It prints:

```text
check: true (22 checks)
after edit: false
FAIL file report.txt: size differs
```

- `cap::seal` writes `noqtis.json` and `noqtis.sig` into the folder;
  `meta` is JSON text (an object), signed with the manifest and never
  interpreted. `cap::seal2` seals in format 2, with the capsules it was
  made from.
- `cap::check` returns a `Report` also when the capsule fails:
  `ok()` is true only when every check passed, and `rows` lists every
  check. Without `trust` it accepts the key in the seal, and the `key`
  row says so.
- `cap::inspect`, `cap::capid`, `cap::prove` and `cap::checkp` do what
  `noqtis inspect`, the capsule id, `noqtis prove` and
  `noqtis check --proof` do.

## Sign and verify

This is `examples/sign.rs` (`cargo run --example sign`):

```rust
use noqtis::sign::{self, Opts};

fn main() -> noqtis::Result<()> {
    let (pk, sk) = sign::keygen("ML-DSA-65", None)?;
    let o = Opts {
        ctx: b"app-v1",
        ..Opts::default()
    };
    let sig = sign::sign("ML-DSA-65", &sk, b"the results in table 2", &o)?;
    println!("signature: {} bytes", sig.len());
    println!(
        "verify: {}",
        sign::verify("ML-DSA-65", &pk, b"the results in table 2", &sig, &o)?
    );
    println!(
        "other message: {}",
        sign::verify("ML-DSA-65", &pk, b"other", &sig, &o)?
    );
    Ok(())
}
```

```text
signature: 3309 bytes
verify: true
other message: false
```

`verify` returns `Ok(false)` for a bad signature; only a bad argument is
an `Err`. Every error is a `noqtis::Error` with the library's code
(`code()`, `kind()`) and message (`message()`, from `nqerr`).

## Identity cards

An identity card ties your signing key to who you are, signed by the
key itself; `noqtis check --card` reads it too. This is
`examples/card.rs` (`cargo run --example card`):

```rust
use noqtis::{card, sign};

fn main() -> noqtis::Result<()> {
    let (pk, sk) = sign::keygen("ML-DSA-65", None)?;
    let f = card::Fields {
        orcid: Some("https://orcid.org/0000-0002-1825-0097"),
        url: Some("https://example.org/ada"),
        ..card::Fields::new("Ada Lovelace")
    };
    let c = card::make("ML-DSA-65", &sk, &pk, &f, None)?;

    // None unless it verifies and is pk's
    if let Some(v) = card::verify(&c, Some(&pk))? {
        println!("name: {}", v.name);
        println!("orcid: {}", v.orcid.unwrap_or_default());
    }

    // a changed card does not verify; a wrong check digit is refused
    let t = String::from_utf8_lossy(&c).replace("Ada", "Eve");
    println!("changed: {:?}", card::verify(t.as_bytes(), None)?);
    let bad = card::Fields {
        orcid: Some("0000-0002-1825-0098"),
        ..card::Fields::new("Ada Lovelace")
    };
    let e = card::make("ML-DSA-65", &sk, &pk, &bad, None).unwrap_err();
    println!("refused: {:?}", e.kind());
    Ok(())
}
```

```text
name: Ada Lovelace
orcid: 0000-0002-1825-0097
changed: None
refused: Arg
```

The card holds the bare ORCID iD. It is self-signed: it shows that the
holder of the key wrote it, not that the name is true, so give the key's
SHA-256 (`key_sha256`) where people already know you, or let readers pin
your public key. `card::verify` returns `Ok(None)` for a card that does
not verify or is for another key, and an error of kind `Decode` for
input that is not a card.

## Notes

- `noqtis::kem` has `keygen`, `encap` and `decap`; `noqtis::hash`,
  `noqtis::hmac` and `noqtis::random` the rest; `noqtis::keyfile` reads
  and writes the CLI's key files.
- Secret keys are plain `Vec<u8>`: wipe them yourself when that matters.

The full API is in the crate's
[README](https://github.com/rootcoder007/noqtis/tree/main/bindings/rust#readme).
