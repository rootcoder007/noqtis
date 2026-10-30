# noqtis for Rust

Post-quantum signatures, key encapsulation, hashes and sealed file
capsules, from the [noqtis](https://github.com/rootcoder007/noqtis) C
library. The build script compiles the library into the crate with the
`cc` crate (a C11 compiler is all it needs); there are no other
dependencies and no bindgen.

| Family | Algorithms | Standard |
|---|---|---|
| Signatures | ML-DSA-44/65/87 | FIPS 204 |
| | SLH-DSA-SHA2 and SLH-DSA-SHAKE, 128/192/256, s and f | FIPS 205 |
| | Ed25519, and the hybrids ML-DSA-44/65/87+Ed25519 | RFC 8032 |
| KEMs | ML-KEM-512/768/1024 | FIPS 203 |
| | HQC-128/192/256 | HQC round 4 |
| Hashes | SHA-224 ... SHA-512/256, SHA3-224 ... SHA3-512, SHAKE128/256, HMAC | FIPS 180-4, FIPS 202 |

```sh
cargo add noqtis        # once it is on crates.io
cargo add noqtis --git https://github.com/rootcoder007/noqtis    # until then
```

## Signatures

`examples/sign.rs` (`cargo run --example sign`):

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

- `keygen(alg, seed)` returns `(pk, sk)`; `Some(seed)` gives the
  standard's deterministic key pair.
- `Opts` holds the context (`ctx`, at most 255 bytes), `deterministic`
  (all-zero per-signature randomness), `rnd` (that randomness given
  explicitly) and `prehash` (`Some("SHA-512")` or any name from
  `noqtis::hashes()`: HashML-DSA / HashSLH-DSA / Ed25519ph; the message
  is still the message).
- `verify` returns `Ok(false)` for a bad or malformed signature; only a
  bad argument is an `Err`.

## Key encapsulation

```rust
let (pk, sk) = noqtis::kem::keygen("ML-KEM-768", None)?;
let (ct, ss) = noqtis::kem::encap("ML-KEM-768", &pk, None)?;
assert_eq!(noqtis::kem::decap("ML-KEM-768", &sk, &ct)?, ss);
```

A tampered ciphertext decapsulates to an unrelated secret rather than an
error (implicit rejection, as FIPS 203 requires).

## Hashes and random bytes

```rust
noqtis::hash("SHA3-256", b"abc", None)?;
noqtis::hash("SHAKE256", b"abc", Some(100))?;   // 100 bytes of output
noqtis::hmac("SHA-256", b"key", b"data")?;
noqtis::random(32)?;                           // the OS CSPRNG
```

## Capsules

A capsule is a folder sealed with a manifest of every file in it
(`noqtis.json`) and a post-quantum signature over it (`noqtis.sig`), the
same files the `noqtis` command writes and checks. `examples/seal.rs`
(`cargo run --example seal`):

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

```text
check: true (22 checks)
after edit: false
FAIL file report.txt: size differs
```

- `check` returns a `Report` (`code`, `rows` of `check`, `ok`, `detail`)
  also when the capsule fails; `Report::ok()` is true only when every
  check passed. Without `trust`, the key in the seal is accepted and the
  `key` row says so. `cap::Opts` also takes TSA `anchors` (DER), `only`
  (a partial check), `lineage` (folders to find a format 2 capsule's
  inputs in) and key statements (`stmts`).
- `seal2(dir, alg, sk, pk, meta, inputs)` seals in format 2 (a Merkle
  tree over the files), recording the capsules it was made from
  (`cap::Input { id, name }`, the id from `capid`).
- `prove(dir, &["data/in.csv"])` writes a proof (noqtis-proof-1) that
  shows those files of a format 2 capsule and nothing of the others;
  `checkp(proof, &opts, dir)` checks one.
- `inspect(dir)` says what a capsule says without checking anything (the
  `info.*` rows, `Report::get("info.alg")`); `files(dir)` adds one
  `info.file` row per listed file.

## Key files

`noqtis::keyfile` reads and writes the text key files `noqtis keygen`
makes (`noqtis-key-1 <alg> <pub|sec>`, then base64), as strictly as the
command-line tool reads them:

```rust
use noqtis::keyfile;

let k = keyfile::read("me", Some("sec"))?;        // Key { alg, kind, key }
let sig = noqtis::sign::sign(&k.alg, &k.key, b"a message", &Default::default())?;

let (pk, sk) = noqtis::sign::keygen("ML-DSA-65", None)?;
keyfile::write("you", "ML-DSA-65", "sec", &sk, false)?;    // owner-only, no overwrite
keyfile::write("you.pub", "ML-DSA-65", "pub", &pk, false)?;
```

## Errors

Every failure is a `noqtis::Error`: `code()` is the library's `NQE*`
value (-1 for NQEARG, ...), `kind()` the same as a `noqtis::Code`
(`Arg`, `Buf`, `Verify`, `Decode`, `Rand`, `Mem`, `Io`, `Unsupported`,
`Limit`, `State`), `message()` the library's message (`nqerr`), and its
`Display` adds what was wrong.

## Notes

- Secret keys and shared secrets are plain `Vec<u8>`: wipe them yourself
  (with the `zeroize` crate, say) when that matters.
- Algorithms are named as `noqtis algs` lists them, in any case;
  `noqtis::algs()` has every name and size.
- `cargo package` needs the library inside the crate: run
  `sh tools/vendor.sh` first (it copies `../../src` to `vendor/`).

Licensed under Apache-2.0 WITH LLVM-exception.
