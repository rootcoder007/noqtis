// SPDX-License-Identifier: LGPL-3.0-or-later
//! The CLI's key files (docs/guides/keys.md, docs/spec/keyfile.md): a
//! header line `noqtis-key-1 <algorithm> <pub|sec>` and the key bytes as
//! padded base64 in lines of 64 characters, as `noqtis keygen` writes
//! them. A signature secret key is written as `noqtis-key-2 <algorithm>
//! sec` holding its version 2 container ([`sign::sxmake`](crate::sign::sxmake)),
//! which [`decode`] returns; a version 1 file still decodes, to the key.
//!
//! [`decode`] is as strict as the CLI's reader: the exact header, `\n` or
//! `\r\n` line ends and nothing else outside the base64 alphabet,
//! canonical padding, and the algorithm's exact key size. The base64 coder
//! has no table lookups or branches on the key bytes.
//!
//! ```
//! use noqtis::{keyfile, sign};
//!
//! let (pk, _) = sign::keygen("ML-DSA-44", None)?;
//! let t = keyfile::encode("ML-DSA-44", "pub", &pk)?;
//! assert_eq!(keyfile::decode(t.as_bytes())?.key, pk);
//! # Ok::<(), noqtis::Error>(())
//! ```

use crate::{ffi, Alg, Error, Result};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

/// The first word of a key file of version 1: a public key, a KEM secret
/// key, or a signature secret key written before 0.3.0.
pub const MAGIC: &str = "noqtis-key-1";

/// The first word of a signature secret key in the version 2 container.
pub const MAGIC2: &str = "noqtis-key-2";

/// A decoded key file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    /// The algorithm's name, as noqtis spells it.
    pub alg: String,
    /// "pub" or "sec".
    pub kind: String,
    /// The key bytes.
    pub key: Vec<u8>,
}

fn size(a: &Alg, kind: &str) -> usize {
    if kind == "pub" {
        a.pk
    } else {
        a.sk
    }
}

fn kalg(name: &str) -> Result<Alg> {
    crate::alg(name).map_err(|_| {
        Error::why(
            -8,
            format!("unknown algorithm {name:?} (the names `noqtis algs` lists)"),
        )
    })
}

// 0-25 'A'.., 26-51 'a'.., 52-61 '0'.., 62 '+', 63 '/', without branches
fn ench(x: u32) -> u8 {
    let x = x as i32;
    let mut c = x + 65;
    c += ((25 - x) >> 8) & 6;
    c -= ((51 - x) >> 8) & 75;
    c -= ((61 - x) >> 8) & 15;
    c += ((62 - x) >> 8) & 3;
    c as u8
}

// the value of a base64 character, or -1, without branches
fn dech(c: u8) -> i32 {
    let c = c as i32;
    let mut v = -1;
    // each range adds (c - base + offset + 1) when c is in it
    let r = |lo: i32, hi: i32, off: i32| -> i32 {
        let m = ((lo - 1 - c) & (c - hi - 1)) >> 8; // -1 when lo <= c <= hi
        m & (c - lo + off + 1)
    };
    v += r(65, 90, 0) + r(97, 122, 26) + r(48, 57, 52);
    v += (((42 - c) & (c - 44)) >> 8) & 63; // '+' (43): 62
    v += (((46 - c) & (c - 48)) >> 8) & 64; // '/' (47): 63
    v
}

fn b64e(k: &[u8]) -> String {
    let mut s = String::with_capacity(k.len().div_ceil(3) * 4);
    for c in k.chunks(3) {
        let n = c.len();
        let v = (c[0] as u32) << 16
            | (if n > 1 { c[1] as u32 } else { 0 }) << 8
            | if n > 2 { c[2] as u32 } else { 0 };
        s.push(ench(v >> 18) as char);
        s.push(ench((v >> 12) & 63) as char);
        s.push(if n > 1 {
            ench((v >> 6) & 63) as char
        } else {
            '='
        });
        s.push(if n > 2 { ench(v & 63) as char } else { '=' });
    }
    s
}

// strict, padded, canonical base64, or None
fn b64d(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut bad = 0i32;
    let q = s.len() / 4;
    for (i, g) in s.chunks(4).enumerate() {
        let last = i + 1 == q;
        let pad = if last {
            (g[3] == b'=') as usize + (g[2] == b'=') as usize
        } else {
            0
        };
        if pad == 1 && g[2] == b'=' {
            return None;
        }
        let mut v = 0u32;
        for (j, &c) in g.iter().enumerate() {
            let d = if j >= 4 - pad { 0 } else { dech(c) };
            bad |= d;
            v = v << 6 | (d as u32 & 63);
        }
        out.push((v >> 16) as u8);
        if pad < 2 {
            out.push((v >> 8) as u8);
        } else if v & 0xffff != 0 {
            return None;
        }
        if pad < 1 {
            out.push(v as u8);
        } else if v & 0xff != 0 {
            return None;
        }
    }
    if bad < 0 {
        return None;
    }
    Some(out)
}

/// `sk` under `passphrase` (noqtis-pwkey-1): Argon2id with `m` KiB, `t`
/// passes and `p` lanes (0 for each: 64 MiB, 3, 4) gives the key of
/// ChaCha20-Poly1305, whose associated data includes `ad`.
pub fn pwenc(passphrase: &[u8], sk: &[u8], ad: &[u8], m: u32, t: u32, p: u32) -> Result<Vec<u8>> {
    let cap = sk.len() + 51;
    let mut out = vec![0u8; cap];
    let mut n = 0usize;
    // SAFETY: the buffers are valid for the lengths passed
    crate::rc(unsafe {
        ffi::nqpwenc(
            passphrase.as_ptr(),
            passphrase.len(),
            ad.as_ptr(),
            ad.len(),
            m,
            t,
            p,
            sk.as_ptr(),
            sk.len(),
            out.as_mut_ptr(),
            cap,
            &mut n,
        )
    })?;
    out.truncate(n);
    Ok(out)
}

/// The derivation of [`pwenc`]: Argon2id.
pub const KDF_ARGON2ID: i32 = 1;
/// PBKDF2 with HMAC-SHA-256, for places whose rules ask for it.
pub const KDF_PBKDF2: i32 = 2;

/// [`pwenc`] under the derivation `kdf`: [`KDF_ARGON2ID`] with `m`, `t`
/// and `p` as there, or [`KDF_PBKDF2`] with `t` the iteration count (0:
/// 600000; 100000 to 10000000) and `m` and `p` 0. [`pwdec`] reads both.
pub fn pwenc2(
    kdf: i32,
    passphrase: &[u8],
    sk: &[u8],
    ad: &[u8],
    m: u32,
    t: u32,
    p: u32,
) -> Result<Vec<u8>> {
    let cap = sk.len() + 51;
    let mut out = vec![0u8; cap];
    let mut n = 0usize;
    // SAFETY: the buffers are valid for the lengths passed
    crate::rc(unsafe {
        ffi::nqpwenc2(
            kdf,
            passphrase.as_ptr(),
            passphrase.len(),
            ad.as_ptr(),
            ad.len(),
            m,
            t,
            p,
            sk.as_ptr(),
            sk.len(),
            out.as_mut_ptr(),
            cap,
            &mut n,
        )
    })?;
    out.truncate(n);
    Ok(out)
}

/// The key [`pwenc`] protected: [`Code::Verify`](crate::Code) for a wrong
/// passphrase or `ad`, or any changed byte; [`Code::Limit`](crate::Code)
/// for parameters over the limits (a file cannot ask for more memory or
/// time). The caller should [`wipe`](crate::wipe) the key after use.
pub fn pwdec(passphrase: &[u8], data: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    let cap = data.len().saturating_sub(51).max(1);
    let mut sk = vec![0u8; cap];
    let mut n = 0usize;
    // SAFETY: the buffers are valid for the lengths passed
    crate::rc(unsafe {
        ffi::nqpwdec(
            passphrase.as_ptr(),
            passphrase.len(),
            ad.as_ptr(),
            ad.len(),
            data.as_ptr(),
            data.len(),
            sk.as_mut_ptr(),
            cap,
            &mut n,
        )
    })?;
    sk.truncate(n);
    Ok(sk)
}

fn ad(a: &Alg, magic: &str) -> String {
    format!("{magic} {} sec", a.name)
}

/// The key file text for `key`: `kind` is "pub" or "sec".
pub fn encode(alg: &str, kind: &str, key: &[u8]) -> Result<String> {
    encodep(alg, kind, key, None)
}

/// [`encode`], with a secret key kept under `passphrase` when given (the
/// format `noqtis keygen --pass-fd` writes).
pub fn encodep(alg: &str, kind: &str, key: &[u8], passphrase: Option<&[u8]>) -> Result<String> {
    let a = kalg(alg)?;
    if kind != "pub" && kind != "sec" {
        return Err(Error::why(-1, "kind: \"pub\" or \"sec\""));
    }
    let mut magic = MAGIC;
    let mut x = Vec::new();
    let mut key = key;
    if kind == "sec" && a.kind == crate::Kind::Sign {
        // a signature secret key is written in the version 2 container:
        // the key becomes one, a container is taken once it checks
        magic = MAGIC2;
        if key.len() == a.sk {
            x = crate::sign::sxmake(&a.name, key)?;
            key = &x[..];
        } else if key.len() != crate::sign::sxsize(&a.name)? || !crate::sign::sxcheck(&a.name, key)?
        {
            return Err(Error::why(
                -1,
                format!(
                    "{} secret key: {} bytes, neither the key ({}) nor a sound container",
                    a.name,
                    key.len(),
                    a.sk
                ),
            ));
        }
    } else {
        let want = size(&a, kind);
        if key.len() != want {
            return Err(Error::why(
                -1,
                format!("{} {kind} key: {want} bytes, not {}", a.name, key.len()),
            ));
        }
    }
    let mut e = Vec::new();
    let key = match passphrase {
        None => key,
        Some(_) if kind != "sec" => {
            return Err(Error::why(-1, "a passphrase protects a secret key only"));
        }
        Some(pw) => {
            e = pwenc(pw, key, ad(&a, magic).as_bytes(), 0, 0, 0)?;
            &e[..]
        }
    };
    let b = b64e(key);
    crate::wipe(&mut e);
    crate::wipe(&mut x);
    let mut s = format!("{magic} {} {kind}\n", a.name);
    for l in b.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(l).unwrap());
        s.push('\n');
    }
    Ok(s)
}

fn notkey() -> Error {
    Error::why(
        -4,
        format!(
            "not a noqtis key file (want a first line \"{MAGIC} <alg> <pub|sec>\" or \"{MAGIC2} <alg> sec\")"
        ),
    )
}

/// The algorithm, kind and key of key file text.
pub fn decode(text: &[u8]) -> Result<Key> {
    decodep(text, None)
}

/// [`decode`], opening a secret key kept under `passphrase`.
pub fn decodep(text: &[u8], passphrase: Option<&[u8]>) -> Result<Key> {
    let nl = text.iter().position(|&c| c == b'\n').ok_or_else(notkey)?;
    if nl >= 96 {
        return Err(notkey());
    }
    let mut h = &text[..nl];
    if h.last() == Some(&b'\r') {
        h = &h[..h.len() - 1];
    }
    let h = std::str::from_utf8(h).map_err(|_| notkey())?;
    let f: Vec<&str> = h.split(' ').collect();
    let v2 = f.len() == 3 && f[0] == MAGIC2 && f[2] == "sec";
    if f.len() != 3 || (f[0] != MAGIC && !v2) || (f[2] != "pub" && f[2] != "sec") {
        return Err(notkey());
    }
    let a = kalg(f[1])?;
    if v2 && a.kind != crate::Kind::Sign {
        return Err(Error::why(
            -4,
            format!(
                "a {} key has no version 2 container (only signature keys do)",
                a.name
            ),
        ));
    }
    let want = if v2 {
        crate::sign::sxsize(&a.name)?
    } else {
        size(&a, f[2])
    };
    let magic = f[0];
    let k = decodek(&a, f[2], magic, want, &text[nl + 1..], passphrase)?;
    if v2 && !crate::sign::sxcheck(&a.name, &k.key)? {
        return Err(Error::why(
            -4,
            "the secret key is damaged: its integrity value does not match (restore the file from a copy)",
        ));
    }
    Ok(k)
}

fn decodek(
    a: &Alg,
    kind: &str,
    magic: &str,
    want: usize,
    rest: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<Key> {
    let a = a.clone();
    let f = [magic, "", kind];
    let body: Vec<u8> = rest
        .iter()
        .copied()
        .filter(|&c| c != b'\r' && c != b'\n')
        .collect();
    let prot = |k: &Vec<u8>| f[2] == "sec" && k.len() == want + 51 && k.starts_with(b"NQPW");
    match b64d(&body) {
        Some(k) if prot(&k) => match passphrase {
            None => Err(Error::why(
                -1,
                "the key is protected by a passphrase: give it to decodep or readp",
            )),
            Some(pw) => Ok(Key {
                alg: a.name.clone(),
                kind: f[2].to_string(),
                key: pwdec(pw, &k, ad(&a, f[0]).as_bytes())?,
            }),
        },
        Some(k) if k.len() == want && passphrase.is_some() && f[2] == "sec" => {
            Err(Error::why(-1, "the key is not protected by a passphrase"))
        }
        Some(k) if k.len() == want => Ok(Key {
            alg: a.name,
            kind: f[2].to_string(),
            key: k,
        }),
        _ => Err(Error::why(
            -4,
            format!(
                "the key is not {want} bytes of base64 for {} (the file is damaged or cut short)",
                a.name
            ),
        )),
    }
}

/// Reads a key file; `kind` "pub" or "sec" requires that kind.
pub fn read(file: impl AsRef<Path>, kind: Option<&str>) -> Result<Key> {
    readp(file, kind, None)
}

/// [`read`], opening a secret key kept under `passphrase`.
pub fn readp(file: impl AsRef<Path>, kind: Option<&str>, passphrase: Option<&[u8]>) -> Result<Key> {
    let p = file.as_ref();
    if !matches!(kind, None | Some("pub") | Some("sec")) {
        return Err(Error::why(-1, "kind: None, \"pub\" or \"sec\""));
    }
    let mut t = Vec::new();
    fs::File::open(p)
        .and_then(|f| f.take(1 << 20).read_to_end(&mut t))
        .map_err(|e| Error::why(-7, format!("cannot read key file {}: {e}", p.display())))?;
    let k = decodep(&t, passphrase)?;
    if let Some(want) = kind {
        if k.kind != want {
            let w = |s: &str| if s == "sec" { "secret" } else { "public" };
            return Err(Error::why(
                -1,
                format!(
                    "{} is a {} key; give the {} key",
                    p.display(),
                    w(&k.kind),
                    w(want)
                ),
            ));
        }
    }
    Ok(k)
}

/// Writes a key file. A secret key file is created owner-only (on Unix),
/// never through a link; an existing file is kept unless `force`, which
/// removes it first so the new one never inherits its permissions.
pub fn write(file: impl AsRef<Path>, alg: &str, kind: &str, key: &[u8], force: bool) -> Result<()> {
    writep(file, alg, kind, key, force, None)
}

/// [`write`], with a secret key kept under `passphrase` when given.
pub fn writep(
    file: impl AsRef<Path>,
    alg: &str,
    kind: &str,
    key: &[u8],
    force: bool,
    passphrase: Option<&[u8]>,
) -> Result<()> {
    let p = file.as_ref();
    let text = encodep(alg, kind, key, passphrase)?;
    if force {
        match fs::remove_file(p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::why(
                    -7,
                    format!("cannot replace {}: {e}", p.display()),
                ));
            }
        }
    }
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(if kind == "sec" { 0o600 } else { 0o644 });
    }
    let mut f = o.open(p).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Error::why(
                -7,
                format!("{} exists (pass force to replace it)", p.display()),
            )
        } else {
            Error::why(-7, format!("cannot write {}: {e}", p.display()))
        }
    })?;
    f.write_all(text.as_bytes())
        .map_err(|e| Error::why(-7, format!("cannot write {}: {e}", p.display())))
}
