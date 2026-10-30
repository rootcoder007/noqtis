// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! noqtis: post-quantum signatures, KEMs, hashes and sealed file capsules.
//!
//! The Rust binding of the noqtis C library (FIPS 203, 204, 205, 202,
//! 180-4, RFC 8032 and HQC), compiled into the crate by its build script;
//! no other dependencies.
//!
//! ```
//! use noqtis::sign;
//!
//! let (pk, sk) = sign::keygen("ML-DSA-65", None)?;
//! let sig = sign::sign("ML-DSA-65", &sk, b"data", &sign::Opts::default())?;
//! assert!(sign::verify("ML-DSA-65", &pk, b"data", &sig, &sign::Opts::default())?);
//! # Ok::<(), noqtis::Error>(())
//! ```
#![deny(missing_docs)]

use std::ffi::CStr;
use std::fmt;
use std::os::raw::c_int;
use std::sync::OnceLock;

mod ffi;

pub mod cap;
pub mod kem;
pub mod keyfile;
pub mod sign;

/// What went wrong, one per `NQE*` code of noqtis.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Code {
    /// An argument is out of range or NULL (NQEARG).
    Arg,
    /// An output buffer is too small (NQEBUF).
    Buf,
    /// A signature, MAC or digest does not verify (NQEVRFY).
    Verify,
    /// Input is not in the encoding the standard defines (NQEDEC).
    Decode,
    /// The operating system's random source failed (NQERNG).
    Rand,
    /// An allocation failed (NQEMEM).
    Mem,
    /// A file could not be read or written (NQEIO).
    Io,
    /// An algorithm or option noqtis does not provide (NQENOSUP).
    Unsupported,
    /// Input exceeds a size or depth limit (NQELIM).
    Limit,
    /// A context was used out of order (NQESTATE).
    State,
    /// A code this crate does not know.
    Other,
}

impl Code {
    fn of(c: i32) -> Code {
        match c {
            -1 => Code::Arg,
            -2 => Code::Buf,
            -3 => Code::Verify,
            -4 => Code::Decode,
            -5 => Code::Rand,
            -6 => Code::Mem,
            -7 => Code::Io,
            -8 => Code::Unsupported,
            -9 => Code::Limit,
            -10 => Code::State,
            _ => Code::Other,
        }
    }
}

/// A failed noqtis call: the library's `NQE*` code, its message
/// (`nqerr`) and, for a check this crate makes, what was wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    code: i32,
    msg: String,
    why: String,
}

impl Error {
    pub(crate) fn new(code: c_int) -> Error {
        Error {
            code,
            msg: errmsg(code),
            why: String::new(),
        }
    }

    pub(crate) fn why(code: c_int, why: impl Into<String>) -> Error {
        Error {
            code,
            msg: errmsg(code),
            why: why.into(),
        }
    }

    /// The `NQE*` code, a negative number (-1 for NQEARG, ...).
    pub fn code(&self) -> i32 {
        self.code
    }

    /// The code as a [`Code`].
    pub fn kind(&self) -> Code {
        Code::of(self.code)
    }

    /// The library's message for the code (`nqerr`).
    pub fn message(&self) -> &str {
        &self.msg
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.why.is_empty() {
            write!(f, "noqtis: {}", self.msg)
        } else {
            write!(f, "noqtis: {}: {}", self.msg, self.why)
        }
    }
}

impl std::error::Error for Error {}

/// The result of every fallible call.
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn rc(code: c_int) -> Result<()> {
    if code == ffi::NQOK {
        Ok(())
    } else {
        Err(Error::new(code))
    }
}

fn cstr(p: *const std::os::raw::c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the library returns NUL-terminated static or report strings
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// The library's message for an `NQE*` code (`nqerr`).
pub fn errmsg(code: i32) -> String {
    // SAFETY: nqerr returns a static string for any code
    cstr(unsafe { ffi::nqerr(code) })
}

/// The library's version, "0.1.1".
pub fn version() -> String {
    // SAFETY: a static string
    cstr(unsafe { ffi::nqver() })
}

/// Signature or KEM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A signature algorithm (the `sign` module).
    Sign,
    /// A key encapsulation mechanism (the `kem` module).
    Kem,
}

/// One algorithm and its sizes in bytes; `sig` is 0 for a KEM, `ct` and
/// `ss` are 0 for a signature algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Alg {
    /// "ML-DSA-65", "ML-KEM-768", ...
    pub name: String,
    /// Signature or KEM.
    pub kind: Kind,
    /// The library's nqsalg or nqkalg value.
    pub id: i32,
    /// Public key.
    pub pk: usize,
    /// Secret key.
    pub sk: usize,
    /// Signature (at most; SLH-DSA and ML-DSA signatures are this size).
    pub sig: usize,
    /// Ciphertext.
    pub ct: usize,
    /// Shared secret.
    pub ss: usize,
}

fn table() -> &'static [Alg] {
    static T: OnceLock<Vec<Alg>> = OnceLock::new();
    T.get_or_init(|| {
        let mut v = Vec::new();
        for i in 1..64 {
            let mut z = ffi::Ssz::default();
            // SAFETY: z is a valid out struct; an unknown id is an error
            if unsafe { ffi::nqssize(i, &mut z) } == ffi::NQOK {
                v.push(Alg {
                    name: cstr(unsafe { ffi::nqsname(i) }),
                    kind: Kind::Sign,
                    id: i,
                    pk: z.pk,
                    sk: z.sk,
                    sig: z.sig,
                    ct: 0,
                    ss: 0,
                });
            }
        }
        for i in 1..64 {
            let mut z = ffi::Ksz::default();
            // SAFETY: as above
            if unsafe { ffi::nqksize(i, &mut z) } == ffi::NQOK {
                v.push(Alg {
                    name: cstr(unsafe { ffi::nqkname(i) }),
                    kind: Kind::Kem,
                    id: i,
                    pk: z.pk,
                    sk: z.sk,
                    sig: 0,
                    ct: z.ct,
                    ss: z.ss,
                });
            }
        }
        v
    })
}

/// Every algorithm with its sizes, the signature algorithms first.
pub fn algs() -> Vec<Alg> {
    table().to_vec()
}

/// The algorithm of a name (any case), of any kind.
pub fn alg(name: &str) -> Result<Alg> {
    table()
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case(name))
        .cloned()
        .ok_or_else(|| Error::why(-8, format!("unknown algorithm {name:?}")))
}

pub(crate) fn find(name: &str, kind: Kind) -> Result<&'static Alg> {
    let a = table()
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| Error::why(-8, format!("unknown algorithm {name:?}")))?;
    if a.kind != kind {
        let what = if kind == Kind::Sign {
            "signature"
        } else {
            "KEM"
        };
        return Err(Error::why(
            -8,
            format!("{} is not a {what} algorithm", a.name),
        ));
    }
    Ok(a)
}

const HNAMES: [&str; 12] = [
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA-512/224",
    "SHA-512/256",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "SHAKE128",
    "SHAKE256",
];

/// The hash names [`hash`], [`hmac`] and the pre-hash option take.
pub fn hashes() -> Vec<&'static str> {
    HNAMES.to_vec()
}

fn hkey(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '-' | '/' | '_'))
        .collect::<String>()
        .to_ascii_lowercase()
}

/// The nqhalg of a hash name: "SHA-256", "sha256", "sha3_256", ...
pub(crate) fn hid(name: &str) -> Result<c_int> {
    let k = hkey(name);
    HNAMES
        .iter()
        .position(|n| hkey(n) == k)
        .map(|i| i as c_int + 1)
        .ok_or_else(|| Error::why(-8, format!("unknown hash {name:?}")))
}

/// The digest of `data`. `alg` is "SHA-256", "SHA3-512", "SHAKE128", ...
/// `n` is the output length for SHAKE (default 32 for SHAKE128, 64 for
/// SHAKE256); the other hashes have a fixed length and take `None`.
pub fn hash(alg: &str, data: &[u8], n: Option<usize>) -> Result<Vec<u8>> {
    let i = hid(alg)?;
    // SAFETY: a plain lookup
    let mut d = unsafe { ffi::nqhlen(i) };
    if let Some(n) = n {
        if i < 11 {
            return Err(Error::why(
                -1,
                format!("{alg} has a fixed length; n is for SHAKE"),
            ));
        }
        d = n;
    }
    let mut out = vec![0u8; d];
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe { ffi::nqhash(i, data.as_ptr(), data.len(), out.as_mut_ptr(), d) })?;
    Ok(out)
}

/// HMAC of `data` under `key` with a SHA-2 or SHA-3 hash.
pub fn hmac(alg: &str, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let i = hid(alg)?;
    // SAFETY: a plain lookup
    let d = unsafe { ffi::nqhlen(i) };
    let mut out = vec![0u8; d];
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe {
        ffi::nqhmac(
            i,
            key.as_ptr(),
            key.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            d,
        )
    })?;
    Ok(out)
}

/// `n` bytes from the operating system's CSPRNG.
pub fn random(n: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; n];
    // SAFETY: out holds n bytes
    rc(unsafe { ffi::nqrand(out.as_mut_ptr(), n) })?;
    Ok(out)
}
