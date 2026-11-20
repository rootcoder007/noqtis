// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! noqtis: post-quantum signatures, KEMs, hashes and sealed file capsules.
//!
//! Documentation and guides: <https://noqtis.dev/>.
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
pub mod card;
pub mod data;
pub mod dsse;
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
    /// A signature failed the check made right after signing (NQEFLT).
    Fault,
    /// A known answer of the self-test did not match (NQEKAT).
    SelfTest,
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
            -11 => Code::Fault,
            -12 => Code::SelfTest,
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

/// The library's version, "0.2.3".
pub fn version() -> String {
    // SAFETY: a static string
    cstr(unsafe { ffi::nqver() })
}

/// Runs the library's known-answer self-test (every family, about a
/// tenth of a second): `Err` with [`Code::SelfTest`] when an answer
/// differs.
pub fn selftest() -> Result<()> {
    // SAFETY: no arguments; it uses its own buffers
    rc(unsafe { ffi::nqselftest() })
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

/// Wipes `b` (nqwipe): the compiler cannot remove the stores.
pub fn wipe(b: &mut [u8]) {
    // SAFETY: b is valid for its length
    unsafe { ffi::nqwipe(b.as_mut_ptr(), b.len()) }
}

/// `true` when `a` and `b` are equal, in time that depends only on their
/// length (nqcteq): compare MACs and tags with it.
pub fn cteq(a: &[u8], b: &[u8]) -> bool {
    // SAFETY: both hold len bytes
    a.len() == b.len() && unsafe { ffi::nqcteq(a.as_ptr(), b.as_ptr(), a.len()) } == 1
}

/// BLAKE2b (RFC 7693): an `n`-byte digest (1 to 64) of `data`, keyed (a
/// MAC) with up to 64 bytes of `key` (empty for the plain hash).
pub fn blake2b(data: &[u8], key: &[u8], n: usize) -> Result<Vec<u8>> {
    if !(1..=64).contains(&n) {
        return Err(Error::why(-1, "n: 1 to 64 bytes"));
    }
    let mut out = vec![0u8; n];
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe {
        ffi::nqb2b(
            key.as_ptr(),
            key.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            n,
        )
    })?;
    Ok(out)
}

fn kt(bits: u32, data: &[u8], custom: &[u8], n: usize) -> Result<Vec<u8>> {
    if n == 0 {
        return Err(Error::why(-1, "n: 1 byte or more"));
    }
    let mut out = vec![0u8; n];
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe {
        ffi::nqkt(
            bits,
            data.as_ptr(),
            data.len(),
            custom.as_ptr(),
            custom.len(),
            out.as_mut_ptr(),
            n,
        )
    })?;
    Ok(out)
}

/// KangarooTwelve KT128 (RFC 9861): `n` bytes of the tree hash and
/// extendable-output function, with a customization string (empty for
/// none; a secret key there makes it a MAC). 32 bytes give its full
/// strength against collisions.
pub fn kt128(data: &[u8], custom: &[u8], n: usize) -> Result<Vec<u8>> {
    kt(128, data, custom, n)
}

/// KangarooTwelve KT256 (RFC 9861): as [`kt128`], at 256 bits; 64 bytes
/// give its full strength against collisions.
pub fn kt256(data: &[u8], custom: &[u8], n: usize) -> Result<Vec<u8>> {
    kt(256, data, custom, n)
}

/// The ChaCha20 stream cipher (RFC 8439): `data` XORed with the key
/// stream of the 32-byte `key` and the 12-byte `nonce`, from block
/// `counter`. The same call decrypts.
///
/// **Not authenticated**: a changed ciphertext decrypts to a changed
/// plaintext with no error, and a key and nonce used for two messages
/// give away their XOR. To encrypt, use [`sivenc`] or [`gsivenc`].
pub fn chacha20(key: &[u8], nonce: &[u8], counter: u32, data: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; data.len()];
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe {
        ffi::nqcha20(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            counter,
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
        )
    })?;
    Ok(out)
}

fn siv(dec: bool, key: &[u8], ad: &[&[u8]], data: &[u8]) -> Result<Vec<u8>> {
    if dec && data.len() < 16 {
        return Err(Error::why(-1, "data: at least the 16 bytes of the IV"));
    }
    let n = if dec {
        data.len() - 16
    } else {
        data.len() + 16
    };
    let p: Vec<*const u8> = ad.iter().map(|a| a.as_ptr()).collect();
    let l: Vec<usize> = ad.iter().map(|a| a.len()).collect();
    let mut out = vec![0u8; n];
    // SAFETY: p and l hold ad.len() entries, and every buffer is valid
    // for the length passed with it
    rc(unsafe {
        let f = if dec { ffi::nqsivdec } else { ffi::nqsivenc };
        f(
            key.as_ptr(),
            key.len(),
            p.as_ptr(),
            l.as_ptr(),
            ad.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            n,
        )
    })?;
    Ok(out)
}

/// AES-SIV (RFC 5297), deterministic authenticated encryption: the
/// 16-byte synthetic IV, then the ciphertext. `key` is 32, 48 or 64
/// bytes; `ad` is up to 126 associated strings, authenticated and not
/// encrypted (a nonce, where there is one, is by convention the last).
/// The same input always gives the same output.
pub fn sivenc(key: &[u8], ad: &[&[u8]], data: &[u8]) -> Result<Vec<u8>> {
    siv(false, key, ad, data)
}

/// The plaintext of [`sivenc`]; an error of kind `Verify` when the key,
/// the associated strings or the data are not the ones encrypted.
pub fn sivdec(key: &[u8], ad: &[&[u8]], data: &[u8]) -> Result<Vec<u8>> {
    siv(true, key, ad, data)
}

fn gsiv(dec: bool, key: &[u8], nonce: &[u8], ad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if dec && data.len() < 16 {
        return Err(Error::why(-1, "data: at least the 16 bytes of the tag"));
    }
    let n = if dec {
        data.len() - 16
    } else {
        data.len() + 16
    };
    let mut out = vec![0u8; n];
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe {
        let f = if dec { ffi::nqgsivdec } else { ffi::nqgsivenc };
        f(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            ad.as_ptr(),
            ad.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            n,
        )
    })?;
    Ok(out)
}

/// AES-GCM-SIV (RFC 8452), authenticated encryption that resists a nonce
/// used twice: the ciphertext, then the 16-byte tag. `key` is 16 or 32
/// bytes and `nonce` 12.
pub fn gsivenc(key: &[u8], nonce: &[u8], ad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    gsiv(false, key, nonce, ad, data)
}

/// The plaintext of [`gsivenc`]; an error of kind `Verify` when it does
/// not verify.
pub fn gsivdec(key: &[u8], nonce: &[u8], ad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    gsiv(true, key, nonce, ad, data)
}

/// The cost of [`argon2id`]: `t` passes over `m` KiB in `p` lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cost {
    /// Passes, 1 to 1024.
    pub t: u32,
    /// Memory in KiB, 8p to 4 GiB.
    pub m: u32,
    /// Lanes, 1 to 255.
    pub p: u32,
}

impl Default for Cost {
    /// 3 passes over 64 MiB in 4 lanes, the passphrase key files' cost.
    fn default() -> Cost {
        Cost {
            t: 3,
            m: 65536,
            p: 4,
        }
    }
}

/// Argon2id (RFC 9106, version 0x13): `n` bytes (4 to 1024) from the
/// password and the salt (8 bytes or more), with an optional secret
/// `key` and associated data `ad` (empty for none).
pub fn argon2id(
    pw: &[u8],
    salt: &[u8],
    c: Cost,
    n: usize,
    key: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>> {
    if !(4..=1024).contains(&n) {
        return Err(Error::why(-1, "n: 4 to 1024 bytes"));
    }
    let mut out = vec![0u8; n];
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe {
        ffi::nqa2id(
            pw.as_ptr(),
            pw.len(),
            salt.as_ptr(),
            salt.len(),
            key.as_ptr(),
            key.len(),
            ad.as_ptr(),
            ad.len(),
            c.t,
            c.m,
            c.p,
            out.as_mut_ptr(),
            n,
        )
    })?;
    Ok(out)
}

/// A digest of data given in pieces, as [`hash`] gives it for the whole:
/// [`update`](Hasher::update) (or `io::Write`) any number of times, then
/// [`finish`](Hasher::finish); for SHAKE, `finish` may be called again
/// to squeeze more output.
pub struct Hasher {
    c: Box<ffi::Hctx>,
    n: usize,
    shake: bool,
}

impl Hasher {
    /// A new hash of `alg` ("SHA-256", "SHAKE128", ...).
    pub fn new(alg: &str) -> Result<Hasher> {
        let i = hid(alg)?;
        let mut c = Box::new(ffi::Hctx { opq: [0; 52] });
        // SAFETY: c is a context of the size noqtis.h gives
        rc(unsafe { ffi::nqhini(&mut *c, i) })?;
        // SAFETY: a plain lookup
        let n = unsafe { ffi::nqhlen(i) };
        Ok(Hasher {
            c,
            n,
            shake: i >= 11,
        })
    }

    /// Adds `data`.
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        // SAFETY: data holds len bytes
        rc(unsafe { ffi::nqhupd(&mut *self.c, data.as_ptr(), data.len()) })
    }

    /// The digest; `n` is the output length for SHAKE (None: its default).
    pub fn finish(&mut self, n: Option<usize>) -> Result<Vec<u8>> {
        if n.is_some() && !self.shake {
            return Err(Error::why(-1, "n is for SHAKE"));
        }
        let d = n.unwrap_or(self.n);
        let mut out = vec![0u8; d];
        // SAFETY: out holds d bytes
        rc(unsafe { ffi::nqhfin(&mut *self.c, out.as_mut_ptr(), d) })?;
        Ok(out)
    }
}

impl std::io::Write for Hasher {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.update(b)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hasher")
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        // SAFETY: the context is ours
        unsafe {
            ffi::nqwipe(
                self.c.opq.as_mut_ptr().cast(),
                std::mem::size_of::<ffi::Hctx>(),
            )
        }
    }
}
