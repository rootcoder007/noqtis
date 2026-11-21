// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! A store of other people's public keys in a folder: keys under names
//! and addresses, certifications of them, and how far each is trusted.
//! A key is valid when a fully trusted valid key certified it, or three
//! marginally trusted ones; the owner's own keys are trusted
//! ultimately.

use crate::mail::{algname, cs, now, out, string, text};
use crate::{alg as findalg, ffi, find, rc, Error, Kind, Result};
use std::os::raw::{c_char, c_int};
use std::ptr;

/// Trust: not said.
pub const TRUST_UNKNOWN: i32 = 0;
/// Never trusted to certify.
pub const TRUST_NEVER: i32 = 1;
/// Trusted marginally.
pub const TRUST_MARGINAL: i32 = 2;
/// Trusted fully.
pub const TRUST_FULL: i32 = 3;
/// The owner's own key.
pub const TRUST_ULTIMATE: i32 = 4;
/// Validity: not known to belong to its name.
pub const VALID_NONE: i32 = 0;
/// Marginally valid.
pub const VALID_MARGINAL: i32 = 1;
/// Fully valid.
pub const VALID_FULL: i32 = 2;

/// One public key of a store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    /// Its algorithm.
    pub alg: String,
    /// Whether it is a KEM key.
    pub kem: bool,
    /// SHA-256 of the public key.
    pub fingerprint: [u8; 32],
    /// The name it is kept under.
    pub name: String,
    /// Its address, "" when it has none.
    pub email: String,
    /// Whether the store holds its identity card.
    pub card: bool,
    /// One of the `TRUST_` values.
    pub trust: i32,
    /// One of the `VALID_` values.
    pub valid: i32,
    /// Certifications of it under its present name.
    pub certs: usize,
}

/// Puts the public key `pk` of `alg` into the store in the folder `dir`,
/// which must exist, under `name` and `email`; `card` is its identity
/// card. It gives the key's fingerprint.
pub fn add(
    dir: &str,
    alg: &str,
    pk: &[u8],
    name: &str,
    email: Option<&str>,
    card: Option<&[u8]>,
) -> Result<[u8; 32]> {
    let a = findalg(alg)?;
    let d = cs(dir, "the folder")?;
    let n = cs(name, "the name")?;
    let e = email.map(|e| cs(e, "the address")).transpose()?;
    let (cp, cl) = card.map_or((ptr::null(), 0), |c| (c.as_ptr() as *const c_char, c.len()));
    let mut fp = [0u8; 32];
    // SAFETY: the strings are NUL-terminated, every buffer valid
    rc(unsafe {
        ffi::nqksadd(
            d.as_ptr(),
            (a.kind == Kind::Kem) as c_int,
            a.id,
            pk.as_ptr(),
            pk.len(),
            n.as_ptr(),
            e.as_ref().map_or(ptr::null(), |e| e.as_ptr()),
            cp,
            cl,
            fp.as_mut_ptr(),
        )
    })?;
    Ok(fp)
}

/// The keys of the store whose name, address or fingerprint (in hex,
/// from its start) matches `query`; all of them with `None`.
pub fn list(dir: &str, query: Option<&str>) -> Result<Vec<Key>> {
    let d = cs(dir, "the folder")?;
    let q = query.map(|q| cs(q, "the query")).transpose()?;
    let qp = q.as_ref().map_or(ptr::null(), |q| q.as_ptr());
    let mut n = 0usize;
    // SAFETY: a NULL list of capacity 0 asks the count
    let c = unsafe { ffi::nqkslist(d.as_ptr(), qp, ptr::null_mut(), 0, &mut n) };
    if c != ffi::NQEBUF {
        rc(c)?;
    }
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut es: Vec<ffi::Kse> = Vec::with_capacity(n);
    let cap = n;
    // SAFETY: es has room for cap entries; the library fills the first n
    rc(unsafe { ffi::nqkslist(d.as_ptr(), qp, es.as_mut_ptr(), cap, &mut n) })?;
    // SAFETY: min(n, cap) entries were written
    unsafe { es.set_len(n.min(cap)) };
    Ok(es
        .iter()
        .map(|e| Key {
            alg: algname(e.kem != 0, e.alg),
            kem: e.kem != 0,
            fingerprint: e.fp,
            name: text(&e.name),
            email: text(&e.email),
            card: e.card != 0,
            trust: e.trust,
            valid: e.valid,
            certs: e.ncert,
        })
        .collect())
}

/// The algorithm and the public key of the key `fp`.
pub fn get(dir: &str, fp: &[u8; 32]) -> Result<(String, Vec<u8>)> {
    let d = cs(dir, "the folder")?;
    let (mut kem, mut alg): (c_int, c_int) = (0, 0);
    let pk = out(1 << 16, |p, cap, got| {
        // SAFETY: fp is 32 bytes, p valid for cap
        unsafe { ffi::nqksget(d.as_ptr(), fp.as_ptr(), &mut kem, &mut alg, p, cap, got) }
    })?;
    Ok((algname(kem != 0, alg), pk))
}

/// Signs, with the signature key pair (`sk`, `pk`) of `alg`, that the
/// key `fp` of the store belongs to the name and address the store has
/// for it. The certification (text) is kept in the store and given
/// back, to pass on.
pub fn certify(
    dir: &str,
    alg: &str,
    sk: &[u8],
    pk: &[u8],
    fp: &[u8; 32],
    at: Option<i64>,
) -> Result<String> {
    let a = find(alg, Kind::Sign)?;
    let d = cs(dir, "the folder")?;
    string(out(2 * a.sig + 4096, |p, cap, got| {
        // SAFETY: every buffer is valid for its length
        unsafe {
            ffi::nqkscert(
                d.as_ptr(),
                a.id,
                sk.as_ptr(),
                sk.len(),
                pk.as_ptr(),
                pk.len(),
                fp.as_ptr(),
                now(at),
                p as *mut c_char,
                cap,
                got,
            )
        }
    })?)
}

/// Puts a certification someone else made into the store: both keys
/// must be in it, and its signature must verify.
pub fn addcert(dir: &str, cert: &str) -> Result<()> {
    let d = cs(dir, "the folder")?;
    // SAFETY: cert is valid for its length
    rc(unsafe { ffi::nqkscput(d.as_ptr(), cert.as_ptr() as *const c_char, cert.len()) })
}

/// Sets how far the owner of the key `fp` is trusted to certify other
/// keys: one of the `TRUST_` values.
pub fn trust(dir: &str, fp: &[u8; 32], level: i32) -> Result<()> {
    let d = cs(dir, "the folder")?;
    // SAFETY: fp is 32 bytes
    rc(unsafe { ffi::nqkstrust(d.as_ptr(), fp.as_ptr(), level) })
}

/// Removes the key `fp` and what the store holds about it.
pub fn delete(dir: &str, fp: &[u8; 32]) -> Result<()> {
    let d = cs(dir, "the folder")?;
    // SAFETY: fp is 32 bytes
    rc(unsafe { ffi::nqksdel(d.as_ptr(), fp.as_ptr()) })
}

/// A bundle (text) of the key `fp`: the key, its name and address, its
/// identity card and the certifications of it, for another store to
/// [`import`] or to publish at its [`url`].
pub fn export(dir: &str, fp: &[u8; 32]) -> Result<String> {
    let d = cs(dir, "the folder")?;
    let mut n = 0usize;
    // SAFETY: a NULL output of capacity 0 asks the size
    let c = unsafe { ffi::nqksexp(d.as_ptr(), fp.as_ptr(), ptr::null_mut(), 0, &mut n) };
    if c != ffi::NQEBUF {
        rc(c)?;
    }
    string(out(n + 1, |p, cap, got| {
        // SAFETY: p is valid for cap
        unsafe { ffi::nqksexp(d.as_ptr(), fp.as_ptr(), p as *mut c_char, cap, got) }
    })?)
}

/// Puts the keys of a bundle into the store. With `email` the bundle's
/// keys must be for that address. It gives the fingerprint of the first
/// key and how many keys came in.
pub fn import(dir: &str, bundle: &str, email: Option<&str>) -> Result<([u8; 32], usize)> {
    let d = cs(dir, "the folder")?;
    let e = email.map(|e| cs(e, "the address")).transpose()?;
    let mut fp = [0u8; 32];
    let mut n = 0usize;
    // SAFETY: bundle is valid for its length, fp is 32 bytes
    rc(unsafe {
        ffi::nqksimp(
            d.as_ptr(),
            bundle.as_ptr() as *const c_char,
            bundle.len(),
            e.as_ref().map_or(ptr::null(), |e| e.as_ptr()),
            fp.as_mut_ptr(),
            &mut n,
        )
    })?;
    Ok((fp, n))
}

/// Where the bundle of an address is looked for, over https at its own
/// domain: `https://<domain>/.well-known/noqtis/<hash of the local
/// part>`. Fetch it, and give what comes back to [`import`] with the
/// address.
pub fn url(email: &str) -> Result<String> {
    let e = cs(email, "the address")?;
    let mut u = [0 as c_char; 512];
    // SAFETY: e is NUL-terminated, u valid for its length
    rc(unsafe { ffi::nqksurl(e.as_ptr(), u.as_mut_ptr(), u.len()) })?;
    let s = text(&u);
    if s.is_empty() {
        return Err(Error::why(-1, "no address"));
    }
    Ok(s)
}
