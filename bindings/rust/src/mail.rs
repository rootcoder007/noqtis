// SPDX-License-Identifier: LGPL-3.0-or-later
//! Text armor, X.509 certificates for noqtis keys, and signed and
//! encrypted messages with them: the Cryptographic Message Syntax
//! (RFC 5652) and S/MIME (RFC 8551).
//!
//! ```
//! use noqtis::{mail, sign};
//!
//! let (pk, sk) = sign::keygen("ML-DSA-44", None)?;
//! let cert = mail::selfcert("ML-DSA-44", &sk, &pk, "Ada Example", None, 1767225600, 1798761600)?;
//! let s = mail::cmssign("ML-DSA-44", &sk, &cert, b"hello", false, Some(1767229200))?;
//! let (content, who) = mail::cmsverify(&s, None, &[&cert], Some(1767229200))?;
//! assert_eq!(content, b"hello");
//! assert_eq!(who.name, "Ada Example");
//! # Ok::<(), noqtis::Error>(())
//! ```

use crate::{ffi, find, rc, Error, Kind, Result};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Calls `f` with a buffer of `n` bytes and gives what it wrote there.
pub(crate) fn out(
    n: usize,
    f: impl FnOnce(*mut u8, usize, &mut usize) -> c_int,
) -> Result<Vec<u8>> {
    let mut b = vec![0u8; n.max(1)];
    let mut got = 0usize;
    rc(f(b.as_mut_ptr(), b.len(), &mut got))?;
    b.truncate(got);
    Ok(b)
}

pub(crate) fn cs(s: &str, what: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::why(-1, format!("a NUL byte in {what}")))
}

pub(crate) fn now(at: Option<i64>) -> i64 {
    at.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    })
}

pub(crate) fn text(b: &[c_char]) -> String {
    // SAFETY: the library NUL-terminates every field within its array
    unsafe { CStr::from_ptr(b.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

pub(crate) fn string(b: Vec<u8>) -> Result<String> {
    String::from_utf8(b).map_err(|_| Error::why(-4, "the result is not UTF-8 text"))
}

pub(crate) fn algname(kem: bool, id: c_int) -> String {
    // SAFETY: the name functions return static strings, or NULL
    let p = unsafe {
        if kem {
            ffi::nqkname(id)
        } else {
            ffi::nqsname(id)
        }
    };
    if p.is_null() {
        String::new()
    } else {
        // SAFETY: a static NUL-terminated string
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

fn lists(v: &[&[u8]]) -> (Vec<*const u8>, Vec<usize>) {
    (
        v.iter().map(|c| c.as_ptr()).collect(),
        v.iter().map(|c| c.len()).collect(),
    )
}

/// Writes `data` as text (RFC 7468): a `-----BEGIN label-----` line,
/// base64 in lines of 64, and the END line. The label is capitals and
/// digits with single spaces between them.
pub fn armor(label: &str, data: &[u8]) -> Result<String> {
    let l = cs(label, "the label")?;
    let mut n = 0usize;
    // SAFETY: l is NUL-terminated, n valid
    rc(unsafe { ffi::nqarmlen(l.as_ptr(), data.len(), &mut n) })?;
    string(out(n, |p, cap, got| {
        // SAFETY: data and p are valid for their lengths
        unsafe {
            ffi::nqarmenc(
                l.as_ptr(),
                data.as_ptr(),
                data.len(),
                p as *mut c_char,
                cap,
                got,
            )
        }
    })?)
}

/// Reads one armor back: its label and its bytes. Text that is not
/// exactly one well-formed armor is [`crate::Code::Decode`].
pub fn dearmor(text_in: &str) -> Result<(String, Vec<u8>)> {
    let mut lab = [0 as c_char; ffi::NQARMLAB];
    let b = out(text_in.len(), |p, cap, got| {
        // SAFETY: the input, the label array and p are valid for their lengths
        unsafe {
            ffi::nqarmdec(
                text_in.as_ptr() as *const c_char,
                text_in.len(),
                lab.as_mut_ptr(),
                lab.len(),
                p,
                cap,
                got,
            )
        }
    })?;
    Ok((text(&lab), b))
}

/// What an X.509 certificate says of its key and holder. `alg` is ""
/// for a key of a kind noqtis does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert {
    /// The key's algorithm, "ML-DSA-65" or "ML-KEM-768", say.
    pub alg: String,
    /// Whether it is an ML-KEM key.
    pub kem: bool,
    /// SHA-256 of the certificate.
    pub fingerprint: [u8; 32],
    /// Valid from, in seconds since 1970.
    pub not_before: i64,
    /// Valid to.
    pub not_after: i64,
    /// Whether it may issue certificates.
    pub ca: bool,
    /// The subject's common name, "" when it has none.
    pub name: String,
    /// Its first e-mail address, "" when it has none.
    pub email: String,
    /// The public key; empty when read from a signer alone.
    pub pk: Vec<u8>,
}

fn certof(f: &ffi::X5f, cert: Option<&[u8]>) -> Cert {
    Cert {
        alg: if f.alg == 0 {
            String::new()
        } else {
            algname(f.kem != 0, f.alg)
        },
        kem: f.kem != 0,
        fingerprint: f.fp,
        not_before: f.nb,
        not_after: f.na,
        ca: f.ca != 0,
        name: text(&f.name),
        email: text(&f.email),
        pk: cert
            .and_then(|c| c.get(f.pkoff..f.pkoff.checked_add(f.pklen)?))
            .map_or_else(Vec::new, |s| s.to_vec()),
    }
}

/// A self-signed X.509 certificate (DER) for the signature key pair
/// (`sk`, `pk`) of `alg`, an ML-DSA, SLH-DSA or Ed25519 key, under
/// `name` and `email`, valid from `not_before` to `not_after` (seconds
/// since 1970). It is a CA of path length 0, so that it can issue a
/// [`kemcert`].
pub fn selfcert(
    alg: &str,
    sk: &[u8],
    pk: &[u8],
    name: &str,
    email: Option<&str>,
    not_before: i64,
    not_after: i64,
) -> Result<Vec<u8>> {
    let a = find(alg, Kind::Sign)?;
    let n = cs(name, "the name")?;
    let e = email.map(|e| cs(e, "the address")).transpose()?;
    out(pk.len() + a.sig + 2048, |p, cap, got| {
        // SAFETY: the keys, the strings and p are valid for their lengths
        unsafe {
            ffi::nqx5self(
                a.id,
                sk.as_ptr(),
                sk.len(),
                pk.as_ptr(),
                pk.len(),
                n.as_ptr(),
                e.as_ref().map_or(ptr::null(), |e| e.as_ptr()),
                not_before,
                not_after,
                p,
                cap,
                got,
            )
        }
    })
}

/// A certificate (DER) for the ML-KEM public key `pk` of `alg`, issued
/// by the signature key `issuer_sk` under the name of its own
/// certificate `issuer_cert`: what others encrypt to.
pub fn kemcert(
    issuer_alg: &str,
    issuer_sk: &[u8],
    issuer_cert: &[u8],
    alg: &str,
    pk: &[u8],
    not_before: i64,
    not_after: i64,
) -> Result<Vec<u8>> {
    let ia = find(issuer_alg, Kind::Sign)?;
    let a = find(alg, Kind::Kem)?;
    out(
        pk.len() + issuer_cert.len() + ia.sig + 2048,
        |p, cap, got| {
            // SAFETY: the keys, the certificate and p are valid for their lengths
            unsafe {
                ffi::nqx5kem(
                    ia.id,
                    issuer_sk.as_ptr(),
                    issuer_sk.len(),
                    issuer_cert.as_ptr(),
                    issuer_cert.len(),
                    a.id,
                    pk.as_ptr(),
                    pk.len(),
                    not_before,
                    not_after,
                    p,
                    cap,
                    got,
                )
            }
        },
    )
}

/// Reads a certificate (DER): its key, holder and dates. It checks no
/// signature; [`cmsverify`] and [`smimeverify`] do, against anchors.
pub fn readcert(cert: &[u8]) -> Result<Cert> {
    // SAFETY: nqx5f is plain data; all zero is a valid value
    let mut f: ffi::X5f = unsafe { std::mem::zeroed() };
    // SAFETY: cert is valid for its length, f for its size
    rc(unsafe { ffi::nqx5info(cert.as_ptr(), cert.len(), &mut f) })?;
    Ok(certof(&f, Some(cert)))
}

/// A CMS SignedData (RFC 5652, DER) of `msg`, signed with the key `sk`
/// of `alg` whose certificate is `cert`; with `detached` the content is
/// left out. `at` is the signing time (`None` for now).
pub fn cmssign(
    alg: &str,
    sk: &[u8],
    cert: &[u8],
    msg: &[u8],
    detached: bool,
    at: Option<i64>,
) -> Result<Vec<u8>> {
    let a = find(alg, Kind::Sign)?;
    out(msg.len() + cert.len() + a.sig + 4096, |p, cap, got| {
        // SAFETY: every buffer is valid for its length
        unsafe {
            ffi::nqcmssign(
                a.id,
                sk.as_ptr(),
                sk.len(),
                cert.as_ptr(),
                cert.len(),
                msg.as_ptr(),
                msg.len(),
                detached as c_int,
                now(at),
                p,
                cap,
                got,
            )
        }
    })
}

/// Checks a SignedData against the `anchors`, certificates (DER) the
/// caller trusts: the signer's certificate must be one of them. `msg`
/// is the content of a detached signature. It gives the content and the
/// signer; [`crate::Code::Verify`] when the signature does not verify
/// or the signer is not an anchor.
pub fn cmsverify(
    cms: &[u8],
    msg: Option<&[u8]>,
    anchors: &[&[u8]],
    at: Option<i64>,
) -> Result<(Vec<u8>, Cert)> {
    let (ap, al) = lists(anchors);
    let (mp, ml) = msg.map_or((ptr::null(), 0), |m| (m.as_ptr(), m.len()));
    // SAFETY: nqx5f is plain data; all zero is a valid value
    let mut f: ffi::X5f = unsafe { std::mem::zeroed() };
    let b = out(cms.len() + ml, |p, cap, got| {
        // SAFETY: every buffer is valid for its length, the lists for nanc
        unsafe {
            ffi::nqcmsvrfy(
                cms.as_ptr(),
                cms.len(),
                mp,
                ml,
                ap.as_ptr(),
                al.as_ptr(),
                ap.len(),
                now(at),
                p,
                cap,
                got,
                &mut f,
            )
        }
    })?;
    Ok((b, certof(&f, None)))
}

/// A CMS AuthEnvelopedData (RFC 5083, AES-256-GCM, DER) of `msg` to the
/// ML-KEM certificates `certs` (RFC 9629, RFC 9936): the secret key of
/// any one of them opens it.
pub fn cmsencrypt(certs: &[&[u8]], msg: &[u8]) -> Result<Vec<u8>> {
    let (cp, cl) = lists(certs);
    let n = msg.len() + 4096 + certs.iter().map(|c| c.len() + 2048).sum::<usize>();
    out(n, |p, cap, got| {
        // SAFETY: every buffer is valid for its length, the lists for nr
        unsafe {
            ffi::nqcmsenc(
                cp.as_ptr(),
                cl.as_ptr(),
                cp.len(),
                msg.as_ptr(),
                msg.len(),
                p,
                cap,
                got,
            )
        }
    })
}

/// Opens an AuthEnvelopedData with the ML-KEM secret key `sk` of `alg`;
/// `cert` is the key's certificate and names the recipient to use.
/// [`crate::Code::Verify`] when it is not for this key or was changed.
pub fn cmsdecrypt(alg: &str, sk: &[u8], cert: Option<&[u8]>, cms: &[u8]) -> Result<Vec<u8>> {
    let a = find(alg, Kind::Kem)?;
    let (cp, cl) = cert.map_or((ptr::null(), 0), |c| (c.as_ptr(), c.len()));
    out(cms.len(), |p, cap, got| {
        // SAFETY: every buffer is valid for its length
        unsafe {
            ffi::nqcmsdec(
                a.id,
                sk.as_ptr(),
                sk.len(),
                cp,
                cl,
                cms.as_ptr(),
                cms.len(),
                p,
                cap,
                got,
            )
        }
    })
}

/// An S/MIME message (RFC 8551) of the MIME `entity` (header lines, an
/// empty line, the body), signed as [`cmssign`] signs:
/// application/pkcs7-mime, or with `detached` multipart/signed, which
/// keeps the entity readable.
pub fn smimesign(
    alg: &str,
    sk: &[u8],
    cert: &[u8],
    entity: &str,
    detached: bool,
    at: Option<i64>,
) -> Result<String> {
    let a = find(alg, Kind::Sign)?;
    string(out(
        3 * entity.len() + 2 * (cert.len() + a.sig) + 8192,
        |p, cap, got| {
            // SAFETY: every buffer is valid for its length
            unsafe {
                ffi::nqsmsign(
                    a.id,
                    sk.as_ptr(),
                    sk.len(),
                    cert.as_ptr(),
                    cert.len(),
                    entity.as_ptr() as *const c_char,
                    entity.len(),
                    detached as c_int,
                    now(at),
                    p as *mut c_char,
                    cap,
                    got,
                )
            }
        },
    )?)
}

/// Checks a signed S/MIME message against the `anchors`, as
/// [`cmsverify`] does, and gives the entity that was signed and the
/// signer.
pub fn smimeverify(mime: &str, anchors: &[&[u8]], at: Option<i64>) -> Result<(String, Cert)> {
    let (ap, al) = lists(anchors);
    // SAFETY: nqx5f is plain data; all zero is a valid value
    let mut f: ffi::X5f = unsafe { std::mem::zeroed() };
    let b = out(mime.len() + 1, |p, cap, got| {
        // SAFETY: every buffer is valid for its length, the lists for nanc
        unsafe {
            ffi::nqsmvrfy(
                mime.as_ptr() as *const c_char,
                mime.len(),
                ap.as_ptr(),
                al.as_ptr(),
                ap.len(),
                now(at),
                p as *mut c_char,
                cap,
                got,
                &mut f,
            )
        }
    })?;
    Ok((string(b)?, certof(&f, None)))
}

/// An encrypted S/MIME message (authEnveloped-data) of the MIME
/// `entity` to the ML-KEM certificates `certs`.
pub fn smimeencrypt(certs: &[&[u8]], entity: &str) -> Result<String> {
    let (cp, cl) = lists(certs);
    let n = 3 * entity.len() + 8192 + certs.iter().map(|c| 2 * c.len() + 4096).sum::<usize>();
    string(out(n, |p, cap, got| {
        // SAFETY: every buffer is valid for its length, the lists for nr
        unsafe {
            ffi::nqsmenc(
                cp.as_ptr(),
                cl.as_ptr(),
                cp.len(),
                entity.as_ptr() as *const c_char,
                entity.len(),
                p as *mut c_char,
                cap,
                got,
            )
        }
    })?)
}

/// Opens an encrypted S/MIME message, as [`cmsdecrypt`] does, and gives
/// the MIME entity inside.
pub fn smimedecrypt(alg: &str, sk: &[u8], cert: Option<&[u8]>, mime: &str) -> Result<String> {
    let a = find(alg, Kind::Kem)?;
    let (cp, cl) = cert.map_or((ptr::null(), 0), |c| (c.as_ptr(), c.len()));
    string(out(mime.len() + 1, |p, cap, got| {
        // SAFETY: every buffer is valid for its length
        unsafe {
            ffi::nqsmdec(
                a.id,
                sk.as_ptr(),
                sk.len(),
                cp,
                cl,
                mime.as_ptr() as *const c_char,
                mime.len(),
                p as *mut c_char,
                cap,
                got,
            )
        }
    })?)
}
