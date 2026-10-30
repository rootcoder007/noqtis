// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! Signatures: ML-DSA (FIPS 204), SLH-DSA (FIPS 205), Ed25519 (RFC 8032)
//! and the ML-DSA + Ed25519 hybrids.
//!
//! ```
//! use noqtis::sign::{self, Opts};
//!
//! let (pk, sk) = sign::keygen("ML-DSA-44", None)?;
//! let o = Opts { ctx: b"app-v1", ..Opts::default() };
//! let sig = sign::sign("ML-DSA-44", &sk, b"message", &o)?;
//! assert!(sign::verify("ML-DSA-44", &pk, b"message", &sig, &o)?);
//! assert!(!sign::verify("ML-DSA-44", &pk, b"message", &sig, &Opts::default())?);
//! # Ok::<(), noqtis::Error>(())
//! ```

use crate::{ffi, find, hid, rc, Error, Kind, Result};
use std::ptr;

/// The options of [`sign`] and [`verify`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Opts<'a> {
    /// The context string, at most 255 bytes (empty for none).
    pub ctx: &'a [u8],
    /// All-zero per-signature randomness: the standard's deterministic
    /// variant ([`sign`] only).
    pub deterministic: bool,
    /// A hash name ("SHA-512", "SHAKE256", ...) for HashML-DSA /
    /// HashSLH-DSA (Ed25519ph for Ed25519); the message is still the
    /// message, hashed inside.
    pub prehash: Option<&'a str>,
    /// The per-signature randomness, explicitly ([`sign`] only).
    pub rnd: Option<&'a [u8]>,
}

fn ph(o: &Opts) -> Result<i32> {
    match o.prehash {
        None => Ok(0),
        Some(h) => hid(h),
    }
}

/// Bytes of per-signature randomness: 32 for ML-DSA and the hybrids, n
/// for SLH-DSA, 0 for Ed25519.
pub fn rndlen(alg: &str) -> Result<usize> {
    let a = find(alg, Kind::Sign)?;
    Ok(if a.name == "Ed25519" {
        0
    } else if a.name.starts_with("ML-DSA") {
        32
    } else {
        a.pk / 2
    })
}

/// A new key pair `(pk, sk)`. With `seed` (xi for ML-DSA, 32 bytes;
/// SK.seed || SK.prf || PK.seed for SLH-DSA, 3n bytes; the private key
/// for Ed25519; xi || the Ed25519 key for a hybrid) the pair is the
/// standard's deterministic one; without, it comes from the OS CSPRNG.
pub fn keygen(alg: &str, seed: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
    let a = find(alg, Kind::Sign)?;
    let mut pk = vec![0u8; a.pk];
    let mut sk = vec![0u8; a.sk];
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe {
        match seed {
            None => ffi::nqskg(a.id, pk.as_mut_ptr(), a.pk, sk.as_mut_ptr(), a.sk),
            Some(s) => ffi::nqskgd(
                a.id,
                s.as_ptr(),
                s.len(),
                pk.as_mut_ptr(),
                a.pk,
                sk.as_mut_ptr(),
                a.sk,
            ),
        }
    })?;
    Ok((pk, sk))
}

/// The signature of `msg` under `sk`.
pub fn sign(alg: &str, sk: &[u8], msg: &[u8], o: &Opts) -> Result<Vec<u8>> {
    let a = find(alg, Kind::Sign)?;
    if o.deterministic && o.rnd.is_some() {
        return Err(Error::why(-1, "deterministic and rnd exclude each other"));
    }
    let p = ph(o)?;
    let zero;
    let r = if o.deterministic {
        zero = vec![0u8; rndlen(alg)?];
        Some(&zero[..])
    } else {
        o.rnd
    };
    let mut sig = vec![0u8; a.sig];
    let mut n = 0usize;
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe {
        match r {
            None => ffi::nqsign(
                a.id,
                sk.as_ptr(),
                sk.len(),
                msg.as_ptr(),
                msg.len(),
                o.ctx.as_ptr(),
                o.ctx.len(),
                p,
                sig.as_mut_ptr(),
                a.sig,
                &mut n,
            ),
            Some(r) => ffi::nqsignd(
                a.id,
                sk.as_ptr(),
                sk.len(),
                msg.as_ptr(),
                msg.len(),
                o.ctx.as_ptr(),
                o.ctx.len(),
                p,
                if r.is_empty() {
                    ptr::null()
                } else {
                    r.as_ptr()
                },
                r.len(),
                sig.as_mut_ptr(),
                a.sig,
                &mut n,
            ),
        }
    })?;
    sig.truncate(n);
    Ok(sig)
}

/// `true` when `sig` is a valid signature of `msg` under `pk` (with the
/// same context and pre-hash); `false` when it does not verify or is not
/// a well-formed signature. Bad arguments (a context over 255 bytes, a
/// public key of the wrong size) are an error.
pub fn verify(alg: &str, pk: &[u8], msg: &[u8], sig: &[u8], o: &Opts) -> Result<bool> {
    let a = find(alg, Kind::Sign)?;
    if pk.len() != a.pk {
        return Err(Error::why(
            -4,
            format!(
                "{} public keys are {} bytes, not {}",
                a.name,
                a.pk,
                pk.len()
            ),
        ));
    }
    let p = ph(o)?;
    // SAFETY: the buffers are valid for the lengths passed
    let c = unsafe {
        ffi::nqvrfy(
            a.id,
            pk.as_ptr(),
            pk.len(),
            msg.as_ptr(),
            msg.len(),
            o.ctx.as_ptr(),
            o.ctx.len(),
            p,
            sig.as_ptr(),
            sig.len(),
        )
    };
    match c {
        ffi::NQOK => Ok(true),
        ffi::NQEVRFY | ffi::NQEDEC => Ok(false),
        _ => Err(Error::new(c)),
    }
}
