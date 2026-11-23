// SPDX-License-Identifier: LGPL-3.0-or-later
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

/// The length of `alg`'s version 2 secret-key container: the key S, for
/// Ed25519 and the hybrids the Ed25519 public key P, and the integrity
/// value T, SHA3-256 of a domain string, the name, S and P
/// (docs/spec/keyfile.md).
pub fn sxsize(alg: &str) -> Result<usize> {
    let a = find(alg, Kind::Sign)?;
    let mut n = 0usize;
    // SAFETY: n is a valid place for the result
    rc(unsafe { ffi::nqsxsz(a.id, &mut n) })?;
    Ok(n)
}

/// The version 2 container of the secret key `sk`. Every signing function
/// takes it in place of `sk`: after signing it checks the integrity value
/// (and for Ed25519 and the hybrids the public key) again, so a change to
/// any stored byte of the key ends in [`Code::Fault`](crate::Code) before
/// a signature leaves.
pub fn sxmake(alg: &str, sk: &[u8]) -> Result<Vec<u8>> {
    let a = find(alg, Kind::Sign)?;
    let n = sxsize(alg)?;
    let mut x = vec![0u8; n];
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe { ffi::nqsxmk(a.id, sk.as_ptr(), sk.len(), x.as_mut_ptr(), n) })?;
    Ok(x)
}

/// Whether `x` is a sound container: `Ok(true)`, `Ok(false)` when it is
/// damaged, [`Code::Unsupported`](crate::Code) for a key with no
/// container (version 1).
pub fn sxcheck(alg: &str, x: &[u8]) -> Result<bool> {
    let a = find(alg, Kind::Sign)?;
    // SAFETY: the buffer is valid for the length passed
    match unsafe { ffi::nqsxchk(a.id, x.as_ptr(), x.len()) } {
        ffi::NQOK => Ok(true),
        -4 => Ok(false),
        c => rc(c).map(|_| false),
    }
}

/// The signature of `msg` under `sk` (the key, or its container from
/// [`sxmake`]).
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

/// The 64-byte message representative mu of FIPS 204 for `msg` under
/// `pk`, as [`sign`] computes it (ML-DSA only; `o.ctx` and `o.prehash`
/// are used), so that the message can be hashed away from the key.
pub fn mu(alg: &str, pk: &[u8], msg: &[u8], o: &Opts) -> Result<Vec<u8>> {
    let a = find(alg, Kind::Sign)?;
    let p = ph(o)?;
    let mut m = vec![0u8; 64];
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe {
        ffi::nqsmu(
            a.id,
            pk.as_ptr(),
            pk.len(),
            msg.as_ptr(),
            msg.len(),
            o.ctx.as_ptr(),
            o.ctx.len(),
            p,
            m.as_mut_ptr(),
            64,
        )
    })?;
    Ok(m)
}

fn rndof(o: &Opts, n: usize) -> Result<Option<Vec<u8>>> {
    if o.deterministic && o.rnd.is_some() {
        return Err(Error::why(-1, "deterministic and rnd exclude each other"));
    }
    Ok(if o.deterministic {
        Some(vec![0u8; n])
    } else {
        o.rnd.map(|r| r.to_vec())
    })
}

fn rp(r: &Option<Vec<u8>>) -> (*const u8, usize) {
    match r {
        None => (ptr::null(), 0),
        Some(v) if v.is_empty() => (b"".as_ptr(), 0),
        Some(v) => (v.as_ptr(), v.len()),
    }
}

/// The signature of the message whose mu is `mu` ([`mu`]): the bytes
/// [`sign`] gives for that message with the same randomness (`o.rnd` or
/// `o.deterministic`; its other options are not used).
pub fn signmu(alg: &str, sk: &[u8], mu: &[u8], o: &Opts) -> Result<Vec<u8>> {
    let a = find(alg, Kind::Sign)?;
    let r = rndof(o, 32)?;
    let (rptr, rl) = rp(&r);
    let mut sig = vec![0u8; a.sig];
    let mut n = 0usize;
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe {
        ffi::nqsignmu(
            a.id,
            sk.as_ptr(),
            sk.len(),
            mu.as_ptr(),
            mu.len(),
            rptr,
            rl,
            sig.as_mut_ptr(),
            a.sig,
            &mut n,
        )
    })?;
    sig.truncate(n);
    Ok(sig)
}

/// `true` when `sig` verifies for the message whose mu is `mu`.
pub fn verifymu(alg: &str, pk: &[u8], mu: &[u8], sig: &[u8]) -> Result<bool> {
    let a = find(alg, Kind::Sign)?;
    // SAFETY: the buffers are valid for the lengths passed
    match unsafe {
        ffi::nqvrfymu(
            a.id,
            pk.as_ptr(),
            pk.len(),
            mu.as_ptr(),
            mu.len(),
            sig.as_ptr(),
            sig.len(),
        )
    } {
        0 => Ok(true),
        -3 | -4 => Ok(false),
        c => Err(Error::new(c)),
    }
}

fn sctx() -> Box<ffi::Sctx> {
    Box::new(ffi::Sctx { opq: [0; 160] })
}

/// A signature over a message given in pieces: [`update`](Signer::update)
/// (or `io::Write`, so `io::copy` works) any number of times, then
/// [`finish`](Signer::finish), which gives the bytes [`sign`] gives for
/// the whole message with the same randomness. Only the piece at hand is
/// held; the secret key is borrowed, not copied. ML-DSA (pure and
/// pre-hash), and HashSLH-DSA, Ed25519ph and the hybrids with prehash
/// "SHA-512"; the others are [`Code::Unsupported`](crate::Code).
pub struct Signer<'a> {
    a: &'static crate::Alg,
    sk: &'a [u8],
    c: Box<ffi::Sctx>,
}

impl<'a> Signer<'a> {
    /// Starts a signature with `sk`; `o.ctx` and `o.prehash` as for
    /// [`sign`].
    pub fn new(alg: &str, sk: &'a [u8], o: &Opts) -> Result<Signer<'a>> {
        let a = find(alg, Kind::Sign)?;
        let p = ph(o)?;
        let mut c = sctx();
        // SAFETY: c is a context of the size noqtis.h gives
        rc(unsafe {
            ffi::nqsini(
                &mut *c,
                a.id,
                sk.as_ptr(),
                sk.len(),
                o.ctx.as_ptr(),
                o.ctx.len(),
                p,
            )
        })?;
        Ok(Signer { a, sk, c })
    }

    /// Adds `data` to the message.
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        // SAFETY: data holds len bytes
        rc(unsafe { ffi::nqsupd(&mut *self.c, data.as_ptr(), data.len()) })
    }

    /// The signature; `o.rnd` or `o.deterministic` as for [`sign`].
    pub fn finish(mut self, o: &Opts) -> Result<Vec<u8>> {
        let r = rndof(o, rndlen(&self.a.name)?)?;
        let (rptr, rl) = rp(&r);
        let mut sig = vec![0u8; self.a.sig];
        let mut n = 0usize;
        // SAFETY: the buffers are valid for the lengths passed
        rc(unsafe {
            ffi::nqsfin(
                &mut *self.c,
                self.sk.as_ptr(),
                self.sk.len(),
                rptr,
                rl,
                sig.as_mut_ptr(),
                self.a.sig,
                &mut n,
            )
        })?;
        sig.truncate(n);
        Ok(sig)
    }
}

/// [`verify`] over a message given in pieces: as [`Signer`], then
/// [`finish`](Verifier::finish) with the signature.
pub struct Verifier<'a> {
    pk: &'a [u8],
    c: Box<ffi::Sctx>,
}

impl<'a> Verifier<'a> {
    /// Starts checking a signature under `pk`.
    pub fn new(alg: &str, pk: &'a [u8], o: &Opts) -> Result<Verifier<'a>> {
        let a = find(alg, Kind::Sign)?;
        let p = ph(o)?;
        let mut c = sctx();
        // SAFETY: c is a context of the size noqtis.h gives
        rc(unsafe {
            ffi::nqvini(
                &mut *c,
                a.id,
                pk.as_ptr(),
                pk.len(),
                o.ctx.as_ptr(),
                o.ctx.len(),
                p,
            )
        })?;
        Ok(Verifier { pk, c })
    }

    /// Adds `data` to the message.
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        // SAFETY: data holds len bytes
        rc(unsafe { ffi::nqsupd(&mut *self.c, data.as_ptr(), data.len()) })
    }

    /// `true` when `sig` is a valid signature of the whole message.
    pub fn finish(mut self, sig: &[u8]) -> Result<bool> {
        // SAFETY: the buffers are valid for the lengths passed
        match unsafe {
            ffi::nqvfin(
                &mut *self.c,
                self.pk.as_ptr(),
                self.pk.len(),
                sig.as_ptr(),
                sig.len(),
            )
        } {
            0 => Ok(true),
            -3 | -4 => Ok(false),
            c => Err(Error::new(c)),
        }
    }
}

macro_rules! sink {
    ($t:ident) => {
        impl std::io::Write for $t<'_> {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.update(b)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl std::fmt::Debug for $t<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($t))
            }
        }
        impl Drop for $t<'_> {
            fn drop(&mut self) {
                // SAFETY: the context is ours (the library wipes it at the
                // end; a dropped unfinished one is wiped here)
                unsafe {
                    ffi::nqwipe(
                        self.c.opq.as_mut_ptr().cast(),
                        std::mem::size_of::<ffi::Sctx>(),
                    )
                }
            }
        }
    };
}
sink!(Signer);
sink!(Verifier);
