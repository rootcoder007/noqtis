// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! Key encapsulation: ML-KEM (FIPS 203) and HQC.
//!
//! ```
//! use noqtis::kem;
//!
//! let (pk, sk) = kem::keygen("ML-KEM-768", None)?;
//! let (ct, ss) = kem::encap("ML-KEM-768", &pk, None)?;
//! assert_eq!(kem::decap("ML-KEM-768", &sk, &ct)?, ss);
//! # Ok::<(), noqtis::Error>(())
//! ```

use crate::{ffi, find, rc, Kind, Result};

/// A new key pair `(pk, sk)`; with `seed` (d || z for ML-KEM) the
/// standard's deterministic one.
pub fn keygen(alg: &str, seed: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
    let a = find(alg, Kind::Kem)?;
    let mut pk = vec![0u8; a.pk];
    let mut sk = vec![0u8; a.sk];
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe {
        match seed {
            None => ffi::nqkkg(a.id, pk.as_mut_ptr(), a.pk, sk.as_mut_ptr(), a.sk),
            Some(s) => ffi::nqkkgd(
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

/// `(ciphertext, shared secret)` for `pk`; `seed` (m for ML-KEM) makes it
/// deterministic, for test vectors.
pub fn encap(alg: &str, pk: &[u8], seed: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
    let a = find(alg, Kind::Kem)?;
    let mut ct = vec![0u8; a.ct];
    let mut ss = vec![0u8; a.ss];
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe {
        match seed {
            None => ffi::nqenc(
                a.id,
                pk.as_ptr(),
                pk.len(),
                ct.as_mut_ptr(),
                a.ct,
                ss.as_mut_ptr(),
                a.ss,
            ),
            Some(s) => ffi::nqencd(
                a.id,
                pk.as_ptr(),
                pk.len(),
                s.as_ptr(),
                s.len(),
                ct.as_mut_ptr(),
                a.ct,
                ss.as_mut_ptr(),
                a.ss,
            ),
        }
    })?;
    Ok((ct, ss))
}

/// The shared secret in `ct`. A tampered ciphertext gives an unrelated
/// pseudorandom secret, not an error (implicit rejection); only a key or
/// ciphertext of the wrong size, or a damaged secret key, is an error.
pub fn decap(alg: &str, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let a = find(alg, Kind::Kem)?;
    let mut ss = vec![0u8; a.ss];
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe {
        ffi::nqdec(
            a.id,
            sk.as_ptr(),
            sk.len(),
            ct.as_ptr(),
            ct.len(),
            ss.as_mut_ptr(),
            a.ss,
        )
    })?;
    Ok(ss)
}
