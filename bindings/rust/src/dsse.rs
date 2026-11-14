// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! DSSE envelopes, the in-toto and SLSA signing wrapper: a payload and
//! its type, signed over PAE(type, payload).
//!
//! ```
//! use noqtis::{dsse, sign};
//!
//! let (pk, sk) = sign::keygen("ML-DSA-44", None)?;
//! let e = dsse::sign("ML-DSA-44", &sk, &pk, "application/vnd.in-toto+json", b"{}")?;
//! let (t, p) = dsse::verify("ML-DSA-44", &pk, &e)?.unwrap();
//! assert_eq!((t.as_str(), &p[..]), ("application/vnd.in-toto+json", &b"{}"[..]));
//! # Ok::<(), noqtis::Error>(())
//! ```

use crate::cap::sized;
use crate::{ffi, find, Error, Kind, Result};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// The envelope (canonical JSON) of `payload` of type `typ` (1 to 255
/// printable ASCII bytes, no quote or backslash), signed by the pair
/// (`sk`, `pk`); its keyid is the hex SHA-256 of `pk`.
pub fn sign(alg: &str, sk: &[u8], pk: &[u8], typ: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let a = find(alg, Kind::Sign)?;
    let t = CString::new(typ).map_err(|_| Error::why(-1, "type: a NUL byte"))?;
    // SAFETY: the buffers are valid for the lengths passed
    sized(
        |o, c, n| unsafe {
            ffi::nqdsse(
                a.id,
                sk.as_ptr(),
                sk.len(),
                pk.as_ptr(),
                pk.len(),
                t.as_ptr(),
                payload.as_ptr(),
                payload.len(),
                o.cast(),
                c,
                n,
            )
        },
        4 * payload.len() + 4 * a.sig + 1024,
    )
}

/// `Some((type, payload))` when one of the envelope's signatures verifies
/// under `pk`, `None` when none does; [`Code::Decode`](crate::Code) for
/// text that is not an envelope.
pub fn verify(alg: &str, pk: &[u8], env: &[u8]) -> Result<Option<(String, Vec<u8>)>> {
    let a = find(alg, Kind::Sign)?;
    let mut t = [0 as c_char; 256];
    // SAFETY: the buffers are valid for the lengths passed
    let r = sized(
        |o, c, n| unsafe {
            ffi::nqdssevrfy(
                a.id,
                pk.as_ptr(),
                pk.len(),
                env.as_ptr().cast(),
                env.len(),
                o,
                c,
                n,
                t.as_mut_ptr(),
            )
        },
        env.len() + 1,
    );
    match r {
        Ok(p) => {
            // SAFETY: the library NUL-terminates the type
            let ty = unsafe { CStr::from_ptr(t.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            Ok(Some((ty, p)))
        }
        Err(e) if e.code() == -3 => Ok(None),
        Err(e) => Err(e),
    }
}
