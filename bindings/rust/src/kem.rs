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

use crate::{ffi, find, rc, Error, Kind, Result};
use std::io::{Read, Write};
use std::os::raw::c_int;

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

/// `msg` sealed to the ML-KEM public key `pk` (noqtis-kseal-1): only the
/// holder of the secret key opens it, with the same `ctx` (at most 255
/// bytes).
pub fn seal(alg: &str, pk: &[u8], msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
    let a = find(alg, Kind::Kem)?;
    let cap = 22 + a.ct + msg.len();
    let mut out = vec![0u8; cap];
    let mut n = 0usize;
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe {
        ffi::nqkseal(
            a.id,
            pk.as_ptr(),
            pk.len(),
            ctx.as_ptr(),
            ctx.len(),
            msg.as_ptr(),
            msg.len(),
            out.as_mut_ptr(),
            cap,
            &mut n,
        )
    })?;
    out.truncate(n);
    Ok(out)
}

/// The message [`seal`] sealed: [`Code::Verify`](crate::Code) for a
/// changed byte, another key or another `ctx`, [`Code::Decode`](crate::Code)
/// for bytes that are not a sealed message of this algorithm.
pub fn open(alg: &str, sk: &[u8], data: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
    let a = find(alg, Kind::Kem)?;
    let cap = data.len().max(1);
    let mut out = vec![0u8; cap];
    let mut n = 0usize;
    // SAFETY: the buffers are valid for the lengths passed
    let c = unsafe {
        ffi::nqkopen(
            a.id,
            sk.as_ptr(),
            sk.len(),
            ctx.as_ptr(),
            ctx.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            cap,
            &mut n,
        )
    };
    if c != 0 {
        crate::wipe(&mut out);
        return Err(Error::new(c));
    }
    let m = out[..n].to_vec();
    crate::wipe(&mut out);
    Ok(m)
}

/// The default chunk size of a sealed stream (NQKFCHUNK).
pub const CHUNK: u32 = 65536;

fn kctx() -> Box<ffi::Kfctx> {
    Box::new(ffi::Kfctx { opq: [0; 16] })
}

type Kfn =
    unsafe extern "C" fn(*mut ffi::Kfctx, *const u8, usize, *mut u8, usize, *mut usize) -> c_int;

fn step(c: &mut ffi::Kfctx, f: Kfn, data: &[u8], cap: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; cap.max(1)];
    let mut n = 0usize;
    // SAFETY: the buffers are valid for the lengths passed
    rc(unsafe { f(c, data.as_ptr(), data.len(), out.as_mut_ptr(), cap, &mut n) })?;
    out.truncate(n);
    Ok(out)
}

/// A stream sealed to an ML-KEM public key (noqtis-kstream-1), the format
/// of `noqtis box`: write [`header`](Boxer::header) first, then
/// [`update`](Boxer::update) for each full chunk and
/// [`finish`](Boxer::finish) for the last (0 to `chunk` bytes; a stream
/// that ends on a full chunk ends with it).
pub struct Boxer {
    c: Box<ffi::Kfctx>,
    hdr: Vec<u8>,
    chunk: usize,
}

impl Boxer {
    /// A stream to `pk` with chunks of `chunk` bytes (1024 to 16777216; 0
    /// for [`CHUNK`]).
    pub fn new(alg: &str, pk: &[u8], ctx: &[u8], chunk: u32) -> Result<Boxer> {
        let a = find(alg, Kind::Kem)?;
        let chunk = if chunk == 0 { CHUNK } else { chunk };
        let mut c = kctx();
        let mut hdr = vec![0u8; 17 + a.ct];
        let mut hl = 0usize;
        // SAFETY: c is a context of the size noqtis.h gives; hdr is cap bytes
        rc(unsafe {
            ffi::nqkfeini(
                &mut *c,
                a.id,
                pk.as_ptr(),
                pk.len(),
                ctx.as_ptr(),
                ctx.len(),
                chunk,
                hdr.as_mut_ptr(),
                hdr.len(),
                &mut hl,
            )
        })?;
        hdr.truncate(hl);
        Ok(Boxer {
            c,
            hdr,
            chunk: chunk as usize,
        })
    }

    /// The stream's header.
    pub fn header(&self) -> &[u8] {
        &self.hdr
    }

    /// The chunk size.
    pub fn chunk(&self) -> usize {
        self.chunk
    }

    /// One full chunk, sealed.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        step(&mut self.c, ffi::nqkfeupd, data, self.chunk + 16)
    }

    /// The last chunk, sealed; the stream ends.
    pub fn finish(mut self, data: &[u8]) -> Result<Vec<u8>> {
        step(&mut self.c, ffi::nqkfefin, data, self.chunk + 16)
    }
}

/// Opens what [`Boxer`] wrote: [`new`](Unboxer::new) with the header,
/// then each sealed chunk (`chunk` + 16 bytes) to
/// [`update`](Unboxer::update) and the last to
/// [`finish`](Unboxer::finish). A chunk's plaintext comes back only when
/// its tag verifies ([`Code::Verify`](crate::Code) otherwise: a changed,
/// moved, dropped or cut chunk).
pub struct Unboxer {
    c: Box<ffi::Kfctx>,
    chunk: usize,
}

impl Unboxer {
    /// Reads the header `hdr` (17 bytes and the KEM ciphertext).
    pub fn new(alg: &str, sk: &[u8], hdr: &[u8], ctx: &[u8]) -> Result<Unboxer> {
        let a = find(alg, Kind::Kem)?;
        let mut c = kctx();
        let mut ch = 0u32;
        // SAFETY: c is a context of the size noqtis.h gives
        rc(unsafe {
            ffi::nqkfdini(
                &mut *c,
                a.id,
                sk.as_ptr(),
                sk.len(),
                ctx.as_ptr(),
                ctx.len(),
                hdr.as_ptr(),
                hdr.len(),
                &mut ch,
            )
        })?;
        Ok(Unboxer {
            c,
            chunk: ch as usize,
        })
    }

    /// The chunk size the header gives.
    pub fn chunk(&self) -> usize {
        self.chunk
    }

    /// One sealed chunk, opened.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        step(&mut self.c, ffi::nqkfdupd, data, self.chunk)
    }

    /// The last sealed chunk, opened; the stream ends.
    pub fn finish(mut self, data: &[u8]) -> Result<Vec<u8>> {
        step(&mut self.c, ffi::nqkfdfin, data, self.chunk)
    }
}

macro_rules! wiped {
    ($t:ident) => {
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}(chunk {})", stringify!($t), self.chunk)
            }
        }
        impl Drop for $t {
            fn drop(&mut self) {
                // SAFETY: the context is ours
                unsafe {
                    ffi::nqwipe(
                        self.c.opq.as_mut_ptr().cast(),
                        std::mem::size_of::<ffi::Kfctx>(),
                    )
                }
            }
        }
    };
}
wiped!(Boxer);
wiped!(Unboxer);

fn io(e: std::io::Error) -> Error {
    Error::why(-7, e.to_string())
}

/// Reads up to `b.len()` bytes (fewer only at the end).
fn fill(r: &mut impl Read, b: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < b.len() {
        match r.read(&mut b[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io(e)),
        }
    }
    Ok(n)
}

/// Moves `r` to `w` in pieces of `n` bytes through `f`, its flag true for
/// the last piece (the one no byte follows), one piece in memory.
fn pump(
    r: &mut impl Read,
    w: &mut impl Write,
    n: usize,
    mut f: impl FnMut(&[u8], bool) -> Result<Vec<u8>>,
) -> Result<()> {
    let mut b = vec![0u8; n];
    let mut pre = 0;
    loop {
        let got = pre + fill(r, &mut b[pre..])?;
        let mut nx = [0u8; 1];
        let more = got == n && fill(r, &mut nx)? == 1;
        let o = f(&b[..got], !more);
        crate::wipe(&mut b);
        w.write_all(&o?).map_err(io)?;
        if !more {
            return Ok(());
        }
        b[0] = nx[0];
        pre = 1;
    }
}

/// Seals all of `r` to `w` as `noqtis box` does (the same format), one
/// chunk in memory; `chunk` as for [`Boxer::new`].
pub fn enbox(
    alg: &str,
    pk: &[u8],
    r: &mut impl Read,
    w: &mut impl Write,
    ctx: &[u8],
    chunk: u32,
) -> Result<()> {
    let mut b = Boxer::new(alg, pk, ctx, chunk)?;
    w.write_all(b.header()).map_err(io)?;
    let (n, cap) = (b.chunk, b.chunk + 16);
    pump(r, w, n, |d, last| {
        step(
            &mut b.c,
            if last { ffi::nqkfefin } else { ffi::nqkfeupd },
            d,
            cap,
        )
    })
}

/// Opens a sealed stream from `r` to `w`, chunk by chunk. On an error
/// what was written before the bad chunk had verified, but the stream is
/// incomplete: discard `w`'s output.
pub fn unbox(
    alg: &str,
    sk: &[u8],
    r: &mut impl Read,
    w: &mut impl Write,
    ctx: &[u8],
) -> Result<()> {
    let a = find(alg, Kind::Kem)?;
    let mut h = vec![0u8; 17 + a.ct];
    let hn = fill(r, &mut h)?;
    let mut u = Unboxer::new(alg, sk, &h[..hn], ctx)?;
    let cap = u.chunk;
    pump(r, w, cap + 16, |d, last| {
        step(
            &mut u.c,
            if last { ffi::nqkfdfin } else { ffi::nqkfdupd },
            d,
            cap,
        )
    })
}
