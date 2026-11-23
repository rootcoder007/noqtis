// SPDX-License-Identifier: LGPL-3.0-or-later
//! Keys on a token, through PKCS #11: a smart card, a hardware security
//! module, or a software token. The private key stays there; the token
//! signs and decapsulates. The post-quantum key types are those of
//! PKCS #11 version 3.2.
//!
//! ```no_run
//! use noqtis::token::Token;
//!
//! let mut t = Token::open("/usr/lib/softhsm/libsofthsm2.so")?;
//! let slot = t.tokens()?[0].slot;
//! t.login(slot, Some("1234"))?;
//! let k = t.generate("ML-DSA-65", "release")?;
//! let sig = t.sign(&k, b"a release", &[])?;
//! # Ok::<(), noqtis::Error>(())
//! ```

use crate::mail::{algname, cs, out, text};
use crate::{alg as findalg, ffi, find, rc, Kind, Result};
use std::os::raw::{c_char, c_int};
use std::ptr;

/// A loaded PKCS #11 module. Dropping it ends the session and unloads
/// the module.
pub struct Token {
    p: *mut ffi::P11,
}

/// One token present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// Its slot, for [`Token::login`].
    pub slot: u64,
    /// Its label.
    pub label: String,
    /// Its maker.
    pub maker: String,
    /// Its model.
    pub model: String,
    /// Its serial number.
    pub serial: String,
    /// Whether its keys need the PIN.
    pub login: bool,
}

/// A private key on a token that noqtis can use.
#[derive(Clone)]
pub struct Key {
    /// Its algorithm.
    pub alg: String,
    /// Whether it is a KEM key.
    pub kem: bool,
    /// Its label.
    pub label: String,
    /// Its ID.
    pub id: Vec<u8>,
    k: ffi::P11k,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("alg", &self.alg)
            .field("kem", &self.kem)
            .field("label", &self.label)
            .field("id", &self.id)
            .finish()
    }
}

fn keyof(k: &ffi::P11k) -> Key {
    Key {
        alg: algname(k.kem != 0, k.alg),
        kem: k.kem != 0,
        label: text(&k.label),
        id: k.id[..k.idlen.min(32)].to_vec(),
        k: *k,
    }
}

impl Token {
    /// Loads the PKCS #11 module at the path `module` and starts it.
    /// The path must have a folder in it: a bare name, which the system
    /// would search for, is [`crate::Code::Arg`].
    pub fn open(module: &str) -> Result<Token> {
        let m = cs(module, "the module")?;
        let mut p: *mut ffi::P11 = ptr::null_mut();
        // SAFETY: m is NUL-terminated, p a valid place for the handle
        rc(unsafe { ffi::nqp11open(m.as_ptr(), &mut p) })?;
        Ok(Token { p })
    }

    /// The module's own return value for the last call it refused: a
    /// CKR number of the standard.
    #[allow(clippy::unnecessary_cast)] // c_ulong is 32 bits on Windows
    pub fn why(&self) -> u64 {
        // SAFETY: p is a live handle
        unsafe { ffi::nqp11why(self.p) as u64 }
    }

    /// The tokens present.
    #[allow(clippy::unnecessary_cast)] // c_ulong is 32 bits on Windows
    pub fn tokens(&mut self) -> Result<Vec<Info>> {
        // SAFETY: nqp11t is plain data; all zero is a valid value
        let mut ts: Vec<ffi::P11t> = (0..64).map(|_| unsafe { std::mem::zeroed() }).collect();
        let mut n = 0usize;
        // SAFETY: ts has 64 entries
        rc(unsafe { ffi::nqp11toks(self.p, ts.as_mut_ptr(), 64, &mut n) })?;
        Ok(ts[..n.min(64)]
            .iter()
            .map(|t| Info {
                slot: t.slot as u64,
                label: text(&t.label),
                maker: text(&t.maker),
                model: text(&t.model),
                serial: text(&t.serial),
                login: t.login != 0,
            })
            .collect())
    }

    /// Opens a session with the token in `slot` and, with a PIN, logs
    /// the user in. [`crate::Code::Verify`] for a wrong or locked PIN.
    pub fn login(&mut self, slot: u64, pin: Option<&str>) -> Result<()> {
        let (pp, pl) = pin.map_or((ptr::null(), 0), |p| (p.as_ptr() as *const c_char, p.len()));
        // SAFETY: the PIN is valid for its length
        rc(unsafe { ffi::nqp11login(self.p, slot as _, pp, pl) })
    }

    /// The private keys of the token that noqtis can use. A token shows
    /// its private keys after the PIN.
    pub fn keys(&mut self) -> Result<Vec<Key>> {
        // SAFETY: nqp11k is plain data; all zero is a valid value
        let mut ks: Vec<ffi::P11k> = (0..64).map(|_| unsafe { std::mem::zeroed() }).collect();
        let mut n = 0usize;
        // SAFETY: ks has 64 entries
        let c = unsafe { ffi::nqp11keys(self.p, ks.as_mut_ptr(), 64, &mut n) };
        if c != ffi::NQEBUF {
            rc(c)?;
        }
        Ok(ks[..n.min(64)].iter().map(keyof).collect())
    }

    /// The public key of `k`, as [`crate::sign::verify`] and
    /// [`crate::kem::encap`] take it.
    pub fn public_key(&mut self, k: &Key) -> Result<Vec<u8>> {
        out(4096, |p, cap, got| {
            // SAFETY: k.k is a key of this handle, p valid for cap
            unsafe { ffi::nqp11pub(self.p, &k.k, p, cap, got) }
        })
    }

    /// Signs `msg` on the token with the signature key `k` and the
    /// context `ctx` (empty for none): the signature
    /// [`crate::sign::sign`] makes, which [`crate::sign::verify`]
    /// checks.
    pub fn sign(&mut self, k: &Key, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
        let a = find(&k.alg, Kind::Sign)?;
        let cp = if ctx.is_empty() {
            ptr::null()
        } else {
            ctx.as_ptr()
        };
        out(a.sig, |p, cap, got| {
            // SAFETY: every buffer is valid for its length
            unsafe {
                ffi::nqp11sign(
                    self.p,
                    &k.k,
                    msg.as_ptr(),
                    msg.len(),
                    cp,
                    ctx.len(),
                    p,
                    cap,
                    got,
                )
            }
        })
    }

    /// Decapsulates the ML-KEM ciphertext `ct` on the token with the
    /// key `k`. The module must be of PKCS #11 version 3.2; an older
    /// one is [`crate::Code::Unsupported`].
    pub fn decap(&mut self, k: &Key, ct: &[u8]) -> Result<Vec<u8>> {
        let a = find(&k.alg, Kind::Kem)?;
        let mut ss = vec![0u8; a.ss];
        // SAFETY: ct and ss are valid for their lengths
        rc(unsafe {
            ffi::nqp11dec(
                self.p,
                &k.k,
                ct.as_ptr(),
                ct.len(),
                ss.as_mut_ptr(),
                ss.len(),
            )
        })?;
        Ok(ss)
    }

    /// Makes a key pair of `alg` on the token under `label`; the
    /// private key is marked never to leave it.
    pub fn generate(&mut self, alg: &str, label: &str) -> Result<Key> {
        let a = findalg(alg)?;
        let l = cs(label, "the label")?;
        // SAFETY: nqp11k is plain data; all zero is a valid value
        let mut k: ffi::P11k = unsafe { std::mem::zeroed() };
        // SAFETY: l is NUL-terminated, k valid for its size
        rc(unsafe {
            ffi::nqp11gen(
                self.p,
                (a.kind == Kind::Kem) as c_int,
                a.id,
                l.as_ptr(),
                &mut k,
            )
        })?;
        Ok(keyof(&k))
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: p came from nqp11open and is closed once
        unsafe { ffi::nqp11close(self.p) }
    }
}
