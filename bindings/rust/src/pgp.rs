// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! OpenPGP (RFC 9580) in its version 6 forms, with Ed25519 and X25519
//! and the post-quantum algorithms of draft-ietf-openpgp-pqc: keys,
//! signatures and encrypted messages. Keys and messages are binary
//! packets; [`armor`] and [`dearmor`] make them text and back, and
//! [`verify`] and [`decrypt`] take either.
//!
//! ```
//! use noqtis::pgp;
//!
//! let (sec, cert) = pgp::generate(pgp::ED25519, pgp::X25519, "Ada <ada@example.org>", None, None)?;
//! let s = pgp::sign(&sec, None, b"hello", pgp::Mode::Inline, None)?;
//! let (data, _when) = pgp::verify(&cert, &s, None)?;
//! assert_eq!(data, b"hello");
//! # Ok::<(), noqtis::Error>(())
//! ```

use crate::mail::{cs, now, out, string, text};
use crate::{ffi, rc, Result};
use std::os::raw::{c_char, c_int};
use std::ptr;

/// X25519 (RFC 9580), an encryption subkey.
pub const X25519: i32 = 25;
/// Ed25519 (RFC 9580).
pub const ED25519: i32 = 27;
/// ML-DSA-65 with Ed25519.
pub const MLDSA65: i32 = 30;
/// SLH-DSA-SHAKE-128s.
pub const SLH128S: i32 = 32;
/// SLH-DSA-SHAKE-128f.
pub const SLH128F: i32 = 33;
/// SLH-DSA-SHAKE-256s.
pub const SLH256S: i32 = 34;
/// ML-KEM-768 with X25519, an encryption subkey.
pub const MLKEM768: i32 = 35;

/// How [`sign`] signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A signed message that carries the data.
    Inline,
    /// The signature alone.
    Detached,
    /// The text with the armored signature under it.
    Clear,
}

/// The kinds of OpenPGP armor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Armor {
    /// PGP MESSAGE
    Message = 1,
    /// PGP PUBLIC KEY BLOCK
    PublicKey = 2,
    /// PGP PRIVATE KEY BLOCK
    PrivateKey = 3,
    /// PGP SIGNATURE
    Signature = 4,
}

/// What an OpenPGP key or certificate says of itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    /// The primary key's algorithm.
    pub alg: i32,
    /// The encryption subkey's, 0 when it has none.
    pub encalg: i32,
    /// A secret key.
    pub secret: bool,
    /// Under a passphrase.
    pub locked: bool,
    /// The primary key's fingerprint.
    pub fingerprint: [u8; 32],
    /// The encryption subkey's.
    pub encfingerprint: Option<[u8; 32]>,
    /// Seconds since 1970.
    pub created: i64,
    /// When it expires; `None`: never.
    pub expires: Option<i64>,
    /// The user ID.
    pub userid: String,
}

fn opt(b: Option<&[u8]>) -> (*const u8, usize) {
    b.map_or((ptr::null(), 0), |b| (b.as_ptr(), b.len()))
}

/// Makes a version 6 OpenPGP key: a primary key of `sigalg` that
/// certifies and signs, the user ID `uid` (by convention
/// `Name <address>`), and, when `encalg` is not 0, an encryption
/// subkey. It gives the secret key, under `passphrase` when there is
/// one, and the certificate to give to others.
pub fn generate(
    sigalg: i32,
    encalg: i32,
    uid: &str,
    created: Option<i64>,
    passphrase: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    const N: usize = 1 << 18;
    let u = cs(uid, "the user ID")?;
    let (pp, pl) = opt(passphrase);
    let mut sec = vec![0u8; N];
    let mut pubk = vec![0u8; N];
    let (mut sn, mut pn) = (0usize, 0usize);
    // SAFETY: u is NUL-terminated, every buffer valid for its length
    let c = unsafe {
        ffi::nqpgpgen(
            sigalg,
            encalg,
            u.as_ptr(),
            now(created),
            pp,
            pl,
            sec.as_mut_ptr(),
            N,
            &mut sn,
            pubk.as_mut_ptr(),
            N,
            &mut pn,
        )
    };
    if c != ffi::NQOK {
        crate::wipe(&mut sec);
        rc(c)?;
    }
    let out_sec = sec[..sn].to_vec();
    crate::wipe(&mut sec);
    pubk.truncate(pn);
    Ok((out_sec, pubk))
}

/// Reads an OpenPGP key or certificate (binary). Only what a
/// self-signature of the primary key binds is taken; a key with none,
/// or a revoked one, is [`crate::Code::Verify`].
pub fn info(key: &[u8]) -> Result<Key> {
    // SAFETY: nqpgpk is plain data; all zero is a valid value
    let mut f: ffi::Pgpk = unsafe { std::mem::zeroed() };
    // SAFETY: key is valid for its length, f for its size
    rc(unsafe { ffi::nqpgpinfo(key.as_ptr(), key.len(), &mut f) })?;
    Ok(Key {
        alg: f.alg,
        encalg: f.encalg,
        secret: f.secret != 0,
        locked: f.locked != 0,
        fingerprint: f.fp,
        encfingerprint: (f.encalg != 0).then_some(f.encfp),
        created: f.created,
        expires: (f.expires != 0).then_some(f.expires),
        userid: text(&f.uid),
    })
}

/// Signs `msg` with the secret key. The result is binary packets,
/// except [`Mode::Clear`], which is text.
pub fn sign(
    key: &[u8],
    passphrase: Option<&[u8]>,
    msg: &[u8],
    mode: Mode,
    at: Option<i64>,
) -> Result<Vec<u8>> {
    let (pp, pl) = opt(passphrase);
    out(3 * msg.len() + (1 << 17), |p, cap, got| {
        // SAFETY: every buffer is valid for its length
        unsafe {
            ffi::nqpgpsign(
                key.as_ptr(),
                key.len(),
                pp,
                pl,
                msg.as_ptr(),
                msg.len(),
                mode as c_int,
                now(at),
                p,
                cap,
                got,
            )
        }
    })
}

/// Checks a signed message, a cleartext signature or a detached
/// signature (`msg` is then what it signs), armored or binary, under
/// the certificate `cert`. It gives the data that was signed and the
/// time of the signature; [`crate::Code::Verify`] when it does not
/// verify.
pub fn verify(cert: &[u8], sig: &[u8], msg: Option<&[u8]>) -> Result<(Vec<u8>, i64)> {
    let (mp, ml) = opt(msg);
    let mut at = 0i64;
    let b = out(sig.len() + ml + 1, |p, cap, got| {
        // SAFETY: every buffer is valid for its length
        unsafe {
            ffi::nqpgpvrfy(
                cert.as_ptr(),
                cert.len(),
                sig.as_ptr(),
                sig.len(),
                mp,
                ml,
                p,
                cap,
                got,
                &mut at,
            )
        }
    })?;
    Ok((b, at))
}

/// Encrypts `msg` to the encryption subkeys of `certs` (at most 64)
/// and, with `passphrase`, to that passphrase as well: AES-256 with
/// OCB. With `signer`, a secret key and its passphrase, the message is
/// signed first.
pub fn encrypt(
    certs: &[&[u8]],
    passphrase: Option<&[u8]>,
    signer: Option<(&[u8], Option<&[u8]>)>,
    msg: &[u8],
    at: Option<i64>,
) -> Result<Vec<u8>> {
    let cp: Vec<*const u8> = certs.iter().map(|c| c.as_ptr()).collect();
    let cl: Vec<usize> = certs.iter().map(|c| c.len()).collect();
    let (pp, pl) = opt(passphrase);
    let (sp, sl) = opt(signer.map(|s| s.0));
    let (wp, wl) = opt(signer.and_then(|s| s.1));
    let n = msg.len() + msg.len() / 512 + 2048 * certs.len() + (1 << 17);
    out(n, |p, cap, got| {
        // SAFETY: every buffer is valid for its length, the lists for nc
        unsafe {
            ffi::nqpgpenc(
                cp.as_ptr(),
                cl.as_ptr(),
                cp.len(),
                pp,
                pl,
                sp,
                sl,
                wp,
                wl,
                msg.as_ptr(),
                msg.len(),
                now(at),
                p,
                cap,
                got,
            )
        }
    })
}

/// What [`decrypt`] opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// The content.
    pub data: Vec<u8>,
    /// Whether the signature of the `signer` certificate verified.
    pub signed: bool,
    /// The time of that signature, 0 when not checked.
    pub at: i64,
}

/// Opens an encrypted message, armored or binary, with the secret key
/// (`passphrase` is then the key's) or, with `key` `None`, with the
/// passphrase of the message. With `signer`, a certificate, the message
/// inside must be signed by it. [`crate::Code::Verify`] when it does
/// not open or the signature does not verify.
pub fn decrypt(
    key: Option<&[u8]>,
    passphrase: Option<&[u8]>,
    signer: Option<&[u8]>,
    msg: &[u8],
) -> Result<Opened> {
    let (kp, kl) = opt(key);
    let (pp, pl) = opt(passphrase);
    let (sp, sl) = opt(signer);
    let mut sb: c_int = 0;
    let mut at = 0i64;
    let data = out(msg.len() + 1, |p, cap, got| {
        // SAFETY: every buffer is valid for its length
        unsafe {
            ffi::nqpgpdec(
                kp,
                kl,
                pp,
                pl,
                sp,
                sl,
                msg.as_ptr(),
                msg.len(),
                p,
                cap,
                got,
                &mut sb,
                &mut at,
            )
        }
    })?;
    Ok(Opened {
        data,
        signed: sb != 0,
        at,
    })
}

/// Writes OpenPGP packets as ASCII armor.
pub fn armor(kind: Armor, data: &[u8]) -> Result<String> {
    let mut n = 0usize;
    // SAFETY: data is valid for its length; a NULL output asks the size
    rc(unsafe {
        ffi::nqpgparm(
            kind as c_int,
            data.as_ptr(),
            data.len(),
            ptr::null_mut(),
            0,
            &mut n,
        )
    })?;
    string(out(n, |p, cap, got| {
        // SAFETY: data and p are valid for their lengths
        unsafe {
            ffi::nqpgparm(
                kind as c_int,
                data.as_ptr(),
                data.len(),
                p as *mut c_char,
                cap,
                got,
            )
        }
    })?)
}

/// Reads one OpenPGP armor back: its kind and its packets.
pub fn dearmor(text_in: &str) -> Result<(Armor, Vec<u8>)> {
    let mut kind: c_int = 0;
    let b = out(text_in.len(), |p, cap, got| {
        // SAFETY: the input and p are valid for their lengths
        unsafe {
            ffi::nqpgpdearm(
                text_in.as_ptr() as *const c_char,
                text_in.len(),
                &mut kind,
                p,
                cap,
                got,
            )
        }
    })?;
    let k = match kind {
        1 => Armor::Message,
        2 => Armor::PublicKey,
        3 => Armor::PrivateKey,
        _ => Armor::Signature,
    };
    Ok((k, b))
}
