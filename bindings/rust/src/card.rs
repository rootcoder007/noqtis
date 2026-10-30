// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! Identity cards (noqtis-idcard-1): a signing key with its holder's
//! name and, when given, ORCID iD, e-mail address, web page and
//! affiliation, signed by the key itself under the card's own context, so
//! that a card is never taken for a seal or a key statement.
//!
//! A card is self-signed: it shows that whoever holds the key wrote it
//! and that it is unchanged, not that the name is true. Compare
//! [`Card::key_sha256`] with the one its holder published, or pin the key.
//!
//! ```
//! use noqtis::{card, sign};
//!
//! let (pk, sk) = sign::keygen("ML-DSA-44", None)?;
//! let f = card::Fields {
//!     orcid: Some("0000-0002-1825-0097"),
//!     ..card::Fields::new("Ada Lovelace")
//! };
//! let c = card::make("ML-DSA-44", &sk, &pk, &f, None)?;
//! let v = card::verify(&c, Some(&pk))?.expect("it verifies");
//! assert_eq!(v.orcid.as_deref(), Some("0000-0002-1825-0097"));
//! # Ok::<(), noqtis::Error>(())
//! ```

use crate::{ffi, find, rc, Error, Kind, Result};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

/// What a card says: `name` and the optional fields. Each is checked by
/// the library: `name` and `affil` 1 to 255 bytes of text, no control
/// character, no space at either end; `orcid` an ORCID iD (or its
/// `https://orcid.org/` address) whose check digit is right; `email`
/// `local@domain.tld` in at most 254 bytes; `url` an `https://` address
/// in at most 1024 bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fields<'a> {
    /// Your name, as you want it shown.
    pub name: &'a str,
    /// Your ORCID iD.
    pub orcid: Option<&'a str>,
    /// Your e-mail address.
    pub email: Option<&'a str>,
    /// Your web page.
    pub url: Option<&'a str>,
    /// Your affiliation.
    pub affil: Option<&'a str>,
}

impl<'a> Fields<'a> {
    /// A card's fields with the name alone.
    pub fn new(name: &'a str) -> Fields<'a> {
        Fields {
            name,
            ..Fields::default()
        }
    }
}

/// A card that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    /// The name.
    pub name: String,
    /// The bare ORCID iD, when the card has one.
    pub orcid: Option<String>,
    /// The e-mail address, when the card has one.
    pub email: Option<String>,
    /// The web page, when the card has one.
    pub url: Option<String>,
    /// The affiliation, when the card has one.
    pub affil: Option<String>,
    /// When it was made, `YYYY-MM-DDTHH:MM:SSZ`.
    pub created: String,
    /// The key's algorithm.
    pub alg: String,
    /// The public key.
    pub pk: Vec<u8>,
    /// The SHA-256 of the public key, hex (as `noqtis inspect` shows a
    /// seal's key).
    pub key_sha256: String,
}

fn cs(s: &str, what: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::why(-1, format!("{what}: a NUL character")))
}

fn opt(s: Option<&str>, what: &str) -> Result<Option<CString>> {
    s.map(|v| cs(v, what)).transpose()
}

fn p(s: &Option<CString>) -> *const c_char {
    s.as_ref().map_or(ptr::null(), |x| x.as_ptr())
}

/// An identity card (JSON) for the key pair (sk, pk) of `alg`, made at
/// `created` (seconds since 1970, UTC; `None` for now) and signed by it.
/// The card holds the bare ORCID iD. A field out of its limits, or keys
/// that are not one pair, are [`crate::Code::Arg`]; Ed25519 alone is
/// [`crate::Code::Unsupported`].
pub fn make(alg: &str, sk: &[u8], pk: &[u8], f: &Fields, created: Option<i64>) -> Result<Vec<u8>> {
    let a = find(alg, Kind::Sign)?;
    let at = match created {
        Some(t) => t,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    };
    let n = cs(f.name, "name")?;
    let o = opt(f.orcid, "orcid")?;
    let e = opt(f.email, "email")?;
    let u = opt(f.url, "url")?;
    let af = opt(f.affil, "affil")?;
    let call = |out: *mut c_char, cap: usize, len: &mut usize| {
        // SAFETY: the strings are NUL-terminated, the keys and out valid
        unsafe {
            ffi::nqcard(
                a.id,
                sk.as_ptr(),
                sk.len(),
                pk.as_ptr(),
                pk.len(),
                n.as_ptr(),
                p(&o),
                p(&e),
                p(&u),
                p(&af),
                at,
                out,
                cap,
                len,
            )
        }
    };
    let mut len = 0usize;
    let c = call(ptr::null_mut(), 0, &mut len);
    if c != ffi::NQEBUF {
        rc(c)?;
    }
    let mut out = vec![0u8; len];
    rc(call(out.as_mut_ptr() as *mut c_char, out.len(), &mut len))?;
    out.truncate(len);
    Ok(out)
}

fn text(b: &[c_char]) -> String {
    // SAFETY: the library NUL-terminates every field within its array
    unsafe { CStr::from_ptr(b.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn some(b: &[c_char]) -> Option<String> {
    let s = text(b);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Checks a card (at most 256 KiB): `Ok(Some(card))` when it verifies
/// and, with `pk`, is for that public key; `Ok(None)` when its signature
/// does not verify or it is for another key. Input that is not a card is
/// [`crate::Code::Decode`].
pub fn verify(card: &[u8], pk: Option<&[u8]>) -> Result<Option<Card>> {
    // SAFETY: nqcardf is plain data; all zero is a valid value
    let mut f: Box<ffi::Cardf> = Box::new(unsafe { std::mem::zeroed() });
    let (pp, pl) = pk.map_or((ptr::null(), 0), |k| (k.as_ptr(), k.len()));
    // SAFETY: card and pk are valid for their lengths, f for its size
    let c = unsafe { ffi::nqcardvrfy(card.as_ptr() as *const c_char, card.len(), pp, pl, &mut *f) };
    if c == ffi::NQEVRFY {
        return Ok(None);
    }
    rc(c)?;
    // SAFETY: a static name for an algorithm the card was verified with
    let alg = unsafe { CStr::from_ptr(ffi::nqsname(f.alg)) }
        .to_string_lossy()
        .into_owned();
    Ok(Some(Card {
        name: text(&f.name),
        orcid: some(&f.orcid),
        email: some(&f.email),
        url: some(&f.url),
        affil: some(&f.affil),
        created: text(&f.utc),
        alg,
        pk: f.pk[..f.pklen.min(f.pk.len())].to_vec(),
        key_sha256: f.fp.iter().map(|x| format!("{x:02x}")).collect(),
    }))
}
