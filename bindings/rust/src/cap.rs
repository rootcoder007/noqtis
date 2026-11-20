// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! Capsules: a folder sealed with a manifest of every file in it
//! (`noqtis.json`) and a post-quantum signature over it (`noqtis.sig`),
//! the same files the `noqtis` command writes and checks.
//!
//! ```no_run
//! use noqtis::{cap, sign};
//!
//! let (pk, sk) = sign::keygen("ML-DSA-65", None)?;
//! cap::seal("results", "ML-DSA-65", &sk, &pk, Some(r#"{"project":"x"}"#))?;
//! let o = cap::Opts { trust: Some(pk), ..cap::Opts::default() };
//! let r = cap::check("results", &o)?;
//! assert!(r.ok());
//! # Ok::<(), noqtis::Error>(())
//! ```

use crate::{ffi, find, rc, Error, Kind, Result};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};
use std::ptr;

/// One check of a capsule: its name, whether it passed, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// "manifest.digest", "file", "key", "info.alg", ...
    pub check: String,
    /// Whether it passed.
    pub ok: bool,
    /// What was found.
    pub detail: String,
}

/// What a check (or [`inspect`]) found: every row, and the library's
/// return code (0, or a negative `NQE*` code such as -3 when a check
/// failed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The library's return code.
    pub code: i32,
    /// Every check, in order.
    pub rows: Vec<Row>,
}

impl Report {
    /// `true` when every check made passed. With [`Report::partial`]
    /// `true` those checks left files out (`only`, a proof) and `ok` says
    /// nothing of the others: the capsule passed as a whole only when
    /// `ok() && !partial()`.
    pub fn ok(&self) -> bool {
        self.code == 0 && self.rows.iter().all(|r| r.ok)
    }

    /// `true` when only some files were checked (a "partial" row says
    /// which were left out).
    pub fn partial(&self) -> bool {
        self.get("partial").is_some()
    }

    /// The rows that did not pass.
    pub fn failed(&self) -> Vec<&Row> {
        self.rows.iter().filter(|r| !r.ok).collect()
    }

    /// The first row of that name ("info.alg", "key", ...).
    pub fn get(&self, check: &str) -> Option<&Row> {
        self.rows.iter().find(|r| r.check == check)
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for r in &self.rows {
            let s = if r.ok { "ok" } else { "FAIL" };
            writeln!(f, "{s:<4} {}: {}", r.check, r.detail)?;
        }
        Ok(())
    }
}

/// What [`check`] and [`checkp`] check beyond the seal itself; every
/// member may be empty.
#[derive(Debug, Clone, Default)]
pub struct Opts {
    /// The public key the seal must carry; `None` accepts the key in the
    /// seal (the `key` row then says so).
    pub trust: Option<Vec<u8>>,
    /// TSA trust anchors (DER certificates, at most 32): the seal must
    /// then carry an RFC 3161 timestamp that verifies under one of them.
    pub anchors: Vec<Vec<u8>>,
    /// A partial check: only these paths ('/' separated).
    pub only: Vec<String>,
    /// Capsule folders to find a format 2 capsule's inputs in.
    pub lineage: Vec<PathBuf>,
    /// Key statements (noqtis-keys-1), at most 32; they need `trust`.
    pub stmts: Vec<Vec<u8>>,
}

/// An input of a format 2 capsule: the input capsule's id ([`capid`]) and
/// a short name for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// The input capsule's id.
    pub id: [u8; 32],
    /// 1 to 255 bytes of UTF-8, no control character.
    pub name: String,
}

fn cs(s: &[u8], what: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::why(-1, format!("{what}: a NUL byte")))
}

/// A folder as the bytes the library takes (UTF-8 on Windows).
pub(crate) fn cpath(p: &Path) -> Result<CString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        cs(p.as_os_str().as_bytes(), "path")
    }
    #[cfg(not(unix))]
    {
        match p.to_str() {
            Some(s) => cs(s.as_bytes(), "path"),
            None => Err(Error::why(-1, "path: not valid Unicode")),
        }
    }
}

fn copt(s: Option<&str>) -> Result<Option<CString>> {
    s.map(|m| cs(m.as_bytes(), "meta")).transpose()
}

/// Writes noqtis.json and noqtis.sig into `dir` (format 1), covering
/// every regular file in it. `meta` is JSON text (an object) kept in the
/// manifest. The creation time is SOURCE_DATE_EPOCH when set, else the
/// clock.
pub fn seal(
    dir: impl AsRef<Path>,
    alg: &str,
    sk: &[u8],
    pk: &[u8],
    meta: Option<&str>,
) -> Result<()> {
    let a = find(alg, Kind::Sign)?;
    let d = cpath(dir.as_ref())?;
    let m = copt(meta)?;
    // SAFETY: the strings are NUL-terminated and the buffers valid
    rc(unsafe {
        ffi::nqseal(
            d.as_ptr(),
            a.id,
            sk.as_ptr(),
            sk.len(),
            pk.as_ptr(),
            pk.len(),
            m.as_ref().map_or(ptr::null(), |x| x.as_ptr()),
            ptr::null(),
        )
    })
}

/// [`seal`] in format 2: the manifest also carries a Merkle tree over its
/// entries, so that [`prove`] can show single files without the rest,
/// and the capsules it was made from (`inputs`, at most 1024).
pub fn seal2(
    dir: impl AsRef<Path>,
    alg: &str,
    sk: &[u8],
    pk: &[u8],
    meta: Option<&str>,
    inputs: &[Input],
) -> Result<()> {
    let a = find(alg, Kind::Sign)?;
    let d = cpath(dir.as_ref())?;
    let m = copt(meta)?;
    let names = inputs
        .iter()
        .map(|i| cs(i.name.as_bytes(), "input name"))
        .collect::<Result<Vec<_>>>()?;
    let ins: Vec<ffi::Cin> = inputs
        .iter()
        .zip(&names)
        .map(|(i, n)| ffi::Cin {
            id: i.id,
            name: n.as_ptr(),
        })
        .collect();
    // SAFETY: the strings and the array live until the call returns
    rc(unsafe {
        ffi::nqseal2(
            d.as_ptr(),
            a.id,
            sk.as_ptr(),
            sk.len(),
            pk.as_ptr(),
            pk.len(),
            m.as_ref().map_or(ptr::null(), |x| x.as_ptr()),
            if ins.is_empty() {
                ptr::null()
            } else {
                ins.as_ptr()
            },
            ins.len(),
        )
    })
}

/// The id of the capsule in `dir`: the SHA-256 of the bytes its seal
/// signs. Nothing else is checked: check the capsule first.
pub fn capid(dir: impl AsRef<Path>) -> Result<[u8; 32]> {
    let d = cpath(dir.as_ref())?;
    let mut id = [0u8; 32];
    // SAFETY: id holds 32 bytes
    rc(unsafe { ffi::nqcapid(d.as_ptr(), id.as_mut_ptr()) })?;
    Ok(id)
}

fn text(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the report's strings are NUL-terminated
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// The report the library made (freed here), or the error when it made
/// none.
fn report(code: c_int, r: *mut ffi::Rep) -> Result<Report> {
    if r.is_null() {
        return Err(Error::new(if code == 0 { -10 } else { code }));
    }
    let mut rows = Vec::new();
    // SAFETY: r is a report from the library, freed once below
    unsafe {
        for i in 0..ffi::nqrepn(r) {
            let mut c = ptr::null();
            let mut d = ptr::null();
            let mut ok: c_int = 0;
            if ffi::nqrepi(r, i, &mut c, &mut ok, &mut d) != ffi::NQOK {
                break;
            }
            rows.push(Row {
                check: text(c),
                ok: ok != 0,
                detail: text(d),
            });
        }
        ffi::nqrepfree(r);
    }
    Ok(Report { code, rows })
}

/// The C view of [`Opts`]; the vectors keep its pointers alive.
struct Co {
    anc: Vec<*const u8>,
    ancl: Vec<usize>,
    _only: Vec<CString>,
    onlyp: Vec<*const c_char>,
    _lin: Vec<CString>,
    linp: Vec<*const c_char>,
    st: Vec<*const c_char>,
    stl: Vec<usize>,
}

fn nul<T>(v: &[T]) -> *const T {
    if v.is_empty() {
        ptr::null()
    } else {
        v.as_ptr()
    }
}

impl Co {
    fn new(o: &Opts) -> Result<Co> {
        let only = o
            .only
            .iter()
            .map(|s| cs(s.as_bytes(), "only"))
            .collect::<Result<Vec<_>>>()?;
        let lin = o
            .lineage
            .iter()
            .map(|p| cpath(p))
            .collect::<Result<Vec<_>>>()?;
        Ok(Co {
            anc: o.anchors.iter().map(|a| a.as_ptr()).collect(),
            ancl: o.anchors.iter().map(|a| a.len()).collect(),
            onlyp: only.iter().map(|s| s.as_ptr()).collect(),
            _only: only,
            linp: lin.iter().map(|s| s.as_ptr()).collect(),
            _lin: lin,
            st: o
                .stmts
                .iter()
                .map(|s| s.as_ptr() as *const c_char)
                .collect(),
            stl: o.stmts.iter().map(|s| s.len()).collect(),
        })
    }

    fn raw(&self, o: &Opts) -> ffi::Copt {
        let (t, tl) = match &o.trust {
            Some(t) => (t.as_ptr(), t.len()),
            None => (ptr::null(), 0),
        };
        ffi::Copt {
            trust: t,
            trustlen: tl,
            anc: nul(&self.anc),
            anclen: nul(&self.ancl),
            nanc: self.anc.len(),
            only: nul(&self.onlyp),
            nonly: self.onlyp.len(),
            lin: nul(&self.linp),
            nlin: self.linp.len(),
            stmt: nul(&self.st),
            stmtlen: nul(&self.stl),
            nstmt: self.st.len(),
        }
    }
}

/// Checks `dir` against its seal, with the options of `o`. The report
/// lists every check; [`Report::ok`] is `true` only when all passed.
/// A failed check is a report, not an error.
pub fn check(dir: impl AsRef<Path>, o: &Opts) -> Result<Report> {
    let d = cpath(dir.as_ref())?;
    let c = Co::new(o)?;
    let x = c.raw(o);
    let mut r = ptr::null_mut();
    // SAFETY: x points into c and o, alive across the call
    let code = unsafe { ffi::nqchkx(d.as_ptr(), &x, &mut r) };
    report(code, r)
}

/// What the capsule in `dir` says, with nothing checked: the report ends
/// with info.format, info.alg, info.key, info.created, info.files,
/// info.bytes, info.timestamp and, when there is one, info.meta.
pub fn inspect(dir: impl AsRef<Path>) -> Result<Report> {
    let d = cpath(dir.as_ref())?;
    let mut r = ptr::null_mut();
    // SAFETY: d is NUL-terminated
    let code = unsafe { ffi::nqinsp(d.as_ptr(), &mut r) };
    report(code, r)
}

/// [`inspect`], with one "info.file" row per listed file first: its size,
/// SHA-256 and path, with a space between.
pub fn files(dir: impl AsRef<Path>) -> Result<Report> {
    let d = cpath(dir.as_ref())?;
    let mut r = ptr::null_mut();
    // SAFETY: d is NUL-terminated
    let code = unsafe { ffi::nqfiles(d.as_ptr(), &mut r) };
    report(code, r)
}

/// A proof (noqtis-proof-1, JSON) that the files `paths` are in the
/// format 2 capsule in `dir`, which shows nothing of the other files.
/// Check the capsule first.
pub fn prove(dir: impl AsRef<Path>, paths: &[&str]) -> Result<Vec<u8>> {
    let d = cpath(dir.as_ref())?;
    let ps = paths
        .iter()
        .map(|p| cs(p.as_bytes(), "path"))
        .collect::<Result<Vec<_>>>()?;
    let pp: Vec<*const c_char> = ps.iter().map(|p| p.as_ptr()).collect();
    let mut n = 0usize;
    // SAFETY: a size query (out NULL, cap 0) then the real call
    let c = unsafe { ffi::nqprove(d.as_ptr(), nul(&pp), pp.len(), ptr::null_mut(), 0, &mut n) };
    if c != ffi::NQEBUF {
        rc(c)?;
    }
    let mut out = vec![0u8; n];
    let c = unsafe {
        ffi::nqprove(
            d.as_ptr(),
            nul(&pp),
            pp.len(),
            out.as_mut_ptr() as *mut c_char,
            out.len(),
            &mut n,
        )
    };
    rc(c)?;
    out.truncate(n);
    Ok(out)
}

/// Checks a proof from [`prove`]: its seal (with `o`'s trusted key and
/// TSA anchors; its other members are not used) and each entry's audit
/// path; with `dir`, each proven file there against its entry.
pub fn checkp(proof: &[u8], o: &Opts, dir: Option<&Path>) -> Result<Report> {
    let d = dir.map(cpath).transpose()?;
    let c = Co::new(o)?;
    let x = c.raw(o);
    let mut r = ptr::null_mut();
    // SAFETY: x points into c and o; proof is passed with its length
    let code = unsafe {
        ffi::nqchkp(
            proof.as_ptr() as *const c_char,
            proof.len(),
            &x,
            d.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            &mut r,
        )
    };
    report(code, r)
}

/// What [`sealwhy`] names (nqsealwhy(3)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// A symbolic link or reparse point.
    Link,
    /// Not a regular file or folder (a device, a FIFO, a socket).
    Odd,
    /// A name noqtis refuses.
    Name,
    /// A path equal to another but for ASCII case.
    Case,
    /// A file that starts like a noqtis secret key.
    Key,
}

/// Why [`seal`] refused `dir` (an [`Code::Arg`](crate::Code) error): the
/// first thing in it a capsule cannot hold and its path; `None` when
/// nothing in it stops a seal (the keys given were then not one pair).
pub fn sealwhy(dir: impl AsRef<Path>) -> Result<Option<(Why, String)>> {
    let d = cpath(dir.as_ref())?;
    let mut w: c_int = 0;
    let mut p = vec![0 as c_char; 4200];
    // SAFETY: p holds its length
    rc(unsafe { ffi::nqsealwhy(d.as_ptr(), &mut w, p.as_mut_ptr(), p.len()) })?;
    let why = match w {
        0 => return Ok(None),
        1 => Why::Link,
        2 => Why::Odd,
        3 => Why::Name,
        4 => Why::Case,
        _ => Why::Key,
    };
    Ok(Some((why, text(p.as_ptr()))))
}

fn nonce(n: Option<&[u8]>) -> (*const u8, usize) {
    n.map_or((ptr::null(), 0), |n| (n.as_ptr(), n.len()))
}

fn wfail(c: c_int, w: *const c_char) -> Error {
    if w.is_null() {
        Error::new(c)
    } else {
        Error::why(c, text(w))
    }
}

/// The RFC 3161 TimeStampReq for the seal in `dir`: send it to a TSA (the
/// library makes no network request) and give its reply to [`tsput`].
pub fn tsreq(dir: impl AsRef<Path>, nonce_: Option<&[u8]>) -> Result<Vec<u8>> {
    let d = cpath(dir.as_ref())?;
    let (np, nl) = nonce(nonce_);
    let mut q = vec![0u8; 256];
    let mut n = 0usize;
    // SAFETY: q holds its length
    rc(unsafe { ffi::nqtsreq(d.as_ptr(), np, nl, q.as_mut_ptr(), q.len(), &mut n) })?;
    q.truncate(n);
    Ok(q)
}

/// Stores the TSA's reply as the seal's timestamp once it checks (with
/// `anchors`, DER certificates, its TSA must chain to one): the time it
/// gives, in seconds since 1970. [`Code::Verify`](crate::Code), with what
/// failed, when it does not check.
pub fn tsput(
    dir: impl AsRef<Path>,
    reply: &[u8],
    nonce_: Option<&[u8]>,
    anchors: &[&[u8]],
) -> Result<i64> {
    let d = cpath(dir.as_ref())?;
    let (np, nl) = nonce(nonce_);
    let a: Vec<*const u8> = anchors.iter().map(|x| x.as_ptr()).collect();
    let al: Vec<usize> = anchors.iter().map(|x| x.len()).collect();
    let (mut gt, mut w) = (0i64, ptr::null());
    // SAFETY: the arrays hold nanc entries
    let c = unsafe {
        ffi::nqtsput(
            d.as_ptr(),
            reply.as_ptr(),
            reply.len(),
            np,
            nl,
            nul(&a),
            nul(&al),
            a.len(),
            &mut gt,
            &mut w,
        )
    };
    if c != 0 {
        return Err(wfail(c, w));
    }
    Ok(gt)
}

/// The TimeStampReq of the next archive timestamp of the capsule's
/// evidence record (RFC 4998): `hash` "SHA-256", "SHA-384" or "SHA-512"
/// for a hash-tree renewal, `None` to keep the record's.
pub fn ersreq(dir: impl AsRef<Path>, hash: Option<&str>, nonce_: Option<&[u8]>) -> Result<Vec<u8>> {
    let d = cpath(dir.as_ref())?;
    let h = hash.map(crate::hid).transpose()?.unwrap_or(0);
    let (np, nl) = nonce(nonce_);
    let mut q = vec![0u8; 256];
    let (mut n, mut w) = (0usize, ptr::null());
    // SAFETY: q holds its length
    let c = unsafe {
        ffi::nqersreq(
            d.as_ptr(),
            h,
            np,
            nl,
            q.as_mut_ptr(),
            q.len(),
            &mut n,
            &mut w,
        )
    };
    if c != 0 {
        return Err(wfail(c, w));
    }
    q.truncate(n);
    Ok(q)
}

/// How [`ersput`] renewed the evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Renewal {
    /// A new record.
    New,
    /// A timestamp renewal.
    Timestamp,
    /// A hash-tree renewal.
    HashTree,
}

/// Adds the reply to [`ersreq`] to the evidence record (noqtis.ers) once
/// it and the record check: its time and the kind of renewal.
pub fn ersput(
    dir: impl AsRef<Path>,
    reply: &[u8],
    hash: Option<&str>,
    nonce_: Option<&[u8]>,
    anchors: &[&[u8]],
) -> Result<(i64, Renewal)> {
    let d = cpath(dir.as_ref())?;
    let h = hash.map(crate::hid).transpose()?.unwrap_or(0);
    let (np, nl) = nonce(nonce_);
    let a: Vec<*const u8> = anchors.iter().map(|x| x.as_ptr()).collect();
    let al: Vec<usize> = anchors.iter().map(|x| x.len()).collect();
    let (mut gt, mut how, mut w) = (0i64, 0 as c_int, ptr::null());
    // SAFETY: the arrays hold nanc entries
    let c = unsafe {
        ffi::nqersput(
            d.as_ptr(),
            h,
            reply.as_ptr(),
            reply.len(),
            np,
            nl,
            nul(&a),
            nul(&al),
            a.len(),
            &mut gt,
            &mut how,
            &mut w,
        )
    };
    if c != 0 {
        return Err(wfail(c, w));
    }
    let r = match how {
        0 => Renewal::New,
        1 => Renewal::Timestamp,
        _ => Renewal::HashTree,
    };
    Ok((gt, r))
}

/// Calls f with room of cap bytes, then once more with the size it asked
/// for (NQEBUF with *outlen).
pub(crate) fn sized(
    mut f: impl FnMut(*mut u8, usize, &mut usize) -> c_int,
    cap: usize,
) -> Result<Vec<u8>> {
    let mut cap = cap;
    for _ in 0..2 {
        let mut b = vec![0u8; cap];
        let mut n = 0usize;
        let c = f(b.as_mut_ptr(), cap, &mut n);
        if c == -2 && n > cap {
            cap = n + 1;
            continue;
        }
        rc(c)?;
        b.truncate(n);
        return Ok(b);
    }
    Err(Error::new(-2))
}

fn kstmt(
    a: &crate::Alg,
    sk: &[u8],
    pk: &[u8],
    n: Option<(&crate::Alg, &[u8], &[u8])>,
    at: i64,
    reason: Option<&str>,
) -> Result<Vec<u8>> {
    let r = reason.map(|s| cs(s.as_bytes(), "reason")).transpose()?;
    let (na, nsk, npk) = match n {
        Some((x, s, p)) => (x.id, s, p),
        None => (a.id, &[][..], &[][..]),
    };
    let none = n.is_none();
    // SAFETY: the buffers are valid for the lengths passed
    sized(
        |o, c, l| unsafe {
            ffi::nqkstmt(
                a.id,
                sk.as_ptr(),
                sk.len(),
                pk.as_ptr(),
                pk.len(),
                na,
                if none { ptr::null() } else { nsk.as_ptr() },
                nsk.len(),
                if none { ptr::null() } else { npk.as_ptr() },
                npk.len(),
                at,
                r.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                o.cast(),
                c,
                l,
            )
        },
        65536,
    )
}

/// A key statement (noqtis-keys-1, JSON) that the key pair (`sk`, `pk`)
/// of `alg` is replaced by (`nsk`, `npk`) of `nalg` from `at` (seconds
/// since 1970), signed by both keys; `reason` is up to 255 bytes. Both
/// algorithms must be post-quantum. Give it to [`check`] in
/// [`Opts::stmts`].
#[allow(clippy::too_many_arguments)]
pub fn rotate(
    alg: &str,
    sk: &[u8],
    pk: &[u8],
    nalg: &str,
    nsk: &[u8],
    npk: &[u8],
    at: i64,
    reason: Option<&str>,
) -> Result<Vec<u8>> {
    let a = crate::find(alg, crate::Kind::Sign)?;
    let n = crate::find(nalg, crate::Kind::Sign)?;
    kstmt(a, sk, pk, Some((n, nsk, npk)), at, reason)
}

/// A key statement that the key pair (`sk`, `pk`) is revoked from `at`,
/// signed by it; as [`rotate`].
pub fn revoke(alg: &str, sk: &[u8], pk: &[u8], at: i64, reason: Option<&str>) -> Result<Vec<u8>> {
    let a = crate::find(alg, crate::Kind::Sign)?;
    kstmt(a, sk, pk, None, at, reason)
}

/// A key statement that the key pair (`sk`, `pk`) seals until `at` and
/// not after, signed by it; as [`rotate`]. [`check`] accepts its seals as
/// before until that time has come, and from then on only with a verified
/// timestamp from before it.
pub fn expire(alg: &str, sk: &[u8], pk: &[u8], at: i64, reason: Option<&str>) -> Result<Vec<u8>> {
    let a = crate::find(alg, crate::Kind::Sign)?;
    let r = reason.map(|s| cs(s.as_bytes(), "reason")).transpose()?;
    // SAFETY: the buffers are valid for the lengths passed
    sized(
        |o, c, l| unsafe {
            ffi::nqkexp(
                a.id,
                sk.as_ptr(),
                sk.len(),
                pk.as_ptr(),
                pk.len(),
                at,
                r.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                o.cast(),
                c,
                l,
            )
        },
        65536,
    )
}
