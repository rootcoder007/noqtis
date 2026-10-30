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
    /// `true` only when the library passed the capsule as a whole.
    pub fn ok(&self) -> bool {
        self.code == 0 && self.rows.iter().all(|r| r.ok)
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
fn cpath(p: &Path) -> Result<CString> {
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
