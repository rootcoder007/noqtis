// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//! The data record of a capsule (`noqtis.data.json`, noqtis-data-1):
//! where each data file came from, the schema of its CSV files,
//! summaries that show drift later, and the steps and checks made with
//! it. It is a file of the capsule like any other: seal the folder after
//! changing it, and the seal covers it. Elements go in and come out as
//! JSON text, and the library writes the record in canonical form, the
//! same bytes the `noqtis` command and every other binding write.
//!
//! ```no_run
//! use noqtis::data;
//!
//! let s = data::Src { url: Some("https://example.org/a.csv".into()), ..Default::default() };
//! data::add("results", &["data/a.csv"], &s)?;
//! data::pin("results", &["data/a.csv"], &data::Csv::default())?;
//! assert!(data::check("results")?.ok());
//! # Ok::<(), noqtis::Error>(())
//! ```

use crate::cap::cpath;
use crate::{ffi, Error, Result};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};
use std::ptr;

/// One row of a data check: its name ("record", "source", "schema",
/// "rule", "drift", "drift.warn", "file", ...), whether it passed, why,
/// and for a drift row its numbers as JSON text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// What was checked.
    pub check: String,
    /// Whether it passed.
    pub ok: bool,
    /// What was found.
    pub detail: String,
    /// The row's numbers (canonical JSON), when it has some.
    pub stats: Option<String>,
}

/// What a data check found: every row, and the library's return code (0,
/// or -3 when a row failed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The library's return code.
    pub code: i32,
    /// Every row, in order.
    pub rows: Vec<Row>,
}

impl Report {
    /// `true` only when the library passed it as a whole (and there was
    /// a row). A diff with no difference has no row and is [`same`](Self::same).
    pub fn ok(&self) -> bool {
        self.code == 0 && !self.rows.is_empty() && self.rows.iter().all(|r| r.ok)
    }

    /// For [`diff`]: nothing differs.
    pub fn same(&self) -> bool {
        self.code == 0
    }

    /// "ok", "warn" (a "drift.warn" row and none failed) or "fail".
    pub fn level(&self) -> &'static str {
        if !self.ok() {
            "fail"
        } else if self.rows.iter().any(|r| r.check == "drift.warn") {
            "warn"
        } else {
            "ok"
        }
    }
}

/// Where a source file came from, for [`add`]; every member may be
/// empty. `retrieved` is "now" (SOURCE_DATE_EPOCH when set, else the
/// clock) or a UTC time YYYY-MM-DDTHH:MM:SSZ.
#[derive(Debug, Clone, Default)]
pub struct Src {
    /// Where it was fetched from.
    pub url: Option<String>,
    /// Its title.
    pub title: Option<String>,
    /// Who published it.
    pub publisher: Option<String>,
    /// Its licence (an SPDX identifier, say).
    pub licence: Option<String>,
    /// When it was fetched.
    pub retrieved: Option<String>,
    /// It is a synthetic stand-in, not the real data.
    pub synthetic: bool,
}

/// How a CSV file is read.
#[derive(Debug, Clone)]
pub struct Csv {
    /// The delimiter, one ASCII byte (not a quote or a line break).
    pub delim: u8,
    /// The first line names the columns.
    pub header: bool,
    /// [`schema`] pins each number and date column's range too.
    pub ranges: bool,
}

impl Default for Csv {
    fn default() -> Csv {
        Csv {
            delim: b',',
            header: true,
            ranges: false,
        }
    }
}

/// When [`drift`] calls a column drifted (noqtis-drift(1)).
#[derive(Debug, Clone)]
pub struct Drift {
    /// A PSI at or over this warns.
    pub psiwarn: f64,
    /// A PSI at or over this fails, when both samples have `minn` values.
    pub psifail: f64,
    /// A KS or chi-square p-value below this warns.
    pub alpha: f64,
    /// See `psifail`.
    pub minn: f64,
    /// Test first digits against Benford's law too.
    pub benford: bool,
}

impl Default for Drift {
    fn default() -> Drift {
        Drift {
            psiwarn: 0.1,
            psifail: 0.25,
            alpha: 0.001,
            minn: 1000.0,
            benford: false,
        }
    }
}

const WHY: usize = 600;

fn cs(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::why(-1, format!("a NUL byte in {s:?}")))
}

fn fail(code: c_int, why: &[c_char]) -> Error {
    // SAFETY: the library NUL-terminates why (it was zeroed before)
    let w = unsafe { CStr::from_ptr(why.as_ptr()) }.to_string_lossy();
    if w.is_empty() {
        Error::new(code)
    } else {
        Error::why(code, w.into_owned())
    }
}

/// Text from a call that writes to (out, cap) and its length to *len,
/// NQEBUF with the length when cap is short: tried with 64 KiB, then once
/// more with room for all of it.
fn grow(
    mut f: impl FnMut(*mut c_char, usize, &mut usize) -> c_int,
) -> std::result::Result<String, c_int> {
    let mut cap = 1 << 16;
    loop {
        let mut b = vec![0u8; cap];
        let mut n = 0usize;
        let c = f(b.as_mut_ptr().cast(), cap, &mut n);
        if c == -2 && n + 1 > cap {
            cap = n + 1;
            continue;
        }
        if c != 0 {
            return Err(c);
        }
        b.truncate(n);
        return Ok(String::from_utf8_lossy(&b).into_owned());
    }
}

/// A record, freed when dropped.
struct Rec(*mut ffi::Drec);

impl Drop for Rec {
    fn drop(&mut self) {
        // SAFETY: a record from nqdnew, nqdparse or nqdload, freed once
        unsafe { ffi::nqdrfree(self.0) }
    }
}

impl Rec {
    /// The record of dir; with mk, a new one when there is none.
    fn load(d: &CString, mk: bool) -> Result<Rec> {
        let mut r = ptr::null_mut();
        let mut why = [0 as c_char; WHY];
        // SAFETY: valid strings and buffers
        let mut c = unsafe { ffi::nqdload(d.as_ptr(), &mut r, why.as_mut_ptr(), WHY) };
        if c == -7 && mk {
            // SAFETY: r receives a new record
            c = unsafe { ffi::nqdnew(&mut r) };
        }
        if c != 0 {
            return Err(fail(c, &why));
        }
        Ok(Rec(r))
    }

    fn save(&self, d: &CString) -> Result<()> {
        // SAFETY: a valid record and folder
        crate::rc(unsafe { ffi::nqdsave(self.0, d.as_ptr()) })
    }

    fn json(&self) -> Result<String> {
        // SAFETY: out has cap bytes
        grow(|o, c, n| unsafe { ffi::nqdjson(self.0, o, c, n) }).map_err(Error::new)
    }

    /// The element of member with key, or None.
    fn key(&self, m: &str, k: &str) -> Result<Option<String>> {
        let (m, k) = (cs(m)?, cs(k)?);
        // SAFETY: out has cap bytes
        match grow(|o, c, n| unsafe { ffi::nqdkey(self.0, m.as_ptr(), k.as_ptr(), o, c, n) }) {
            Ok(s) => Ok(Some(s)),
            Err(-7) => Ok(None),
            Err(c) => Err(Error::new(c)),
        }
    }

    fn put(&mut self, m: &str, json: &str) -> Result<()> {
        let (m, j) = (cs(m)?, cs(json)?);
        let mut why = [0 as c_char; WHY];
        // SAFETY: valid strings; json is n bytes
        let c = unsafe {
            ffi::nqdput(
                self.0,
                m.as_ptr(),
                j.as_ptr(),
                json.len(),
                why.as_mut_ptr(),
                WHY,
            )
        };
        if c != 0 {
            return Err(fail(c, &why));
        }
        Ok(())
    }
}

/// The report the library made (freed here), or the error when it made
/// none.
fn drep(code: c_int, r: *mut ffi::Drep) -> Result<Report> {
    if r.is_null() {
        return Err(Error::new(if code == 0 { -10 } else { code }));
    }
    let s = |p: *const c_char| {
        if p.is_null() {
            String::new()
        } else {
            // SAFETY: a NUL-terminated string of the report
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        }
    };
    let mut rows = Vec::new();
    // SAFETY: r is a report from the library, freed once below
    unsafe {
        for i in 0..ffi::nqdrepn(r) {
            let (mut c, mut d) = (ptr::null(), ptr::null());
            let mut ok: c_int = 0;
            if ffi::nqdrepi(r, i, &mut c, &mut ok, &mut d) != 0 {
                break;
            }
            let j = ffi::nqdrepj(r, i);
            rows.push(Row {
                check: s(c),
                ok: ok != 0,
                detail: s(d),
                stats: if j.is_null() { None } else { Some(s(j)) },
            });
        }
        ffi::nqdrepfree(r);
    }
    Ok(Report { code, rows })
}

fn csvopt(o: &Csv) -> Result<ffi::Csvopt> {
    if o.delim == 0 || o.delim > 127 {
        return Err(Error::why(-1, "delim must be one ASCII character"));
    }
    Ok(ffi::Csvopt {
        delim: o.delim as c_char,
        noheader: !o.header as c_int,
        ranges: o.ranges as c_int,
    })
}

/// The record in `dir` as its canonical JSON text.
pub fn text(dir: impl AsRef<Path>) -> Result<String> {
    Rec::load(&cpath(dir.as_ref())?, false)?.json()
}

/// The JSON text of a record in canonical form, after checking it as
/// the library checks a record it reads (the bytes [`text`] gives for
/// it).
pub fn canon(json: &str) -> Result<String> {
    let mut r = ptr::null_mut();
    let mut why = [0 as c_char; WHY];
    // SAFETY: json is json.len() bytes; why has WHY bytes
    let c = unsafe {
        ffi::nqdparse(
            json.as_ptr().cast(),
            json.len(),
            &mut r,
            why.as_mut_ptr(),
            WHY,
        )
    };
    if c != 0 {
        return Err(fail(c, &why));
    }
    Rec(r).json()
}

/// One string as JSON text.
fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for ch in s.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Seconds since 1970 as YYYY-MM-DDTHH:MM:SSZ (the proleptic Gregorian
/// calendar, days from H. Hinnant's civil_from_days).
fn utc(t: i64) -> String {
    let (z, s) = (t.div_euclid(86400) + 719468, t.rem_euclid(86400));
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        s / 3600,
        s % 3600 / 60,
        s % 60
    )
}

fn now() -> String {
    let t = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|e| e.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64)
        });
    utc(t)
}

/// Records each file's SHA-256 and size (paths relative to `dir`, '/'
/// between folders) as a source, keeping what the record already says of
/// it, with where it came from (`s`). Makes the record when there is
/// none.
pub fn add(dir: impl AsRef<Path>, files: &[&str], s: &Src) -> Result<()> {
    if s.url.is_some() && files.len() > 1 {
        return Err(Error::why(
            -1,
            "url describes one file: add the files one at a time",
        ));
    }
    let mut f: Vec<(&str, String)> = Vec::new();
    let r = if s.retrieved.as_deref() == Some("now") {
        Some(now())
    } else {
        s.retrieved.clone()
    };
    for (k, v) in [
        ("url", &s.url),
        ("title", &s.title),
        ("publisher", &s.publisher),
        ("licence", &s.licence),
        ("retrieved", &r),
    ] {
        if let Some(v) = v {
            f.push((k, jstr(v)));
        }
    }
    if s.synthetic {
        f.push(("synthetic", "true".into()));
    }
    let d = cpath(dir.as_ref())?;
    let rec = Rec::load(&d, true)?;
    let mut why = [0 as c_char; WHY];
    for p in files {
        let pc = cs(p)?;
        // SAFETY: valid record, strings and buffer
        let c = unsafe { ffi::nqdsrc(rec.0, d.as_ptr(), pc.as_ptr(), why.as_mut_ptr(), WHY) };
        if c != 0 {
            return Err(fail(c, &why));
        }
        for (k, v) in &f {
            let (m, kc, vc) = (cs("sources")?, cs(k)?, cs(v)?);
            // SAFETY: as above; v is v.len() bytes
            let c = unsafe {
                ffi::nqdset(
                    rec.0,
                    m.as_ptr(),
                    pc.as_ptr(),
                    kc.as_ptr(),
                    vc.as_ptr(),
                    v.len(),
                    why.as_mut_ptr(),
                    WHY,
                )
            };
            if c != 0 {
                return Err(fail(c, &why));
            }
        }
    }
    rec.save(&d)
}

/// Adds an element (JSON text) to a member: "sources", "schemas",
/// "stats", "chunks" (the one with the same path is replaced), "checks"
/// (the same name), "steps", "commits" (appended), or sets "env" or
/// "cite". Makes the record when there is none.
pub fn put(dir: impl AsRef<Path>, member: &str, json: &str) -> Result<()> {
    let d = cpath(dir.as_ref())?;
    let mut r = Rec::load(&d, true)?;
    r.put(member, json)?;
    r.save(&d)
}

/// Removes the element of `member` with path or name `key`, or the
/// whole member when `key` is None.
pub fn del(dir: impl AsRef<Path>, member: &str, key: Option<&str>) -> Result<()> {
    let d = cpath(dir.as_ref())?;
    let r = Rec::load(&d, false)?;
    let m = cs(member)?;
    let k = key.map(cs).transpose()?;
    // SAFETY: valid record and strings
    crate::rc(unsafe {
        ffi::nqddel(
            r.0,
            m.as_ptr(),
            k.as_ref().map_or(ptr::null(), |k| k.as_ptr()),
        )
    })?;
    r.save(&d)
}

/// The element of a keyed member ("sources", "schemas", "stats",
/// "chunks" by path, "checks" by name) with `key`, or None.
pub fn key(dir: impl AsRef<Path>, member: &str, key: &str) -> Result<Option<String>> {
    Rec::load(&cpath(dir.as_ref())?, false)?.key(member, key)
}

/// Checks the record and every file it lists: each source's SHA-256 and
/// size, each schema and its rules, and the checks recorded as failed.
pub fn check(dir: impl AsRef<Path>) -> Result<Report> {
    let d = cpath(dir.as_ref())?;
    let mut r = ptr::null_mut();
    // SAFETY: valid string; r receives the report
    let c = unsafe { ffi::nqdchk(d.as_ptr(), &mut r) };
    drep(c, r)
}

/// The schema of the CSV file `file` in `dir` as a "schemas" element:
/// its columns with the narrowest type of each, missing values, rows
/// (and with `o.ranges`, number and date ranges). [`put`] records it.
pub fn schema(dir: impl AsRef<Path>, file: &str, o: &Csv) -> Result<String> {
    let (d, f, co) = (cpath(dir.as_ref())?, cs(file)?, csvopt(o)?);
    let mut why = [0 as c_char; WHY];
    let w = why.as_mut_ptr();
    // SAFETY: out has cap bytes, why WHY
    grow(|o, c, n| unsafe { ffi::nqdinfer(d.as_ptr(), f.as_ptr(), &co, o, c, n, w, WHY) })
        .map_err(|c| fail(c, &why))
}

/// The "schema" and "rule" rows of [`check`], of the files named only
/// when `files` is not empty.
pub fn schemacheck(dir: impl AsRef<Path>, files: &[&str]) -> Result<Report> {
    let r = check(dir)?;
    let rows: Vec<Row> = r
        .rows
        .into_iter()
        .filter(|x| {
            (x.check == "schema" || x.check == "rule")
                && (files.is_empty() || {
                    let p = x.detail.split(':').next().unwrap_or("");
                    files.contains(&p.trim_end_matches(" [synthetic]"))
                })
        })
        .collect();
    let code = if !rows.is_empty() && rows.iter().all(|x| x.ok) {
        0
    } else {
        -3
    };
    Ok(Report { code, rows })
}

/// Records each CSV file's summaries (a "stats" element, noqtis-drift(1))
/// in the record, which [`drift`] later compares a file with.
pub fn pin(dir: impl AsRef<Path>, files: &[&str], o: &Csv) -> Result<()> {
    let d = cpath(dir.as_ref())?;
    let co = csvopt(o)?;
    let mut r = Rec::load(&d, true)?;
    for p in files {
        let f = cs(p)?;
        let mut why = [0 as c_char; WHY];
        let w = why.as_mut_ptr();
        // SAFETY: out has cap bytes, why WHY
        let s =
            grow(|o, c, n| unsafe { ffi::nqdstats(d.as_ptr(), f.as_ptr(), &co, o, c, n, w, WHY) })
                .map_err(|c| fail(c, &why))?;
        r.put("stats", &s)?;
    }
    r.save(&d)
}

/// The value of the top-level member "path" of a canonical JSON object.
// note: only the escapes a capsule path can need (\" and \\)
fn pathof(j: &str) -> Option<String> {
    let b = j.as_bytes();
    let (mut depth, mut i) = (0, 0);
    while i < b.len() {
        match b[i] {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth -= 1,
            b'"' => {
                let s = i + 1;
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                if depth == 1 && i < b.len() && &b[s..i] == b"path" && j[i + 1..].starts_with(":\"")
                {
                    let mut out = String::new();
                    let mut esc = false;
                    for ch in j[i + 3..].chars() {
                        match (esc, ch) {
                            (false, '\\') => esc = true,
                            (false, '"') => return Some(out),
                            (_, c) => {
                                out.push(c);
                                esc = false;
                            }
                        }
                    }
                    return None;
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Compares each summarised file (or the file of `current` in its place)
/// with its summary: Kolmogorov-Smirnov, PSI and Jensen-Shannon,
/// chi-square of homogeneity, Benford (noqtis-drift(1)). `files` empty:
/// every file the record summarises; `current` empty: the files
/// themselves, else one path per file.
pub fn drift(
    dir: impl AsRef<Path>,
    files: &[&str],
    current: &[PathBuf],
    o: &Csv,
    d: &Drift,
) -> Result<Report> {
    let dir = dir.as_ref();
    let r = Rec::load(&cpath(dir)?, false)?;
    let mut fs: Vec<String> = files.iter().map(|s| s.to_string()).collect();
    if fs.is_empty() {
        let m = cs("stats")?;
        // SAFETY: a valid record and string
        let n = unsafe { ffi::nqdlen(r.0, m.as_ptr()) };
        for i in 0..n {
            // SAFETY: out has cap bytes
            let e = grow(|o, c, l| unsafe { ffi::nqdat(r.0, m.as_ptr(), i, o, c, l) })
                .map_err(Error::new)?;
            fs.extend(pathof(&e));
        }
    }
    if fs.is_empty() {
        return Err(Error::why(
            -1,
            "the record has no summaries: pin some first",
        ));
    }
    if !current.is_empty() && current.len() != fs.len() {
        return Err(Error::why(-1, "current needs one path per file"));
    }
    let co = csvopt(o)?;
    let dop = ffi::Dopt {
        psiwarn: d.psiwarn,
        psifail: d.psifail,
        alpha: d.alpha,
        minn: d.minn,
        benford: d.benford as c_int,
    };
    let mut out = Report {
        code: 0,
        rows: Vec::new(),
    };
    for (i, f) in fs.iter().enumerate() {
        let s = r
            .key("stats", f)?
            .ok_or_else(|| Error::why(-1, format!("no summary of {f}: pin one first")))?;
        // a file of the capsule is opened inside dir, never through a
        // link; a file of current is the caller's, opened by its path
        let (d, p) = if current.is_empty() {
            (Some(cpath(dir)?), cs(f)?)
        } else {
            (None, cpath(&current[i])?)
        };
        let dp = d.as_ref().map_or(ptr::null(), |d| d.as_ptr());
        let mut rp = ptr::null_mut();
        // SAFETY: s is s.len() bytes; dp NULL or a valid string; valid
        // options; rp receives the report
        let c = unsafe {
            ffi::nqddriftat(
                s.as_ptr().cast(),
                s.len(),
                dp,
                p.as_ptr(),
                &co,
                &dop,
                &mut rp,
            )
        };
        let x = drep(c, rp)?;
        if out.code == 0 {
            out.code = x.code;
        }
        out.rows.extend(x.rows);
    }
    Ok(out)
}

/// What changed from capsule `a` to capsule `b`: one failed row per
/// difference (files, sources, schemas, summaries, env, ...); the report
/// is [`same`](Report::same) when nothing differs.
pub fn diff(a: impl AsRef<Path>, b: impl AsRef<Path>) -> Result<Report> {
    let (a, b) = (cpath(a.as_ref())?, cpath(b.as_ref())?);
    let mut r = ptr::null_mut();
    // SAFETY: valid strings; r receives the report
    let c = unsafe { ffi::nqddiff(a.as_ptr(), b.as_ptr(), &mut r) };
    drep(c, r)
}

#[cfg(test)]
mod t {
    #[test]
    fn utc() {
        assert_eq!(super::utc(1767225600), "2026-01-01T00:00:00Z");
        assert_eq!(super::utc(951782400 + 86399), "2000-02-29T23:59:59Z");
        assert_eq!(super::utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn pathof() {
        let j = r#"{"columns":[{"name":"path","n":1}],"path":"a \"b\".csv","rows":3}"#;
        assert_eq!(super::pathof(j).as_deref(), Some("a \"b\".csv"));
        assert_eq!(super::pathof(r#"{"x":{"path":"no"}}"#), None);
    }
}

// ---- sources (nqdaddr(3)) ----

/// Where an address of [`addrs`] comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The source's url.
    Url,
    /// The portal: the request to send, whose reply [`reply`] reads.
    Portal,
    /// A mirror.
    Mirror,
    /// The archived copy (a Wayback Machine copy's raw bytes).
    Archived,
}

/// The addresses the source `file` can be fetched from, in the order to
/// try them; none for a synthetic source.
pub fn addrs(dir: impl AsRef<Path>, file: &str) -> Result<Vec<(Kind, String)>> {
    let r = Rec::load(&cpath(dir.as_ref())?, false)?;
    let f = cs(file)?;
    let mut out = Vec::new();
    for i in 0.. {
        let mut k: c_int = 0;
        // SAFETY: valid record and string; out has cap bytes
        match grow(|o, c, n| unsafe { ffi::nqdaddr(r.0, f.as_ptr(), i, &mut k, o, c, n) }) {
            Ok(u) => out.push((
                match k {
                    1 => Kind::Url,
                    2 => Kind::Portal,
                    3 => Kind::Mirror,
                    _ => Kind::Archived,
                },
                u,
            )),
            Err(-1) => break,
            Err(-7) if i > 0 => break,
            Err(c) => return Err(Error::new(c)),
        }
    }
    Ok(out)
}

/// Whether `bytes` are the source file's recorded bytes (its size and
/// SHA-256): only such bytes may be taken for it.
pub fn verify(dir: impl AsRef<Path>, file: &str, bytes: &[u8]) -> Result<bool> {
    let r = Rec::load(&cpath(dir.as_ref())?, false)?;
    let f = cs(file)?;
    // SAFETY: valid record and string; bytes is len bytes
    match unsafe { ffi::nqdvrfy(r.0, f.as_ptr(), bytes.as_ptr(), bytes.len()) } {
        0 => Ok(true),
        -3 => Ok(false),
        c => Err(Error::new(c)),
    }
}

/// The field `name` of element `i` of `member` (0 for "env" and "cite"):
/// a string as its text, anything else as canonical JSON; None when there
/// is none.
pub fn field(dir: impl AsRef<Path>, member: &str, i: usize, name: &str) -> Result<Option<String>> {
    let r = Rec::load(&cpath(dir.as_ref())?, false)?;
    let (m, f) = (cs(member)?, cs(name)?);
    // SAFETY: valid record and strings; out has cap bytes
    match grow(|o, c, n| unsafe { ffi::nqdfld(r.0, m.as_ptr(), i, f.as_ptr(), o, c, n) }) {
        Ok(s) => Ok(Some(s)),
        Err(-7) => Ok(None),
        Err(c) => Err(Error::new(c)),
    }
}

/// The address to ask (a GET) for the file of a source's resolver (JSON:
/// CKAN, Socrata, ArcGIS or the Wayback Machine).
pub fn request(resolver: &str) -> Result<String> {
    let j = cs(resolver)?;
    let mut why = [0 as c_char; WHY];
    let mut b = vec![0u8; 4400];
    let mut n = 0usize;
    // SAFETY: valid string of len bytes; b and why have their sizes
    let c = unsafe {
        ffi::nqdrslv(
            j.as_ptr(),
            resolver.len(),
            b.as_mut_ptr().cast(),
            b.len(),
            &mut n,
            why.as_mut_ptr(),
            WHY,
        )
    };
    if c != 0 {
        return Err(fail(c, &why));
    }
    b.truncate(n);
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// The file's address read from the portal's reply to [`request`], and
/// for the Wayback Machine the copy's time ("" otherwise).
pub fn reply(resolver: &str, body: &[u8]) -> Result<(String, String)> {
    let j = cs(resolver)?;
    let mut why = [0 as c_char; WHY];
    let mut b = vec![0u8; 4400];
    let mut tm = [0 as c_char; 21];
    let mut n = 0usize;
    // SAFETY: valid string; body is len bytes; buffers have their sizes
    let c = unsafe {
        ffi::nqdrsp(
            j.as_ptr(),
            resolver.len(),
            body.as_ptr().cast(),
            body.len(),
            b.as_mut_ptr().cast(),
            b.len(),
            &mut n,
            tm.as_mut_ptr(),
            why.as_mut_ptr(),
            WHY,
        )
    };
    if c != 0 {
        return Err(fail(c, &why));
    }
    b.truncate(n);
    // SAFETY: the library NUL-terminates tm
    let t = unsafe { CStr::from_ptr(tm.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    Ok((String::from_utf8_lossy(&b).into_owned(), t))
}

/// The raw-bytes address of a Wayback Machine copy (any other http:// or
/// https:// address as it is).
pub fn wayback(url: &str) -> Result<String> {
    let u = cs(url)?;
    // SAFETY: valid string; out has cap bytes
    grow(|o, c, n| unsafe { ffi::nqdwb(u.as_ptr(), o, c, n) }).map_err(Error::new)
}

/// Checks the CSV file of the "schemas" element `schema` (JSON text) in
/// `dir` against it: header, types, missing values, ranges, sets, rows
/// and rules.
pub fn checkschema(dir: impl AsRef<Path>, schema: &str) -> Result<Report> {
    let d = cpath(dir.as_ref())?;
    let s = cs(schema)?;
    let mut r = ptr::null_mut();
    // SAFETY: valid strings; schema is its length
    let c = unsafe { ffi::nqdschk(d.as_ptr(), s.as_ptr(), schema.len(), &mut r) };
    drep(c, r)
}

/// Writes a synthetic stand-in for the CSV file from its recorded schema
/// (`rows` rows, 0: the schema's minimum, else 100; the same bytes for
/// the same `seed`) and records it as a synthetic source. Real data is
/// never replaced ([`Code::Arg`](crate::Code)).
pub fn synth(dir: impl AsRef<Path>, file: &str, seed: u64, rows: u64) -> Result<()> {
    let d = cpath(dir.as_ref())?;
    let rec = Rec::load(&d, false)?;
    let f = cs(file)?;
    let mut why = [0 as c_char; WHY];
    // SAFETY: valid record, strings and buffer
    let c = unsafe {
        ffi::nqdsyn(
            rec.0,
            d.as_ptr(),
            f.as_ptr(),
            seed,
            rows,
            why.as_mut_ptr(),
            WHY,
        )
    };
    if c != 0 {
        return Err(fail(c, &why));
    }
    rec.save(&d)
}

/// Text from a call that also writes a sentence to why.
fn wgrow(
    mut f: impl FnMut(*mut c_char, usize, &mut usize, *mut c_char) -> c_int,
) -> Result<String> {
    let mut why = [0 as c_char; WHY];
    let w = why.as_mut_ptr();
    grow(|o, c, n| f(o, c, n, w)).map_err(|c| fail(c, &why))
}

/// Calibrates the drift warnings of `file`'s summary on `files`, CSV
/// files known not to have drifted from it, and records the result:
/// [`drift`] then warns only beyond what they showed. The element.
pub fn calibrate(dir: impl AsRef<Path>, file: &str, files: &[&Path], o: &Csv) -> Result<String> {
    let d = cpath(dir.as_ref())?;
    let mut rec = Rec::load(&d, false)?;
    let s = rec
        .key("stats", file)?
        .ok_or_else(|| Error::why(-7, format!("no summary of {file}: pin one first")))?;
    let fc = files.iter().map(|p| cpath(p)).collect::<Result<Vec<_>>>()?;
    let fp: Vec<*const c_char> = fc.iter().map(|c| c.as_ptr()).collect();
    let co = csvopt(o)?;
    let sc = cs(&s)?;
    // SAFETY: valid strings, arrays and buffers
    let e = wgrow(|out, c, n, w| unsafe {
        ffi::nqddcal(
            sc.as_ptr(),
            s.len(),
            fp.as_ptr(),
            fp.len(),
            &co,
            out,
            c,
            n,
            w,
            WHY,
        )
    })?;
    rec.put("stats", &e)?;
    rec.save(&d)?;
    Ok(e)
}

/// Records the SHA-256 of each `chunk` bytes (1,024 to 2^30) of the large
/// `file`, so that a piece of it can be checked alone ([`piece`]). The
/// element.
pub fn chunks(dir: impl AsRef<Path>, file: &str, chunk: u64) -> Result<String> {
    let d = cpath(dir.as_ref())?;
    let f = cs(file)?;
    // SAFETY: valid strings and buffers
    let e = wgrow(|o, c, n, w| unsafe {
        ffi::nqdchunk(d.as_ptr(), f.as_ptr(), chunk, o, c, n, w, WHY)
    })?;
    let mut rec = Rec::load(&d, true)?;
    rec.put("chunks", &e)?;
    rec.save(&d)?;
    Ok(e)
}

/// Checks the file `piece`, the bytes of `file` from byte `off` on (a
/// multiple of its chunk), against its recorded chunk digests.
pub fn piece(
    dir: impl AsRef<Path>,
    file: &str,
    piece: impl AsRef<Path>,
    off: u64,
) -> Result<Report> {
    let e = key(dir, "chunks", file)?
        .ok_or_else(|| Error::why(-7, format!("no chunk digests of {file}: record them first")))?;
    let (ec, p) = (cs(&e)?, cpath(piece.as_ref())?);
    let mut r = ptr::null_mut();
    // SAFETY: valid strings
    let c = unsafe { ffi::nqdpiece(ec.as_ptr(), e.len(), p.as_ptr(), off, &mut r) };
    drep(c, r)
}

/// The commitment to `m` under `salt` (16 to 1,024 bytes): 64 hex digits
/// of SHA3-256 (nqdcommit(3)).
pub fn commitment(salt: &[u8], m: &[u8]) -> Result<String> {
    let mut hx = [0 as c_char; 65];
    // SAFETY: hx holds 65 bytes
    crate::rc(unsafe {
        ffi::nqdcommit(
            salt.as_ptr(),
            salt.len(),
            m.as_ptr(),
            m.len(),
            hx.as_mut_ptr(),
        )
    })?;
    // SAFETY: NUL-terminated by the library
    Ok(unsafe { CStr::from_ptr(hx.as_ptr()) }
        .to_string_lossy()
        .into_owned())
}

/// What [`commit`] records besides the digest.
#[derive(Debug, Clone, Default)]
pub struct Commit {
    /// "randomisation", "preregistration" or "other" (None: "other").
    pub kind: Option<String>,
    /// A label.
    pub label: Option<String>,
    /// A UTC time YYYY-MM-DDTHH:MM:SSZ before which not to reveal it.
    pub after: Option<String>,
}

/// Commits to `m` (a randomisation list, an analysis plan) in the record
/// as `noqtis commit` does, and returns the 32-byte secret salt: keep it
/// outside the capsule until the reveal, and [`wipe`](crate::wipe) it.
pub fn commit(dir: impl AsRef<Path>, m: &[u8], o: &Commit) -> Result<Vec<u8>> {
    let salt = crate::random(32)?;
    let mut e = format!(
        "{{\"kind\":{},\"created\":\"{}\",\"alg\":\"sha3-256\",\"digest\":\"{}\"",
        jstr(o.kind.as_deref().unwrap_or("other")),
        now(),
        commitment(&salt, m)?
    );
    if let Some(l) = &o.label {
        e += &format!(",\"label\":{}", jstr(l));
    }
    if let Some(a) = &o.after {
        e += &format!(",\"after\":{}", jstr(a));
    }
    e.push('}');
    put(dir, "commits", &e)?;
    Ok(salt)
}

/// The index in "commits" of the commitment to `m` under `salt`, or None
/// (every digest compared in constant time).
pub fn reveal(dir: impl AsRef<Path>, m: &[u8], salt: &[u8]) -> Result<Option<usize>> {
    let rec = Rec::load(&cpath(dir.as_ref())?, false)?;
    let mut i = 0usize;
    // SAFETY: valid record and buffers
    match unsafe {
        ffi::nqdreveal(
            rec.0,
            salt.as_ptr(),
            salt.len(),
            m.as_ptr(),
            m.len(),
            &mut i,
        )
    } {
        0 => Ok(Some(i)),
        -3 => Ok(None),
        c => Err(Error::new(c)),
    }
}

/// How to cite the data, from the record's "cite": a CITATION.cff
/// (`bib` false) or a BibTeX entry.
pub fn cite(dir: impl AsRef<Path>, bib: bool) -> Result<String> {
    let rec = Rec::load(&cpath(dir.as_ref())?, false)?;
    let f = if bib { 2 } else { 1 };
    // SAFETY: out has cap bytes
    grow(|o, c, n| unsafe { ffi::nqdcite(rec.0, f, o, c, n) }).map_err(Error::new)
}

/// A report of the capsule, as `noqtis report` writes it: whether every
/// check passed, the capsule's check (with `pk` the seal must be by that
/// key), what the data record says and its check; Markdown, or plain
/// text with `txt`.
pub fn report(dir: impl AsRef<Path>, pk: Option<&[u8]>, txt: bool) -> Result<String> {
    let dp = dir.as_ref();
    let sealed = dp.join("noqtis.sig").exists();
    let hasrec = dp.join("noqtis.data.json").exists();
    if !sealed && !hasrec {
        return Err(Error::why(
            -7,
            format!("{} holds neither a seal nor a data record", dp.display()),
        ));
    }
    let d = cpath(dp)?;
    let o = ffi::Copt {
        trust: pk.map_or(ptr::null(), |k| k.as_ptr()),
        trustlen: pk.map_or(0, |k| k.len()),
        anc: ptr::null(),
        anclen: ptr::null(),
        nanc: 0,
        only: ptr::null(),
        nonly: 0,
        lin: ptr::null(),
        nlin: 0,
        stmt: ptr::null(),
        stmtlen: ptr::null(),
        nstmt: 0,
    };
    let (mut cr, mut dr) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: valid folder and options; the reports are freed below
    unsafe {
        if sealed {
            let c = ffi::nqchkx(d.as_ptr(), &o, &mut cr);
            if cr.is_null() {
                return Err(Error::new(c));
            }
        }
        if hasrec {
            let c = ffi::nqdchk(d.as_ptr(), &mut dr);
            if dr.is_null() {
                ffi::nqrepfree(cr);
                return Err(Error::new(c));
            }
        }
    }
    let f = if txt { 2 } else { 1 };
    // SAFETY: out has cap bytes
    let r = grow(|out, c, n| unsafe { ffi::nqdrpt(d.as_ptr(), cr, dr, f, out, c, n) })
        .map_err(Error::new);
    // SAFETY: freed once
    unsafe {
        ffi::nqrepfree(cr);
        ffi::nqdrepfree(dr);
    }
    r
}

// ---- bundles and chains ----

/// The capsule in `dir` as one file (noqtis-bundle-1), as `noqtis pack`
/// writes it: its seal, manifest, evidence record and every listed file
/// (`files` false: only its data record). `file` must not exist. Check
/// the capsule first.
pub fn pack(dir: impl AsRef<Path>, file: impl AsRef<Path>, files: bool) -> Result<()> {
    let (d, f) = (cpath(dir.as_ref())?, cpath(file.as_ref())?);
    // SAFETY: valid strings
    crate::rc(unsafe { ffi::nqdpack(d.as_ptr(), files as c_int, f.as_ptr()) })
}

fn unpk(f: &CString, d: &CString, rm: bool) -> Result<()> {
    let mut why = [0 as c_char; WHY];
    // SAFETY: valid strings and buffer
    let c = unsafe { ffi::nqdunpack(f.as_ptr(), d.as_ptr(), rm as c_int, why.as_mut_ptr(), WHY) };
    if c != 0 {
        return Err(fail(c, &why));
    }
    Ok(())
}

/// Reads a bundle into the new folder `dir`, refusing it whole
/// ([`Code::Decode`](crate::Code) with what is wrong) when any path or
/// size is not one a capsule holds. Check `dir` after.
pub fn unpack(file: impl AsRef<Path>, dir: impl AsRef<Path>) -> Result<()> {
    unpk(&cpath(file.as_ref())?, &cpath(dir.as_ref())?, false)
}

/// [`check`](crate::cap::check) of the capsule in the bundle `file`, read
/// in place: unpacked to a new folder under the system's temporary
/// folder, checked and removed.
pub fn checkpack(file: impl AsRef<Path>, o: &crate::cap::Opts) -> Result<crate::cap::Report> {
    let t = std::env::temp_dir().join(format!(
        "noqtis-{}-{}",
        std::process::id(),
        crate::random(8)?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let (f, d) = (cpath(file.as_ref())?, cpath(&t)?);
    unpk(&f, &d, false)?;
    let r = crate::cap::check(&t, o);
    unpk(&f, &d, true)?;
    r
}

/// Checks an append-only chain of capsules, oldest first (each sealed in
/// format 2 with the one before as its only input, all by the first
/// one's key, `pk` when given): the report ("link", "key" and "head"
/// rows) and the last capsule's id when every row passed.
pub fn chain(
    dirs: &[&Path],
    pk: Option<&[u8]>,
    anchors: &[&[u8]],
) -> Result<(Report, Option<[u8; 32]>)> {
    let dc = dirs.iter().map(|p| cpath(p)).collect::<Result<Vec<_>>>()?;
    let dp: Vec<*const c_char> = dc.iter().map(|c| c.as_ptr()).collect();
    let a: Vec<*const u8> = anchors.iter().map(|x| x.as_ptr()).collect();
    let al: Vec<usize> = anchors.iter().map(|x| x.len()).collect();
    let nul = |n: usize| n == 0;
    let o = ffi::Copt {
        trust: pk.map_or(ptr::null(), |k| k.as_ptr()),
        trustlen: pk.map_or(0, |k| k.len()),
        anc: if nul(a.len()) {
            ptr::null()
        } else {
            a.as_ptr()
        },
        anclen: if nul(a.len()) {
            ptr::null()
        } else {
            al.as_ptr()
        },
        nanc: a.len(),
        only: ptr::null(),
        nonly: 0,
        lin: ptr::null(),
        nlin: 0,
        stmt: ptr::null(),
        stmtlen: ptr::null(),
        nstmt: 0,
    };
    let mut head = [0u8; 32];
    let mut r = ptr::null_mut();
    // SAFETY: the arrays and options are alive across the call
    let c = unsafe { ffi::nqdchain(dp.as_ptr(), dp.len(), &o, head.as_mut_ptr(), &mut r) };
    let rep = drep(c, r)?;
    let ok = rep.ok();
    Ok((rep, if ok { Some(head) } else { None }))
}

// ---- the environment ----

/// One package of the record's runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkg {
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: String,
    /// Where it came from ("crates.io", a git URL, "local", ...).
    pub source: String,
}

/// What [`env`] records besides the platform.
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// The random number generator (its kind) and its seed.
    pub rng: Option<(String, Option<String>)>,
    /// The lock files to record (None: the known ones at the top of dir).
    pub locks: Option<Vec<String>>,
    /// The packages (None: [`packages`] of dir).
    pub packages: Option<Vec<Pkg>>,
}

/// The lock files [`env`] records when they are at the top of the folder.
pub const LOCKS: [&str; 12] = [
    "renv.lock",
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",
    "Cargo.lock",
    "go.sum",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "environment.yml",
    "Manifest.toml",
];

/// The packages of the Rust build: those of `Cargo.lock` at the top of
/// `dir` (name, version, source, or "local" for a path package), read
/// with no network, else this crate alone. A Rust program does not know
/// its dependencies at run time; the lock file does.
pub fn packages(dir: impl AsRef<Path>) -> Vec<Pkg> {
    let mut out = Vec::new();
    if let Ok(t) = std::fs::read_to_string(dir.as_ref().join("Cargo.lock")) {
        for b in t.split("[[package]]").skip(1) {
            let v = |k: &str| {
                b.lines()
                    .find_map(|l| l.strip_prefix(k).and_then(|r| r.trim().strip_prefix('=')))
                    .map(|r| r.trim().trim_matches('"').to_string())
            };
            if let (Some(n), Some(ver)) = (v("name "), v("version ")) {
                let src = v("source ").unwrap_or_else(|| "local".into());
                out.push(Pkg {
                    name: n,
                    version: ver,
                    source: src,
                });
            }
        }
    }
    if out.is_empty() {
        out.push(Pkg {
            name: "noqtis".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            source: "crates.io".into(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
    out.dedup_by(|a, b| a.name == b.name);
    out
}

fn osname() -> &'static str {
    match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "macos",
        "linux" => "linux",
        "freebsd" => "freebsd",
        "openbsd" => "openbsd",
        "netbsd" => "netbsd",
        _ => "other",
    }
}

/// Records the environment in the record's "env", as `noqtis env` does
/// (os, arch, noqtis, locale, tz, the lock files at the top of `dir` with
/// their SHA-256, the rng and its seed), with the Rust runtime: the
/// compiler version this crate was built with and the packages. The
/// element.
pub fn env(dir: impl AsRef<Path>, o: &Env) -> Result<String> {
    let dp = dir.as_ref();
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let mut e = format!(
        "{{\"os\":{},\"arch\":{},\"noqtis\":{}",
        jstr(osname()),
        jstr(std::env::consts::ARCH),
        jstr(&crate::version())
    );
    if let Some(l) = var("LC_ALL").or_else(|| var("LANG")) {
        e += &format!(",\"locale\":{}", jstr(&l));
    }
    if let Some(t) = var("TZ") {
        e += &format!(",\"tz\":{}", jstr(&t));
    }
    let mut p = o.packages.clone().unwrap_or_else(|| packages(dp));
    p.sort_by(|a, b| a.name.cmp(&b.name));
    let ps: Vec<String> = p
        .iter()
        .map(|k| {
            format!(
                "{{\"name\":{},\"version\":{},\"source\":{}}}",
                jstr(&k.name),
                jstr(&k.version),
                jstr(&k.source)
            )
        })
        .collect();
    e += &format!(
        ",\"runtime\":{{\"language\":\"rust\",\"version\":{},\"packages\":[{}]}}",
        jstr(env!("NQRUSTC")),
        ps.join(",")
    );
    let want: Vec<String> = match &o.locks {
        Some(l) => l.clone(),
        None => LOCKS.iter().map(|s| s.to_string()).collect(),
    };
    let mut lk = Vec::new();
    for f in &want {
        let fp = dp.join(f);
        if !fp.is_file() {
            if o.locks.is_some() {
                return Err(Error::why(
                    -1,
                    format!("{f}: not a file in {}", dp.display()),
                ));
            }
            continue;
        }
        // opened from dir, never through a link (nqdsha)
        let (dc, fc) = (cpath(dp)?, cs(f)?);
        let mut d = [0u8; 32];
        // SAFETY: valid strings; d has 32 bytes; size may be NULL
        let c = unsafe { ffi::nqdsha(dc.as_ptr(), fc.as_ptr(), d.as_mut_ptr(), ptr::null_mut()) };
        if c != 0 {
            let w = if c == -1 {
                "a link or not a plain file, refused"
            } else {
                "cannot be read"
            };
            return Err(Error::why(c, format!("{}: {w}", fp.display())));
        }
        let h: String = d.iter().map(|x| format!("{x:02x}")).collect();
        lk.push((f.clone(), h));
    }
    lk.sort();
    if !lk.is_empty() {
        let l: Vec<String> = lk
            .iter()
            .map(|(p, h)| format!("{{\"path\":{},\"sha256\":\"{h}\"}}", jstr(p)))
            .collect();
        e += &format!(",\"locks\":[{}]", l.join(","));
    }
    if let Some((k, s)) = &o.rng {
        e += &format!(",\"rng\":{{\"kind\":{}", jstr(k));
        if let Some(s) = s {
            e += &format!(",\"seed\":{}", jstr(s));
        }
        e.push('}');
    }
    e.push('}');
    put(dp, "env", &e)?;
    Ok(e)
}
