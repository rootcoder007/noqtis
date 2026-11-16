# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""The data record of a capsule (noqtis.data.json, noqtis-data-1).

The record says where each data file of a capsule came from, the schema
of its CSV files, summaries that show drift later, and the steps and
checks made with it. It is a file of the capsule like any other: seal
the folder after changing it, and the seal covers it. Elements go in as
JSON (a dict or a str) and the library writes the record in canonical
form, the same bytes the noqtis tool and every other binding write.

>>> from noqtis import data
>>> data.add("results", ["data/a.csv"], url="https://example.org/a.csv")  # doctest: +SKIP
>>> data.check("results").ok  # doctest: +SKIP
True
"""
import datetime
import json
import os
import time
from typing import (Any, Iterable, List, Mapping, NamedTuple, Optional, Tuple,
                    Union)

from . import _noqtis as _c
from ._alg import path

PathLike = Union[str, bytes, "os.PathLike[str]", "os.PathLike[bytes]"]
Element = Union[str, Mapping[str, Any]]

__all__ = ["DRow", "DReport", "load", "text", "add", "put", "delete",
           "check", "schema", "schemacheck", "pin", "drift", "diff",
           "addrs", "verify", "field", "request", "reply", "wayback",
           "parse", "checkschema", "synth", "calibrate", "chunks", "piece",
           "commitment", "commit", "reveal", "cite", "report", "packages",
           "env"]


class DRow(NamedTuple):
    """One row of a data check: its name, whether it passed, why, and
    for a drift row its numbers (``stats``, a dict) or None."""

    check: str
    ok: bool
    detail: str
    stats: Optional[Mapping[str, Any]]


class DReport:
    """What a data check found: ``rows``; ``ok`` is True only when the
    library passed it as a whole; ``level`` is "ok", "warn" (a
    "drift.warn" row, none failed) or "fail"."""

    __slots__ = ("rows", "code")

    def __init__(self, code: int, rows: Iterable[DRow]) -> None:
        self.code = code
        self.rows: List[DRow] = list(rows)

    @property
    def ok(self) -> bool:
        return self.code == 0 and bool(self.rows) and all(
            r.ok for r in self.rows)

    @property
    def level(self) -> str:
        if not self.ok:
            return "fail"
        return "warn" if any(r.check == "drift.warn" for r in self.rows) \
            else "ok"

    def __repr__(self) -> str:
        return "DReport(%s, %d rows)" % (self.level, len(self.rows))


def _rep(out) -> DReport:
    code, rows = out
    return DReport(code, (DRow(c, ok, d, json.loads(j) if j else None)
                          for c, ok, d, j in rows))


def _js(e: Element) -> str:
    return e if isinstance(e, str) else json.dumps(e, ensure_ascii=False)


def _dl(d: str) -> str:
    if not isinstance(d, str) or len(d) != 1 or ord(d) > 127:
        raise ValueError("delim must be one ASCII character")
    return d


def text(dir: PathLike) -> str:
    """The record as its canonical JSON text."""
    return _c.dload(path(dir))


def load(dir: PathLike) -> dict:
    """The record as a dict."""
    return json.loads(text(dir))


def _now() -> str:
    e = os.environ.get("SOURCE_DATE_EPOCH")
    t = int(e) if e else int(time.time())
    return datetime.datetime.fromtimestamp(
        t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def add(dir: PathLike, files: Iterable[str], url: Optional[str] = None,
        title: Optional[str] = None, publisher: Optional[str] = None,
        licence: Optional[str] = None, retrieved: Optional[str] = None,
        synthetic: bool = False) -> None:
    """Records each file's SHA-256 and size as a source, keeping what the
    record already says of it, with where it came from. ``retrieved`` is
    "now" or a UTC time YYYY-MM-DDTHH:MM:SSZ."""
    files = [files] if isinstance(files, str) else list(files)
    if url is not None and len(files) > 1:
        raise ValueError("url describes one file: add the files one at a "
                         "time")
    f = {"url": url, "title": title, "publisher": publisher,
         "licence": licence,
         "retrieved": _now() if retrieved == "now" else retrieved}
    f = {k: json.dumps(v, ensure_ascii=False) for k, v in f.items()
         if v is not None}
    if synthetic:
        f["synthetic"] = "true"
    _c.dadd(path(dir), tuple(x.encode() for x in files),
            tuple(k.encode() for k in f),
            tuple(v.encode() for v in f.values()))


def put(dir: PathLike, member: str, element: Element) -> None:
    """Adds an element to a member: "sources", "schemas", "stats" (the
    one with the same path is replaced), "checks" (the same name),
    "steps", "commits" (appended), or sets "env" or "cite"."""
    _c.dput(path(dir), member, _js(element))


def delete(dir: PathLike, member: str, key: Optional[str] = None) -> None:
    """Removes the element of member with path or name key, or the whole
    member when key is None."""
    _c.ddel(path(dir), member, key)


def check(dir: PathLike) -> DReport:
    """Checks the record and every file it lists: each source's SHA-256
    and size, each schema, and the checks recorded as failed."""
    return _rep(_c.dchk(path(dir)))


def schema(dir: PathLike, files: Iterable[str], put: bool = False,
           delim: str = ",", header: bool = True,
           ranges: bool = False) -> List[dict]:
    """The schema of each CSV file (its columns, the narrowest type of
    each, missing values, rows; with ranges, number and date ranges).
    With put, they are recorded in the data record too."""
    files = [files] if isinstance(files, str) else list(files)
    d = path(dir)
    out = [_c.dinfer(d, f, _dl(delim), not header, ranges) for f in files]
    if put:
        for s in out:
            _c.dput(d, "schemas", s)
    return [json.loads(s) for s in out]


def schemacheck(dir: PathLike, files: Optional[Iterable[str]] = None
                ) -> DReport:
    """The schema and rule rows of check(), of the files named only when
    files is given."""
    r = check(dir)
    want = None if files is None else set(
        [files] if isinstance(files, str) else files)
    rows = [x for x in r.rows if x.check in ("schema", "rule") and (
        want is None or
        x.detail.split(":", 1)[0].replace(" [synthetic]", "") in want)]
    return DReport(0 if rows and all(x.ok for x in rows) else -3, rows)


def pin(dir: PathLike, files: Iterable[str], delim: str = ",",
        header: bool = True) -> None:
    """Records each CSV file's summaries (noqtis-drift(1)) in the record."""
    files = [files] if isinstance(files, str) else list(files)
    d = path(dir)
    for f in files:
        _c.dput(d, "stats", _c.dstats(d, f, _dl(delim), not header))


def drift(dir: PathLike, files: Optional[Iterable[str]] = None,
          current: Optional[Iterable[PathLike]] = None,
          psiwarn: float = 0.1, psifail: float = 0.25, alpha: float = 0.001,
          minn: float = 1000, benford: bool = False, delim: str = ",",
          header: bool = True) -> DReport:
    """Compares each summarised file (or the file of current in its
    place) with its summary: Kolmogorov-Smirnov, PSI and Jensen-Shannon,
    chi-square of homogeneity, Benford (noqtis-drift(1))."""
    d = path(dir)
    if files is None:
        files = [s["path"] for s in load(dir).get("stats", [])]
    files = [files] if isinstance(files, str) else list(files)
    cur = None if current is None else list(current)
    if not files:
        raise ValueError("the record has no summaries: pin some first")
    if cur is not None and len(cur) != len(files):
        raise ValueError("current needs one path per file")
    code, rows = 0, []
    for i, f in enumerate(files):
        s = _c.dkey(d, "stats", f)
        if s is None:
            raise ValueError("no summary of %s: pin one first" % f)
        # a file of the capsule is opened inside it, never through a
        # link; a file of current is the caller's, opened by its path
        at = (None, path(cur[i])) if cur is not None else (d, f.encode())
        r = _rep(_c.ddrift(s, *at, _dl(delim), not header, float(psiwarn),
                           float(psifail), float(alpha), float(minn),
                           benford))
        code = code or r.code
        rows += r.rows
    return DReport(code, rows)


def diff(a: PathLike, b: PathLike) -> DReport:
    """What changed from capsule a to capsule b: one failed row per
    difference (files, sources, schemas, summaries, env, ...); ok when
    nothing differs."""
    return _rep(_c.ddiff(path(a), path(b)))


# ---- sources ----

#: where each address of addrs() comes from (nqdaddr(3))
KINDS = {1: "url", 2: "portal", 3: "mirror", 4: "archived"}


def addrs(dir: PathLike, file: str) -> List[Tuple[str, str]]:
    """The addresses the source file can be fetched from, in the order to
    try them, each as (kind, address): "url", "portal" (the request to
    send; read its reply with reply()), "mirror", "archived" (a Wayback
    Machine copy's raw bytes). [] for a synthetic source."""
    return [(KINDS[k], u) for k, u in _c.daddr(path(dir), file)]


def verify(dir: PathLike, file: str, b: bytes) -> bool:
    """True when the bytes b are the source file's recorded bytes (size
    and SHA-256): only such bytes may be taken for the file."""
    return _c.dvrfy(path(dir), file, bytes(b))


def field(dir: PathLike, member: str, i: int, name: str) -> Optional[str]:
    """The field name of element i of member (0 for "env" and "cite"): a
    string as its text, anything else as canonical JSON; None when there
    is none."""
    return _c.dfld(path(dir), member, int(i), name)


def request(resolver: Element) -> str:
    """The address to ask (a GET) for the file of a source's resolver
    (CKAN, Socrata, ArcGIS or the Wayback Machine)."""
    return _c.drslv(_js(resolver))


def reply(resolver: Element, body: bytes) -> Tuple[str, str]:
    """The file's address read from the portal's reply to request(), and
    for the Wayback Machine the copy's time ("" otherwise)."""
    return _c.drsp(_js(resolver), bytes(body))


def wayback(url: str) -> str:
    """The raw-bytes address of a Wayback Machine copy (any other http://
    or https:// address as it is)."""
    return _c.dwb(url)


def parse(text: str) -> str:
    """The record in ``text`` checked as ``noqtis data check`` reads one
    and written in canonical form; DecodeError says what is wrong."""
    return _c.dparse(text)


def checkschema(dir: PathLike, schema: Element) -> DReport:
    """Checks the CSV file of the "schemas" element ``schema`` (a dict or
    its JSON) in ``dir`` against it: header, types, missing values,
    ranges, sets, rows and rules."""
    return _rep(_c.dschk(path(dir), _js(schema)))


def synth(dir: PathLike, file: str, seed: int = 0, rows: int = 0) -> None:
    """Writes a synthetic stand-in for the CSV file from its recorded
    schema (``rows`` rows, 0: the schema's minimum, else 100; the same
    bytes for the same seed) and records it as a synthetic source. Real
    data is never replaced (ArgError)."""
    _c.dsyn(path(dir), file, int(seed), int(rows))


def calibrate(dir: PathLike, file: str, files: Iterable[PathLike],
              delim: str = ",", header: bool = True) -> dict:
    """Calibrates the drift warnings of the file's summary on ``files``,
    CSV files known not to have drifted from it, and records the result:
    drift() then warns only beyond what they showed."""
    d = path(dir)
    s = _c.dkey(d, "stats", file)
    if s is None:
        raise ValueError("no summary of %s: pin one first" % file)
    e = _c.dcal(s, tuple(path(f) for f in files), _dl(delim), not header)
    _c.dput(d, "stats", e)
    return json.loads(e)


def chunks(dir: PathLike, file: str, chunk: int = 1 << 20) -> dict:
    """Records the SHA-256 of each ``chunk`` bytes (1,024 to 2^30) of the
    large file, so that a piece of it can be checked alone (piece())."""
    d = path(dir)
    e = _c.dchunk(d, file, int(chunk))
    _c.dput(d, "chunks", e)
    return json.loads(e)


def piece(dir: PathLike, file: str, piece: PathLike, off: int = 0
          ) -> DReport:
    """Checks the file ``piece``, the bytes of ``file`` from byte ``off``
    on (a multiple of its chunk), against its recorded chunk digests."""
    e = _c.dkey(path(dir), "chunks", file)
    if e is None:
        raise ValueError("no chunk digests of %s: record them first" % file)
    return _rep(_c.dpiece(e, path(piece), int(off)))


def commitment(salt: bytes, m: bytes) -> str:
    """The commitment to ``m`` under ``salt`` (16 to 1,024 bytes): 64 hex
    digits of SHA3-256 (nqdcommit(3))."""
    return _c.dcommit(bytes(salt), bytes(m))


def commit(dir: PathLike, m: bytes, kind: str = "other",
           label: Optional[str] = None, after: Optional[str] = None) -> bytes:
    """Commits to ``m`` (a randomisation list, an analysis plan) in the
    record, as ``noqtis commit`` does, and returns the 32-byte secret
    salt: keep it outside the capsule until the reveal. ``kind`` is
    "randomisation", "preregistration" or "other"; ``after`` a UTC time
    YYYY-MM-DDTHH:MM:SSZ before which it is not to be revealed."""
    s = _c.rand(32)
    e = {"kind": kind, "created": _now(), "alg": "sha3-256",
         "digest": _c.dcommit(s, bytes(m))}
    if label is not None:
        e["label"] = label
    if after is not None:
        e["after"] = after
    _c.dput(path(dir), "commits", _js(e))
    return s


def reveal(dir: PathLike, m: bytes, salt: bytes) -> Optional[int]:
    """The index in "commits" of the commitment to ``m`` under ``salt``,
    or None when the record has none (every digest compared in constant
    time)."""
    return _c.dreveal(path(dir), bytes(salt), bytes(m))


def cite(dir: PathLike, fmt: str = "cff") -> str:
    """How to cite the data, from the record's "cite": a CITATION.cff
    ("cff") or a BibTeX entry ("bib")."""
    f = {"cff": 1, "bib": 2, "bibtex": 2}.get(fmt)
    if f is None:
        raise ValueError("fmt: 'cff' or 'bib'")
    return _c.dcite(path(dir), f)


def report(dir: PathLike, fmt: str = "md", pk: Optional[bytes] = None) -> str:
    """A report of the capsule, as ``noqtis report`` writes it: whether
    every check passed, the capsule's check (with ``pk`` the seal must be
    by that key), what the data record says and its check. ``fmt`` "md"
    (Markdown) or "txt"."""
    f = {"md": 1, "markdown": 1, "txt": 2, "text": 2}.get(fmt)
    if f is None:
        raise ValueError("fmt: 'md' or 'txt'")
    d = os.fsdecode(path(dir))
    sealed = os.path.exists(os.path.join(d, "noqtis.sig"))
    rec = os.path.exists(os.path.join(d, "noqtis.data.json"))
    if not sealed and not rec:
        raise ValueError("%s holds neither a seal nor a data record" % d)
    return _c.drpt(path(dir), None if pk is None else bytes(pk), f, sealed,
                   rec)


# ---- the environment ----

#: lock files env() records when they are at the top of the folder
LOCKS = ("renv.lock", "uv.lock", "poetry.lock", "Pipfile.lock",
         "requirements.txt", "Cargo.lock", "go.sum", "package-lock.json",
         "pnpm-lock.yaml", "yarn.lock", "environment.yml", "Manifest.toml")


def _osname() -> str:
    import sys
    p = sys.platform
    for k, v in (("win", "windows"), ("darwin", "macos"), ("linux", "linux"),
                 ("freebsd", "freebsd"), ("openbsd", "openbsd"),
                 ("netbsd", "netbsd")):
        if p.startswith(k):
            return v
    return "other"


def _arch() -> str:
    import platform
    m = platform.machine().lower()
    return {"amd64": "x86_64", "x64": "x86_64", "arm64": "aarch64",
            "x86": "i686", "i386": "i686"}.get(m, m or "other")


def packages() -> List[dict]:
    """The installed distributions, as the record's runtime packages:
    name, version and source ("pypi", or the URL a direct install names),
    sorted by name. Read from the installed metadata, no network."""
    from importlib import metadata
    out = {}
    for d in metadata.distributions():
        n = d.metadata["Name"]
        if not n or n in out:
            continue
        src = "pypi"
        u = d.read_text("direct_url.json")
        if u:
            try:
                src = json.loads(u).get("url") or src
            except ValueError:
                pass
        out[n] = {"name": n, "version": d.version or "", "source": src}
    return [out[k] for k in sorted(out)]


def env(dir: PathLike, rng: Optional[str] = None,
        seed: Union[None, int, str] = None,
        locks: Optional[Iterable[str]] = None,
        pkgs: Optional[Iterable[Mapping[str, str]]] = None) -> dict:
    """Records the environment in the record's "env", as ``noqtis env``
    does (os, arch, noqtis, locale, tz, the lock files at the top of
    ``dir`` with their SHA-256, ``rng`` and its ``seed``), with the
    Python runtime: its version and ``pkgs`` (default: packages())."""
    import platform
    if seed is not None and rng is None:
        raise ValueError("seed needs rng, the generator it seeds")
    d = os.fsdecode(path(dir))
    e: dict = {"os": _osname(), "arch": _arch(), "noqtis": _c.version()}
    loc = os.environ.get("LC_ALL") or os.environ.get("LANG")
    if loc:
        e["locale"] = loc
    if os.environ.get("TZ"):
        e["tz"] = os.environ["TZ"]
    p = packages() if pkgs is None else [dict(x) for x in pkgs]
    e["runtime"] = {"language": "python",
                    "version": platform.python_version(),
                    "packages": sorted(p, key=lambda x: x["name"])}
    lk = []
    for f in (LOCKS if locks is None else list(locks)):
        fp = os.path.join(d, f)
        if not os.path.isfile(fp):
            if locks is not None:
                raise ValueError("%s: not a file in %s" % (f, d))
            continue
        # opened from d, never through a link (nqdsha)
        lk.append({"path": f, "sha256": _c.dsha(path(d), f).hex()})
    if lk:
        e["locks"] = sorted(lk, key=lambda x: x["path"])
    if rng is not None:
        e["rng"] = {"kind": rng}
        if seed is not None:
            e["rng"]["seed"] = seed
    _c.dput(path(dir), "env", _js(e))
    return e
