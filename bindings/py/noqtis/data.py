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
from typing import Any, Iterable, List, Mapping, NamedTuple, Optional, Union

from . import _noqtis as _c
from ._alg import path

PathLike = Union[str, bytes, "os.PathLike[str]", "os.PathLike[bytes]"]
Element = Union[str, Mapping[str, Any]]

__all__ = ["DRow", "DReport", "load", "text", "add", "put", "delete",
           "check", "schema", "schemacheck", "pin", "drift", "diff"]


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
        p = path(cur[i]) if cur is not None else path(os.path.join(
            os.fsdecode(d), f))
        r = _rep(_c.ddrift(s, p, _dl(delim), not header, float(psiwarn),
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
