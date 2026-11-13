# Data record format

| | |
|---|---|
| **Format** | `noqtis-data-1` |
| **File** | `noqtis.data.json` at the top of a capsule folder |
| **Status** | Version 1; any incompatible change gets a new format string |
| **Reference implementation** | `nqd/` of NOQTIS (`nqdparse`, `nqdjson`, `nqdchk`) |

The record is listed in the capsule's manifest and covered by its seal
like any other file ([capsule format](https://noqtis.dev/spec/capsule/)). The full
member list, with the types and what a reader must refuse, is
[noqtis-data(5)](https://noqtis.dev/reference/man/noqtis-data-5/); this page
summarises it.

## Encoding

- Canonical JSON (RFC 8785): UTF-8, no whitespace outside strings,
  members sorted by UTF-16 code units, minimal escapes, numbers as
  ECMAScript writes IEEE doubles.
- A reader MUST reject a record that is not byte-identical to its
  canonical form, has a member name twice, a string with U+0000 or
  invalid UTF-8, a non-finite number, nesting deeper than 32, or more
  than 64 MiB.
- A reader MUST reject any member it does not know, so a record of a
  later format is never half-read.
- Arrays keyed by `path` (`sources`, `schemas`, `stats`, `chunks`) or `name`
  (`checks`) are sorted by the key's bytes, each key once; `steps` and
  `commits` keep their order; no array of objects is empty.

## Members

| Member | Holds |
|---|---|
| `format` | `"noqtis-data-1"` (required) |
| `sources` | per file: `path`, `sha256`, `size` (required); `url`, `resolver` (`kind`: direct, ckan, socrata, arcgis, wayback; `base`, `id`, `resource`, `format`, `layer`), `retrieved`, `etag`, `modified`, `licence`, `publisher`, `title`, `archived` (`url`, `time`), `mirrors`, `synthetic` |
| `schemas` | per CSV file: `path`, `kind` (`csv`); `delim`, `header`, `na`, `rows` (`min`, `max`), `columns` (`name`, `type`: int, real, text, date, bool; `nulls`, `min`, `max`, `set`), `rules` (`kind`: unique, notnull, range, set, incr, complete, distinct, regex, mad, rows, cols, with their arguments: `col`, `cols`, `min`, `max`, `set`, `share`, `pattern`) |
| `stats` | per CSV file: `path`, `rows`, `delim`, `header`, `columns` (`name`, `n`, `nulls`; numeric `q`, `edges`, `counts`, `digits`; categorical `cats`, `other`; a calibration `cal`: `n`, `psi`, `p`, `bp`) |
| `chunks` | per large file: `path`, `size`, `chunk` (1024 to 2^30 bytes), `digests` (the SHA-256 of each run of `chunk` bytes, the last short: exactly ceil(`size` / `chunk`)) |
| `env` | `os`, `arch`, `kernel`, `cpu`, `locale`, `tz`, `noqtis`, `build`, `runtime` (`language`, `version`, `packages`), `locks`, `rng` (`kind`, `seed`) |
| `steps` | `kind` (recode, filter, derive, script, other), `from`, `to`, `note`, `script`, `sha256` |
| `checks` | `name`, `status` (pass, warn, fail); `expected`, `observed`, `tol` (at least 0), `note`: with numbers, `\|observed - expected\| <= tol` recomputes the result |
| `commits` | `kind` (randomisation, preregistration, other), `created`, `alg` (sha3-256), `digest`; `after`, `label` |
| `cite` | `title`; `authors`, `version`, `doi`, `url`, `licence`, `year` |

A `regex` rule's `pattern` is a small subset of regular expressions
(literals, classes, `.`, `^`, `$`, `*`, `+`, `?`, `|`, groups; no
counted repetition or back-references), matched anywhere in the value
over code points, in time linear in the value's length;
[noqtis-data(5)](https://noqtis.dev/reference/man/noqtis-data-5/) gives
the grammar a reader must hold to. A `mad` rule fails a value further
from the median than `max` times 1.4826 times the median absolute
deviation.

How `stats` is made, and the tests made from it, is defined in
[noqtis-drift(1)](https://noqtis.dev/reference/man/noqtis-drift-1/).
