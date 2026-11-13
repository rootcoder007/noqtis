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
- Arrays keyed by `path` (`sources`, `schemas`, `stats`) or `name`
  (`checks`) are sorted by the key's bytes, each key once; `steps` and
  `commits` keep their order; no array of objects is empty.

## Members

| Member | Holds |
|---|---|
| `format` | `"noqtis-data-1"` (required) |
| `sources` | per file: `path`, `sha256`, `size` (required); `url`, `resolver` (`kind`: direct, ckan, socrata, arcgis, wayback; `base`, `id`, `resource`, `format`, `layer`), `retrieved`, `etag`, `modified`, `licence`, `publisher`, `title`, `archived` (`url`, `time`), `mirrors`, `synthetic` |
| `schemas` | per CSV file: `path`, `kind` (`csv`); `delim`, `header`, `na`, `rows` (`min`, `max`), `columns` (`name`, `type`: int, real, text, date, bool; `nulls`, `min`, `max`, `set`), `rules` (`kind`: unique, notnull, range, set, incr, complete, distinct, rows, cols, with their arguments) |
| `stats` | per CSV file: `path`, `rows`, `columns` (`name`, `n`, `nulls`; numeric `q`, `edges`, `counts`, `digits`; categorical `cats`, `other`) |
| `env` | `os`, `arch`, `kernel`, `cpu`, `locale`, `tz`, `noqtis`, `build`, `runtime` (`language`, `version`, `packages`), `locks`, `rng` (`kind`, `seed`) |
| `steps` | `kind` (recode, filter, derive, script, other), `from`, `to`, `note`, `script`, `sha256` |
| `checks` | `name`, `status` (pass, warn, fail); `expected`, `observed`, `tol`, `note` |
| `commits` | `kind` (randomisation, preregistration, other), `created`, `alg` (sha3-256), `digest`; `after`, `label` |
| `cite` | `title`; `authors`, `version`, `doi`, `url`, `licence`, `year` |

How `stats` is made, and the tests made from it, is defined in
[noqtis-drift(1)](https://noqtis.dev/reference/man/noqtis-drift-1/).
