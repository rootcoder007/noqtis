# Data records, schemas and drift

A capsule proves that its files are the ones sealed. A data record,
`noqtis.data.json` in the capsule folder, adds what the files are: where
each came from, the shape of each CSV file, and summaries that show
later whether a new copy of the data has drifted. The record is an
ordinary file of the capsule, so the seal covers it, and
[`noqtis check`](https://noqtis.dev/reference/man/noqtis-check-1/) fails if it
changes. The format is [`noqtis-data-1`](https://noqtis.dev/spec/data/).

## Record the sources

```sh
noqtis data add --url https://example.org/crime.csv \
  --publisher "City of Example" --licence OGL-Canada-2.0 \
  --retrieved now results data/crime.csv
noqtis data check results
```

`data add` records the file's SHA-256 and size, with where it came
from; run it again after fetching the file again and the URL and the
rest are kept. `--synthetic` marks a generated stand-in for the real
data: every report line about it then says `[synthetic]`.
`data check` checks every listed file against the record, and says
what to do about each failure.

A stand-in with the shape of the real data, for tests and examples
where the real data cannot go, is made from the schema pinned for its
path, such as the real file's schema put back under the new path with
`noqtis data put`:

```sh
noqtis data syn --seed 42 --rows 1000 results data/fake.csv
```

The same seed gives the same bytes on every platform; the file is
recorded as a source marked `synthetic`, so it cannot pass for real
data, and `data syn` never writes over a file not so marked.

Results computed elsewhere (a published total, a falsification test)
go in as recorded checks, with what was expected, what was observed and
the tolerance, so that a later reader can recompute them. `data check`
does: a check recorded as `pass` whose observed number is further from
the expected one than `tol` fails, as does one recorded as `fail`:

```sh
echo '{"name":"total","status":"pass","expected":1204,"observed":1203.5,"tol":0.5}' |
  noqtis data put results checks -
```

A step that recodes a column records the digest of its mapping, and
`data check` checks the mapping file against it:

```sh
noqtis hash results/map/offence.csv
echo '{"kind":"recode","from":"offence","to":"group","script":"map/offence.csv","sha256":"<its SHA-256>"}' |
  noqtis data put results steps -
```

`data check` also makes each file's drift summaries again and compares
them with the recorded ones byte for byte.

## Fetch the sources, and see if they changed

`noqtis src` fetches the files a record names. `src add` records a file
by its address, or by its portal and dataset (CKAN, Socrata, ArcGIS),
fetching it when it is not there yet; `--wayback` pins the Wayback
Machine's copy of it too:

```sh
noqtis src add --portal ckan --base https://data.ontario.ca \
  --id ontario-public-library-statistics --wayback \
  results data/libraries.csv
```

Later, perhaps on another machine, `src fetch` restores each missing
file from the first address that gives the recorded bytes: the URL, the
portal, each mirror, then the archived copy. It says which copy it used,
and never writes bytes whose SHA-256 or size differ from the record:

```sh
noqtis src fetch results
```

`src refresh` fetches each source again from its URL or portal and says
whether it is unchanged, changed (with the old and the new SHA-256 and
size) or unreachable, with exit status 0, 1 and 3; `--write` takes the
new bytes into the capsule and records them, to be sealed again. A
synthetic source is never fetched, and every line about it says so.
`src resolve` asks each portal where its file is now.

## Pin the schema

```sh
noqtis schema infer --put --ranges results data/crime.csv
noqtis schema check results
```

`schema infer` reads the CSV file (RFC 4180, any one-byte delimiter)
and pins its columns, the narrowest type of each, missing values, the
row count and, with `--ranges`, each number and date range. Rules are
part of a file's schema element, which `data put` replaces whole: take
the pinned one (`noqtis data show --json`), add `rules`, and put it
back. A schema of rules alone, as here, checks only them: that `id` is
unique, `year` within bounds, every `code` two capitals, a dash and
two digits, and no `count` further from the median than 5 robust
standard deviations (5 times 1.4826 times the median absolute
deviation).

```sh
noqtis data put results schemas - <<'EOF2'
{"path":"data/crime.csv","kind":"csv","rules":[
 {"kind":"unique","col":"id"},
 {"kind":"range","col":"year","min":1998,"max":2026},
 {"kind":"regex","col":"code","pattern":"^[A-Z][A-Z]-\\d\\d$"},
 {"kind":"mad","col":"count","max":5}]}
EOF2
```

The other rules are `notnull`, `set`, `incr` (each value at least the
one before), `complete` (a share not missing), `distinct` (a number of
distinct values), `rows` and `cols`. A `regex` pattern is a small
subset (literals, classes, `.`, `^`, `$`, `*`, `+`, `?`, `|`, groups),
matched anywhere in the value unless anchored, in time linear in the
value whatever the pattern.

## Find drift later, without the old data

```sh
noqtis drift pin results data/crime.csv
noqtis seal -k me results
# a year later
curl -o new.csv https://example.org/crime.csv
noqtis drift check results data/crime.csv=new.csv
```

`drift pin` keeps summaries of a fixed size whatever the file's size: a
quantile sketch of each numeric column, the bins of the population
stability index, first-digit counts, and the 1,000 most frequent values
of each other column. `drift check` compares a later file with them:
Kolmogorov-Smirnov, PSI and Jensen-Shannon for numeric columns,
chi-square of homogeneity for the others, Benford's first-digit test.
It exits `0` when nothing drifted, `1` when a column failed and `3`
when one only warned, for CI.

How often a column warns when nothing changed depends on the data. To
set the warnings from data known not to have drifted (two downloads a
day apart, or two halves of a random split), calibrate:

```sh
noqtis drift cal results data/crime.csv=copy1.csv data/crime.csv=copy2.csv
```

Each column then keeps, in the record, the largest PSI and the smallest
p-values seen on those files, and `drift check` warns of it only beyond
them. The definitions, the levels and the
measured error of the sketch are in
[noqtis-drift(1)](https://noqtis.dev/reference/man/noqtis-drift-1/).

## Compare two capsules

```sh
noqtis diff results-2025 results-2026
noqtis check -p me.pub -r archive/      # every capsule under archive/
```

`diff` lists the files added, removed or changed, and what changed in
the data records: sources, columns, summaries, environment, steps.

## A report

```sh
noqtis report -p me.pub -o report.md results
noqtis report -f txt results
```

`report` checks the capsule and its data record in one run and writes
what it found, with what the record says of the data (sources, schemas,
drift summaries, environment, steps, recorded checks, commitments,
citation), as Markdown or plain text. `--json` gives the counts (failed,
verified, changed) and every check for a machine, and `--github` a
workflow annotation per failed check.

## Check a piece of a large file

```sh
noqtis chunk pin --size 4194304 results data/big.parquet
noqtis seal -k me results
# later, with only bytes 8 MiB to 16 MiB of the file
noqtis check -p me.pub --only noqtis.data.json results
noqtis chunk check --at 8388608 results data/big.parquet part
```

`chunk pin` records the SHA-256 of each run of `--size` bytes; the file
is read once and never split. `chunk check` reads only the piece it is
given and checks each whole chunk in it, so a range fetched alone, or the
part of a file that survived, can be checked without the rest.

## Ship a reproducibility bundle

```sh
noqtis pack init --template r study
noqtis data add --url https://example.org/a.csv study data/a.csv
noqtis pack build -k me -o study.nqb study
noqtis pack check -p me.pub study.nqb
noqtis check -p me.pub study.nqb      # what a reader runs
```

`pack init` lays out `data/`, the code folder and `output/` with a
README and an empty record. `pack build` records the environment and
lock files (`noqtis env`), seals the folder and writes it as one file
(`noqtis export --as bundle`); `pack check` checks the capsule, the
record and each lock file, and that an environment and a lock file are
recorded. `noqtis check` reads the bundle file as it is; `noqtis pack
unpack` opens it into a folder, refusing any path that would leave it.
The format is in the capsule specification, section 14.

## Keep a chain of capsules

```sh
noqtis seal --format 2 -k me log/2026-01
noqtis seal -k me --input prev=log/2026-01 log/2026-02
noqtis chain -p me.pub log/2026-01 log/2026-02
```

Each capsule sealed with the last as its only input signs the last
one's id. `noqtis chain` checks every link, that each follows the one
before it, with no fork or gap, and that one key sealed them all, and
prints the head: the last link's id.

## Commands

| Command | What it does |
|---|---|
| `noqtis data init\|add\|put\|del\|fmt\|show\|check` | make, show and check the data record |
| `noqtis src add\|resolve\|fetch\|refresh\|list` | fetch the sources from their URL, portal, mirrors or archived copy, verified; say whether they changed |
| `noqtis schema infer\|check` | pin and check the schema of CSV files |
| `noqtis drift pin\|check` | summarise CSV files, and say later if they drifted |
| `noqtis chunk pin\|check` | chunk digests of a large file; check a piece of it alone |
| `noqtis env`, `commit`, `reveal`, `cite` | the environment, commitments, citation |
| `noqtis diff` | what changed between two capsules |
| `noqtis pack init\|build\|check\|unpack` | start, build and check a reproducibility bundle |
| `noqtis export --as bundle` | a capsule as one file, which `noqtis check` reads |
| `noqtis chain` | check an append-only chain of capsules and give its head |

## From R and Python

```r
noqtis::nqdadd("results", "data/crime.csv", url = "https://example.org/crime.csv")
noqtis::nqschema("results", "data/crime.csv", put = TRUE)
noqtis::nqdpin("results", "data/crime.csv")
noqtis::nqdrift("results", "data/crime.csv", current = "new.csv")
```

```python
from noqtis import data
data.add("results", "data/crime.csv", url="https://example.org/crime.csv")
data.schema("results", "data/crime.csv", put=True)
data.pin("results", "data/crime.csv")
data.drift("results", ["data/crime.csv"], ["new.csv"]).level
```

Both write the same bytes as the command line.

From Rust, Go and Java the same steps are `noqtis::data::{add, schema,
put, pin, drift}`, `noqtis.DataAdd`, `Schema`, `DataPut`, `Pin` and
`Drift`, and `Data.add`, `schema`, `put`, `pin` and `drift`.
