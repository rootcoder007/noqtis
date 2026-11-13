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

Results computed elsewhere (a published total, a falsification test)
go in as recorded checks; one recorded as `fail` fails `data check`:

```sh
echo '{"name":"total","status":"pass","expected":1204,"observed":1204}' |
  noqtis data put results checks -
```

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
unique and `year` within bounds.

```sh
noqtis data put results schemas - <<'EOF2'
{"path":"data/crime.csv","kind":"csv","rules":[
 {"kind":"unique","col":"id"},
 {"kind":"range","col":"year","min":1998,"max":2026}]}
EOF2
```

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
when one only warned, for CI. The definitions, the levels and the
measured error of the sketch are in
[noqtis-drift(1)](https://noqtis.dev/reference/man/noqtis-drift-1/).

## Compare two capsules

```sh
noqtis diff results-2025 results-2026
noqtis check -p me.pub -r archive/      # every capsule under archive/
```

`diff` lists the files added, removed or changed, and what changed in
the data records: sources, columns, summaries, environment, steps.

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
