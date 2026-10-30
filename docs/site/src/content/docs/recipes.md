---
title: Recipes
description: Step-by-step recipes for a replication package, OSF and Dataverse deposits, GitHub Actions, showing only some files, and rotating a key.
---

Each recipe is a short sequence of commands you can copy. They assume a
key pair made once with `noqtis keygen -a ML-DSA-65 -o me` and `me.pub`
published where your readers can find it (your web page, the paper's
data availability statement, the repository).

## A replication package

Seal the folder that holds the data, code and outputs of a paper, with a
note of how it was made and a timestamp:

```sh
cat > meta.json <<'EOF'
{"title": "Replication package for ...", "doi_of_paper": "10.xxxx/...",
 "software": {"R": "4.5.1", "noqtis": "0.1.1"}}
EOF
noqtis seal -k me --meta meta.json --tsa http://timestamp.example \
  replication/
noqtis check -p me.pub replication/
```

- Seal **last**, after the final run: any later change, even a new file,
  fails the check.
- Keep `meta.json` outside the folder; its content is copied into the
  manifest.
- `--tsa` takes any RFC 3161 time-stamping authority; give it twice for
  a fallback. A reader checks the time with `--anchor <tsa-root.der>`
  ([timestamps](/noqtis/guides/timestamps/)).
- For a package built from earlier sealed capsules (raw data sealed when
  collected, say), add `--input raw=data-raw/` so the manifest records
  which capsule it came from; readers check both with
  `noqtis check --lineage data-raw/ -p me.pub replication/`.

## Depositing on OSF

OSF stores files as you upload them. Upload the folder as a ZIP so the
names and layout survive:

```sh
(cd replication && zip -r -X ../replication.zip .)
```

Readers download it, unzip it into an empty folder and check:

```sh
mkdir rep && unzip -q replication.zip -d rep
noqtis check -p me.pub rep
```

Put the fingerprint `noqtis inspect` prints, or `me.pub` itself, in the
project's wiki so readers can compare.

## Depositing on Dataverse

Dataverse changes some uploads: it **unpacks a ZIP** into its files and
**converts tabular files** (CSV, Stata, SPSS, R data) into its own
`.tab` format. Both break a seal. To keep the capsule byte for byte:

- upload a ZIP inside a ZIP (Dataverse unpacks only the outer one), or a
  `.tar.gz`, which it leaves as one file; and
- tell readers to download the **original** file, not a converted one.

```sh
tar -czf replication.tar.gz -C replication .
```

```sh
mkdir rep && tar -xzf replication.tar.gz -C rep
noqtis check -p me.pub rep
```

## Sealing in GitHub Actions

See [Use in CI](/noqtis/guides/ci/) for the full guide. In short: keep the
secret key file in an encrypted repository secret, keep `me.pub` in the
repository, and seal with the action:

```yaml
- uses: rootcoder007/noqtis@v0
  with:
    mode: seal
    dir: results
    key: ${{ secrets.NOQTIS_KEY }}
    pub: keys/me.pub
```

Check in a later job, or in someone else's workflow, with `mode: check`;
the job fails unless every check passes.

## Showing some files and not the others

Seal with format 2, then make a proof of the files you can share:

```sh
noqtis seal -k me --format 2 study/
noqtis prove -p me.pub -o table1.proof.json study/ out/table1.csv
```

Send `table1.proof.json` and `out/table1.csv`. The reader checks that the
file is the one in your sealed capsule, without seeing any other name or
digest:

```sh
mkdir -p shown/out && cp table1.csv shown/out/
noqtis check -p me.pub --proof table1.proof.json shown
```

## Rotating a key

When you replace a key (a new machine, a stronger algorithm, a key that
may have leaked), write a statement signed by both keys and publish it
next to the old `.pub`:

```sh
noqtis keygen -a ML-DSA-87 -o me2
noqtis rotate -k me -n me2 --reason "new laptop" -o me-rotate.json
```

Readers who trusted `me.pub` then accept seals made with the new key:

```sh
noqtis check -p me.pub --keys me-rotate.json new-results/
```

Seals made with the old key keep passing **only** if they carry a
verified timestamp from before the rotation; without one, nobody can
tell whether the old key made them before or after it was replaced.
That is why sealing with `--tsa` is worth it for anything that must last.

If a secret key leaked, revoke it instead, from the time you believe it
was safe until:

```sh
noqtis revoke -k me --at 2026-10-01T00:00:00Z --reason "laptop stolen" \
  -o me-revoke.json
noqtis check -p me.pub --keys me-revoke.json old-results/
```

## Moving a capsule

A capsule is a plain folder: it survives `cp -r`, `rsync -a`, Git, ZIP
and tar, as long as the tool keeps names and contents byte for byte.
Watch out for tools that change them:

- **Line endings.** Git on Windows with `core.autocrlf=true` rewrites
  text files; add `* -text` to `.gitattributes` in a sealed folder.
- **Case-insensitive file systems.** Two names that differ only in case
  are refused when sealing, so this cannot bite after the fact.
- **Metadata files.** macOS adds `.DS_Store` and `._*` files when you
  browse or copy; they fail the check as `extra`. Delete them, or seal
  after copying.
