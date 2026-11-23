#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
"""Writes the guides in vignettes/ from the help pages: every help page is
shown once, in the guide of its subject, with what the functions are for
and the example of the page as it runs.

    Rscript tools/vigrd.R . rd.json      the help pages
    python3 tools/vig.py . rd.json

The guides are generated: change a help page (or GROUPS below) and run this
again. vignettes/noqtis.Rmd, the introduction, is written by hand and left
alone.
"""
import json
import pathlib
import re
import sys

repo = pathlib.Path(sys.argv[1])
pages = {p["file"][:-3]: p for p in json.load(open(sys.argv[2]))}

# guide file, title, one sentence, the help pages it holds (in reading order)
GROUPS = [
    ("signatures", "Signatures: ML-DSA, SLH-DSA, Ed25519 and hybrids",
     "Signing and verifying a message, whole or in pieces, with the post-quantum and hybrid algorithms, and the DSSE envelope that carries a signed statement.",
     ["nqsign", "nqsigner", "nqmu", "nqdsse"]),
    ("keys", "Keys: making, storing, identifying and replacing them",
     "Key pairs, the key files of the command-line tool, identity cards that say whose key it is, and statements that rotate or revoke a seal key.",
     ["nqkeygen", "nqreadkey", "nqsxmk", "nqidcard", "nqrotate"]),
    ("key-encapsulation", "Key encapsulation and sealing to a key",
     "Agreeing a shared secret with ML-KEM or HQC, and sealing a message or a file so only the holder of a key can open it.",
     ["nqencap", "nqkseal", "nqboxto"]),
    ("hashes-and-random", "Hashes, ciphers, password hashing and random bytes",
     "SHA-2, SHA-3 and SHAKE with HMAC, KangarooTwelve, BLAKE2b and Argon2id, comparison in constant time, AES-SIV, AES-GCM-SIV and ChaCha20, and random bytes from the operating system.",
     ["nqhash", "nqblake2b", "nqkt", "nqrand"]),
    ("capsules", "Capsules: sealing a folder and checking it later",
     "Sealing every file of a folder under one signature, checking it, proving some files without the rest, bundling capsules and comparing two of them.",
     ["nqseal", "nqinspect", "nqcapid", "nqpack", "nqdiff"]),
    ("timestamps", "Timestamps and evidence records",
     "Asking a time-stamping authority to date a capsule, and renewing that evidence so it outlives the algorithms it was made with.",
     ["nqtsreq"]),
    ("data-records", "Data records: sources, schemas, drift and the environment",
     "What a capsule says of its data: where each file came from, the schema of its tables, summaries that show drift later, the environment of the run, and commitments.",
     ["nqdata", "nqdaddr", "nqschema", "nqdpin", "nqdparse", "nqdenv", "nqdcommit"]),
    ("the-library", "The library: algorithms, version and self-test",
     "Which algorithms the bundled library has and their sizes, its version, and the known-answer test that shows it computes them correctly.",
     ["nqalgs", "nqver", "nqselftest"]),
]

HEAD = '''---
title: "{title}"
output: rmarkdown::html_vignette
vignette: >
  %\\VignetteIndexEntry{{{title}}}
  %\\VignetteEngine{{knitr::rmarkdown}}
  %\\VignetteEncoding{{UTF-8}}
---

```{{r, include = FALSE}}
# the vignette runs in full in GitHub CI and for the package tarball (NOT_CRAN),
# on r-universe (MY_UNIVERSE), on the package website (IN_PKGDOWN) and in an
# interactive session; when CRAN re-builds it in its check, none of these is set
# and only this chunk runs
if (!interactive() &&
      !any(nzchar(Sys.getenv(c("NOT_CRAN", "MY_UNIVERSE", "IN_PKGDOWN"))))) {{
  knitr::knit_exit()
}}
knitr::opts_chunk$set(collapse = TRUE, comment = "#>")
options(width = 88)
library(noqtis)
```

{lead}

Each section is one help page: what its functions are for, and the example
of the page as it runs. `?name` gives the arguments and the value in full.

'''

want = [p for g in GROUPS for p in g[3]]
assert sorted(want) == sorted(n for n in pages if not n.endswith("-package")), (
    "help pages and GROUPS differ", sorted(set(want) ^ {n for n in pages if not n.endswith("-package")}))
exports = set(re.findall(r"^export\((.*)\)$", (repo / "NAMESPACE").read_text(), re.M))
shown = set()
for name, title, lead, names in GROUPS:
    body = []
    for n in names:
        p = pages[n]
        fns = [a for a in p["aliases"] if a in exports]
        shown |= set(fns)
        desc = re.sub("[‘’]", "`", p["desc"])
        body += ["## %s" % p["title"].rstrip("."), "",
                 "%s: %s" % (", ".join("`%s()`" % f for f in fns), desc), "",
                 "```{r %s}" % n, p["ex"], "```", ""]
    (repo / "vignettes" / (name + ".Rmd")).write_text(
        (HEAD.format(title=title, lead=lead) + "\n".join(body)).rstrip("\n") + "\n", encoding="utf-8")
    print("%-20s %d pages" % (name, len(names)))
print(len(GROUPS), "guides,", len(want), "help pages,", len(shown), "of", len(exports), "exports shown")
if exports - shown:
    print("NOT SHOWN:", " ".join(sorted(exports - shown)))
    sys.exit(1)
