---
title: Coming from rmoriebricklayer
description: The data provenance functions of rmoriebricklayer and its GitHub Action, and what does the same in NOQTIS.
---

rmoriebricklayer pinned data provenance (`data_provenance.json`) and
checked it in R, and its GitHub Action ran those checks in CI. NOQTIS
keeps the same information in the capsule's data record,
`noqtis.data.json`, which the post-quantum seal covers, and checks it
from the command line, C, R or Python. The cryptography (ML-DSA,
SLH-DSA, ML-KEM, SHA-2, SHA-3, RFC 3161) was already in NOQTIS; this
table is about data.

| rmoriebricklayer | NOQTIS |
|---|---|
| `loadprov`, `capsule_bundle.json` reading | `noqtis data show`, `nqdload`, `nqdata()` (R), `data.load` (Python) |
| `citecps` (citation from provenance) | the record's `cite` member (`noqtis data put <dir> cite`) |
| `recrd`, `recevid` (record cross-checks, correctness evidence) | `checks` elements (`noqtis data put <dir> checks`); a check recorded as `fail` fails `noqtis data check` |
| `rcdmnf`, `wrrcdmnf`, `vrfrcdmnf` (recode manifests) | `steps` elements with the mapping's SHA-256; the seal covers them |
| `infsch` (infer a schema) | `noqtis schema infer`, `nqdinfer`, `nqschema()` |
| `valsch`, `schval` (validate against a schema) | `noqtis schema check`, `nqdschk`, `nqschk()` |
| `rul`, `valrules`, `rulebtw`, `ruleinset`, `rulenull`, `ruleuniq`, `ruleincr`, `rulecmpl`, `ruledstn`, `rulecolcnt` | schema `rules`: `range`, `set`, `notnull`, `unique`, `incr`, `complete`, `distinct`, `cols`, `rows` |
| `rulerx`, `rulemad` | not yet: no regular expressions or outlier rule |
| `drftks`, `drftpsi`, `drftchisq`, `drfthomog`, `benfordtst`, `cpsdrft` | `noqtis drift check`, `nqddrift`, `nqdrift()`: KS, PSI, Jensen-Shannon, chi-square of homogeneity, Benford, from summaries kept in the record (no need to keep the old data) |
| `mnfdiff`, `envdiff` | `noqtis diff`, `nqddiff`, `nqdiff()` |
| `cpsseal`, `cpschk` (every capsule under a folder) | `noqtis seal -r`, `noqtis check -r` |
| `rmbl verify` | `noqtis check` and `noqtis data check` |
| `rmbl drift` | `noqtis drift check` (fetch the source first; the tool does not yet fetch it) |
| `mksyncsv`, `mksyncol` (synthetic data) | the `synthetic` flag of a source; generating data stays in R |
| `capenv`, `capdeps`, `mnfrecseed` | the record's `env` member (filled by hand or by a binding for now) |
| `ralloc`, `prrgdecl` | the record's `commits` member (format only so far) |

Not in NOQTIS on purpose: stateful XMSS signing (index reuse is fatal;
SLH-DSA covers hash-based signatures), the language-model helpers, the
Shiny and HTML interfaces, and the statistical procedures that belong
to an analysis package; their results go in as recorded `checks`.
