# Coming from rmoriebricklayer

rmoriebricklayer's provenance and capsule functions have counterparts in
noqtis, from the command line and from every binding. The data layer
(`noqtis data`, `schema`, `drift`, `src` and the `nqd*` functions) holds
what bricklayer kept in `data_provenance.json`.

| rmoriebricklayer | noqtis |
|---|---|
| `fetchvrf`, `fdl`, `dldata` | `noqtis src fetch` (the url, the portal, the mirrors, then the archived copy; only the recorded bytes are kept) |
| `cpsrfrsh`, `rmbl refresh` | `noqtis src refresh [--write]` |
| `rslvckan`, `rslvsoc`, `rslvarc` | `noqtis src add --portal ckan\|socrata\|arcgis`, `src resolve`; `nqdrslv(3)`, `nqdrsp(3)` |
| `wbsnpurl`, `wbsnpnat`, `rmbl wayback` | `noqtis src add --wayback`, `src resolve --wayback`; `nqdwb(3)` |
| `infsch`, `valsch`, `valrules` | `noqtis schema infer\|check` |
| `cpsdrft`, `drft*`, `drftcal` | `noqtis drift pin\|check\|cal` |
| `mnfdiff`, `envdiff` | `noqtis diff` |
| `capenv` | `noqtis env` |
| `ralloc`, `prrgdecl` and their checks | `noqtis commit`, `noqtis reveal`; the commitment is dated by sealing the capsule with a timestamp (`noqtis seal --tsa`), whose token covers the data record that holds it |
| `mkbndl`, `mkbndlproj`, `usecpstmpl`, `rmbl pack` | `noqtis pack init --template plain\|r\|python`, `pack build`, `pack check` (there is no separate `noqtis init`) |
| `chnkfile` | `noqtis chunk pin\|check` |
| `mksyncsv` | `noqtis data syn` (marked `synthetic`) |
| `hqccmpkey` | the HQC key-generation seed itself: keep the seed and make the key again with `noqtis keygen -a HQC-128 --seed <seed>` (`nqkkgd(3)`); there is no other compressed form |
| `rmbl-action` modes verify, drift, refresh, report | the action's `check`, `drift`, `refresh` and `report` modes, with `fail-on`, `base-ref` and `comment` ([CI guide](ci.md)) |
