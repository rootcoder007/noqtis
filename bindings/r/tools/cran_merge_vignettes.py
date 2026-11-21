# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Combines the guides of vignettes/ into five in the CRAN copy (run by
# tools/cran_build.sh inside the copy it builds from). R CMD check re-builds
# every vignette, and each one costs an R process, rmarkdown and pandoc even
# when it stops after its first chunk; five keep that step to a few seconds.
# The repository, r-universe and the website keep every guide. Each guide
# becomes a child document (vignettes/parts/_<name>.Rmd) of one of the five,
# and every vignette("<name>") in the guides and the README is pointed at
# the vignette that now holds it.
import os
import re

GROUPS = [
    ("noqtis", "noqtis: getting started, and the library itself",
     ["noqtis", "the-library"]),
    ("signatures-and-keys", "Signatures and keys",
     ["signatures", "keys", "mail-and-keys"]),
    ("encapsulation-and-hashes", "Key encapsulation, hashes and random bytes",
     ["key-encapsulation", "hashes-and-random"]),
    ("capsules-and-timestamps", "Capsules, timestamps and evidence records",
     ["capsules", "timestamps"]),
    ("data-records", "Data records: sources, schemas, drift and the environment",
     ["data-records"]),
]
GATE = ('# the vignette runs in full in GitHub CI and for the package tarball (NOT_CRAN), on r-universe\n'
        '# (MY_UNIVERSE), on the package website (IN_PKGDOWN) and in an interactive session; when CRAN\n'
        '# re-builds it in its check, none of these is set and only this chunk runs\n'
        'if (!interactive() && !any(nzchar(Sys.getenv(c("NOT_CRAN", "MY_UNIVERSE", "IN_PKGDOWN"))))) {\n'
        '  knitr::knit_exit()\n}\n'
        '# the guides were written apart: two may name a chunk alike\n'
        'options(knitr.duplicate.label = "allow")\n')
GATE_RE = re.compile(
    r"# the vignette runs in full in GitHub CI[\s\S]*?"
    r"knitr::knit_exit\(\)\s*\n\}\n")
where = {old: new for new, _, olds in GROUPS for old in olds}
have = sorted(f[:-4] for f in os.listdir("vignettes") if f.endswith(".Rmd"))
assert have == sorted(where), "vignettes/ and GROUPS differ: %s" % sorted(set(have) ^ set(where))


def relink(s):
    return re.sub(r'vignette\("([a-z-]+)"\)', lambda m: 'vignette("%s")' % where.get(m.group(1), m.group(1)), s)


os.makedirs("vignettes/parts", exist_ok=True)
for old in where:
    src = "vignettes/%s.Rmd" % old
    s = open(src, encoding="utf-8").read()
    m = re.match(r"---\n(.*?)\n---\n", s, re.S)
    assert m, old
    title = re.search(r"VignetteIndexEntry\{(.*)\}", m.group(1)).group(1)
    body = s[m.end():]
    # the gate as the guide writes it, however its lines are wrapped; the
    # walk-through written by hand has none and runs whole in its place
    hits = GATE_RE.findall(body)
    assert len(hits) == (0 if old == "noqtis" else 1), old
    body = relink(GATE_RE.sub("", body, count=1))
    # a section of a guide sits one level below the guide's own title
    body = re.sub(r"(?m)^(#{1,5}) ", r"#\1 ", body)
    open("vignettes/parts/_%s.Rmd" % old, "w", encoding="utf-8").write(
        "# %s\n%s" % (title, body if body.startswith("\n") else "\n" + body))
    os.remove(src)
for new, title, olds in GROUPS:
    parts = "\n".join('```{r child = "parts/_%s.Rmd"}\n```\n' % o for o in olds)
    open("vignettes/%s.Rmd" % new, "w", encoding="utf-8").write(
        '---\ntitle: "%s"\noutput:\n  rmarkdown::html_vignette:\n    toc: true\n    toc_depth: 2\nvignette: >\n'
        '  %%\\VignetteIndexEntry{%s}\n  %%\\VignetteEngine{knitr::rmarkdown}\n  %%\\VignetteEncoding{UTF-8}\n---\n\n'
        '```{r gate, include = FALSE}\n%s```\n\n%s' % (title, title, GATE, parts))
readme = open("README.md", encoding="utf-8").read()
open("README.md", "w", encoding="utf-8").write(relink(readme))
print("vignettes: %d guides as %d" % (len(where), len(GROUPS)))
