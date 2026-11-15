# Contributing to the noqtis R package

The R package lives in `bindings/r` of the noqtis repository, and the
guide for contributions is the repository's
[CONTRIBUTING.md](https://github.com/rootcoder007/noqtis/blob/main/CONTRIBUTING.md):
how to build and test, the style of code and commits, and how to report
a security issue. For the R package in particular, run
`R CMD check --as-cran` and `goodpractice::gp()` in `bindings/r` before
a change is sent; both must pass.
