# T2 SDE package

`package/security/noqtis` is the package for T2 SDE (t2sde.org, the source
tree at svn.exactcode.de `t2/trunk`, mirrored to github.com/rxrbln/t2sde), in
the layout of the T2 tree: copy `package/security/noqtis` into a T2 checkout
as it is.

It builds the release tarball with T2's CMake build (shared library, the
`noqtis` tool, the manual pages; no `-Werror`, which T2's compiler wrapper
removes anyway). The tests are off, as in every T2 package, unless the T2
configuration asks for checks (`SDECFG_DO_CHECK`); then the build runs them
with `make test`. The `[D]` checksum is T2's: the SHA-224 of the
decompressed tarball (`gzip -dc noqtis-X.Y.Z.tar.gz | sha224sum`).

To try it in a T2 tree (on T2, as root):

    cp -R packaging/community/t2/package/security/noqtis /usr/src/t2-src/package/security/
    cd /usr/src/t2-src
    scripts/Check-PkgFormat noqtis
    t2 install -optional-deps=no noqtis

The `t2` job in `.github/workflows/pkgs.yml` runs `ci.sh` in the root file
system of a T2 ISO (T2 publishes no container image), on x86-64 and arm64:
it checks the `.desc`, downloads the tarball from the `[D]` URL (checking
the checksum), builds the build dependencies the `.cache` names, then the
package with `Emerge-Pkg` (printing the `.cache` that build writes), then the
package again with `SDECFG_DO_CHECK`, so that the build runs the noqtis
tests, and builds a program against the installed package. It changes one line of the T2 tree: the ISOs carry no cmake, and
`cmake.desc` cannot bootstrap cmake without one (a T2 bug, see `ci.sh`).
Last, it builds this tree with T2's gcc at `-O2` and at `-Os` with
`-Werror`, which T2's compiler wrapper otherwise removes, and runs the tests.

At a release, `[V]` and the `[D]` line move with the other community
recipes (`packaging/vercheck.sh` fails while `[V]` or the `[D]` file name
lags them); the new checksum is the line T2's `scripts/Download -mk-cksum`
prints for the new tarball.

Status: not yet submitted to T2.
