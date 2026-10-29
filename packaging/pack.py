#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Packs a staged install tree into a reproducible release archive.

The same tree and SOURCE_DATE_EPOCH always give the same bytes: entries
are sorted by path, every entry carries the commit time as its mtime,
owner and group are 0 with no names, modes are 0755 for bin/ and shared
libraries and 0644 for the rest (whatever the build host's umask was),
and the gzip header has no file name and a zero time (as gzip -n).
Python's own tarfile and zipfile are used so that Linux, macOS and
Windows runners pack the same way without GNU tar.

  pack.py <stage dir> <out.tar.gz | out.zip>

<stage dir> holds exactly one directory, the archive's top directory.
"""
import gzip
import os
import stat
import sys
import tarfile
import time
import zipfile


def mode(rel):
    """The mode an entry gets, from its path only."""
    parts = rel.split("/")
    name = parts[-1]
    if len(parts) > 2 and parts[1] == "bin":
        return 0o755
    if ".so" in name or name.endswith(".dylib") or name.endswith(".dll"):
        return 0o755
    return 0o644


def walk(stage):
    """Every path under stage, relative and with '/', sorted."""
    out = []
    for root, dirs, files in os.walk(stage):
        for n in dirs + files:
            full = os.path.join(root, n)
            out.append(os.path.relpath(full, stage).replace(os.sep, "/"))
    return sorted(out)


def tgz(stage, dest, sde):
    with open(dest, "wb") as f:
        with gzip.GzipFile(filename="", mode="wb", fileobj=f,
                           compresslevel=9, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w",
                              format=tarfile.USTAR_FORMAT) as tar:
                for rel in walk(stage):
                    full = os.path.join(stage, rel)
                    ti = tarfile.TarInfo(rel)
                    ti.mtime = sde
                    ti.uid = ti.gid = 0
                    ti.uname = ti.gname = ""
                    if os.path.islink(full):
                        ti.type = tarfile.SYMTYPE
                        ti.linkname = os.readlink(full)
                        ti.mode = 0o777
                        tar.addfile(ti)
                    elif os.path.isdir(full):
                        ti.type = tarfile.DIRTYPE
                        ti.mode = 0o755
                        tar.addfile(ti)
                    else:
                        ti.size = os.path.getsize(full)
                        ti.mode = mode(rel)
                        with open(full, "rb") as src:
                            tar.addfile(ti, src)


def zipped(stage, dest, sde):
    # zip times are local DOS times from 1980 on; use the UTC fields
    when = time.gmtime(max(sde, 315532800))[:6]
    with zipfile.ZipFile(dest, "w") as z:
        for rel in walk(stage):
            full = os.path.join(stage, rel)
            if os.path.islink(full):
                sys.exit("pack.py: symbolic link in a zip tree: " + rel)
            if os.path.isdir(full):
                zi = zipfile.ZipInfo(rel + "/", when)
                zi.create_system = 3
                zi.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
                z.writestr(zi, b"")
                continue
            zi = zipfile.ZipInfo(rel, when)
            zi.create_system = 3
            zi.external_attr = (stat.S_IFREG | mode(rel)) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(full, "rb") as src:
                z.writestr(zi, src.read(), compresslevel=9)


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: pack.py <stage dir> <out.tar.gz|out.zip>")
    stage, dest = sys.argv[1], sys.argv[2]
    sde = os.environ.get("SOURCE_DATE_EPOCH")
    if not sde or not sde.isdigit():
        sys.exit("pack.py: set SOURCE_DATE_EPOCH (the commit time)")
    top = os.listdir(stage)
    if len(top) != 1 or not os.path.isdir(os.path.join(stage, top[0])):
        sys.exit("pack.py: the stage dir must hold one top directory")
    if dest.endswith(".tar.gz"):
        tgz(stage, dest, int(sde))
    elif dest.endswith(".zip"):
        zipped(stage, dest, int(sde))
    else:
        sys.exit("pack.py: the archive must end in .tar.gz or .zip")


if __name__ == "__main__":
    main()
