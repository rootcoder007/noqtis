#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
"""Writes the community recipes of one release.

In this tree the recipes carry the version 0.0.0 and a name (FILL_...) where
a checksum goes, so that no commit has to follow a release. This script
fills them in from the files of the release, and the result is what is sent
to each outside repository.

    python3 packaging/community/fill.py VERSION DIR OUT

DIR holds noqtis-VERSION.tar.gz, noqtis-VERSION-windows-x86_64.zip,
noqtis-VERSION-windows-arm64.zip and noqtis-VERSION-github.tar.gz, the
archive GitHub makes of the tag (github.com/.../archive/refs/tags/vVERSION
.tar.gz), which vcpkg and nixpkgs fetch instead of the release tarball.
OUT is made: a copy of this directory with every recipe filled in.

With --names it prints each FILL_ name and its value and writes nothing.
Standard library only.
"""
import base64
import gzip
import hashlib
import os
import re
import shutil
import stat
import struct
import sys
import tarfile
import tempfile

VER = re.compile(r"(^|[^0-9.])0\.0\.0(?=\.?(?:[^0-9.]|$))", re.M)


def digest(kind, path):
    h = hashlib.new(kind)
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def nar(root):
    """The hash nixpkgs' fetchFromGitHub wants: SHA-256 of the tree as a Nix
    archive (names in byte order, the executable bit, symlinks by target)."""
    h = hashlib.sha256()

    def s(b):
        if isinstance(b, str):
            b = b.encode()
        h.update(struct.pack("<Q", len(b)))
        h.update(b)
        h.update(b"\0" * (-len(b) % 8))

    def node(p):
        st = os.lstat(p)
        s("(")
        s("type")
        if stat.S_ISLNK(st.st_mode):
            s("symlink")
            s("target")
            s(os.readlink(p))
        elif stat.S_ISDIR(st.st_mode):
            s("directory")
            for n in sorted(os.listdir(os.fsencode(p))):
                s("entry")
                s("(")
                s("name")
                s(n)
                s("node")
                node(os.path.join(os.fsencode(p), n))
                s(")")
        else:
            s("regular")
            if st.st_mode & 0o100:
                s("executable")
                s("")
            s("contents")
            h.update(struct.pack("<Q", st.st_size))
            with open(p, "rb") as f:
                for b in iter(lambda: f.read(1 << 20), b""):
                    h.update(b)
            h.update(b"\0" * (-st.st_size % 8))
        s(")")

    s("nix-archive-1")
    node(root)
    return "sha256-" + base64.b64encode(h.digest()).decode()


def values(v, d):
    def f(tail):
        p = os.path.join(d, "noqtis-%s%s" % (v, tail))
        if not os.path.isfile(p):
            sys.exit("fill.py: %s is not there" % p)
        return p

    src, w64, wa64, gh = (f(".tar.gz"), f("-windows-x86_64.zip"),
                          f("-windows-arm64.zip"), f("-github.tar.gz"))
    with gzip.open(src, "rb") as g:
        h224 = hashlib.sha224()
        for b in iter(lambda: g.read(1 << 20), b""):
            h224.update(b)
    with tarfile.open(gh) as t, tempfile.TemporaryDirectory() as tmp:
        commit = t.pax_headers.get("comment", "")
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            sys.exit("fill.py: %s does not name its commit" % gh)
        try:
            t.extractall(tmp, filter="tar")
        except TypeError:  # Python before 3.12
            t.extractall(tmp)
        tops = os.listdir(tmp)
        if len(tops) != 1:
            sys.exit("fill.py: %s has more than one top directory" % gh)
        nix = nar(os.path.join(tmp, tops[0]))
    x, a = digest("sha256", w64), digest("sha256", wa64)
    return {
        "FILL_SRC_SHA256": digest("sha256", src),
        "FILL_SRC_SHA512": digest("sha512", src),
        "FILL_SRC_SHA224D": h224.hexdigest(),
        "FILL_WIN64_SHA256U": x.upper(),
        "FILL_WIN64_SHA256": x,
        "FILL_ARM64_SHA256U": a.upper(),
        "FILL_ARM64_SHA256": a,
        "FILL_GH_SHA512": digest("sha512", gh),
        "FILL_NIX_HASH": nix,
        "FILL_COMMIT": commit,
    }


def main():
    args = [a for a in sys.argv[1:] if a != "--names"]
    names = "--names" in sys.argv[1:]
    if len(args) != (2 if names else 3):
        sys.exit("usage: fill.py [--names] VERSION DIR [OUT]")
    v, d = args[0], args[1]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", v):
        sys.exit("fill.py: %s is not a version" % v)
    val = values(v, d)
    if names:
        for k in val:
            print(k, val[k])
        return
    out = args[2]
    here = os.path.dirname(os.path.abspath(__file__))
    shutil.copytree(here, out, symlinks=True)
    os.remove(os.path.join(out, "fill.py"))
    # the longer name first where one starts with another (..._SHA256U)
    keys = sorted(val, key=len, reverse=True)
    for root, dirs, files in os.walk(out, topdown=False):
        for n in files:
            p = os.path.join(root, n)
            with open(p, encoding="utf-8", newline="") as f:
                s = f.read()
            t = s
            for k in keys:
                t = t.replace(k, val[k])
            t = VER.sub(lambda m: m.group(1) + v, t)
            if t != s:
                with open(p, "w", encoding="utf-8", newline="") as f:
                    f.write(t)
        for n in files + dirs:
            if "0.0.0" in n:
                os.rename(os.path.join(root, n),
                          os.path.join(root, n.replace("0.0.0", v)))
    left = []
    for root, dirs, files in os.walk(out):
        for n in files + dirs:
            p = os.path.join(root, n)
            if "0.0.0" in n:
                left.append(p)
            if n in files:
                with open(p, encoding="utf-8") as f:
                    for i, line in enumerate(f, 1):
                        if "FILL_" in line or VER.search(line):
                            left.append("%s:%d: %s" % (p, i, line.rstrip()))
    if left:
        sys.exit("fill.py: not filled in:\n" + "\n".join(left))
    print("fill.py: recipes of noqtis %s in %s" % (v, out))


if __name__ == "__main__":
    main()
