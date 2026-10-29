# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Builds the noqtis extension: the C library (vendor/src) as a static
library with the flags the CMake build uses, then the abi3 module on it.

In the repository, vendor/ is a fresh copy of ../../src and
../../include made here, so the sdist carries the sources it was built
from; an unpacked sdist builds from its own vendor/.
"""
import os
import re
import shutil
import sys

from setuptools import Extension, setup

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
VEN = os.path.join(HERE, "vendor")


def inrepo():
    # the repo layout, and this very file inside it
    me = os.path.join(ROOT, "bindings", "py", "setup.py")
    return (os.path.isfile(os.path.join(ROOT, "include", "noqtis.h"))
            and os.path.isdir(os.path.join(ROOT, "src", "core"))
            and os.path.isfile(me)
            and os.path.samefile(me, os.path.abspath(__file__)))


def vendor():
    if not inrepo():
        if not os.path.isfile(os.path.join(VEN, "include", "noqtis.h")):
            sys.exit("noqtis: vendor/ is missing and ../../src is not here")
        return
    if os.path.isdir(VEN):
        shutil.rmtree(VEN)
    os.makedirs(VEN)
    for d in ("src", "include"):
        shutil.copytree(os.path.join(ROOT, d), os.path.join(VEN, d),
                        ignore=shutil.ignore_patterns("*.o", "*~"))
    for f in ("LICENSE", "NOTICE"):
        shutil.copyfile(os.path.join(ROOT, f), os.path.join(HERE, f))


def version():
    with open(os.path.join(VEN, "include", "noqtis.h"), encoding="utf-8") as f:
        h = f.read()
    v = [re.search(r"#define NQV%s (\d+)" % k, h).group(1)
         for k in ("MAJ", "MIN", "PAT")]
    return ".".join(v)


def sources():
    # every module is a folder under src/; its .c files make the library
    # (the same set CMake's src/*/*.c glob takes), in a fixed order
    out = []
    sd = os.path.join("vendor", "src")
    for mod in sorted(os.listdir(os.path.join(HERE, sd))):
        p = os.path.join(sd, mod)
        if os.path.isdir(os.path.join(HERE, p)):
            out += [os.path.join(p, f).replace(os.sep, "/")
                    for f in sorted(os.listdir(os.path.join(HERE, p)))
                    if f.endswith(".c")]
    return out


vendor()
WIN = sys.platform == "win32"
MAC = sys.platform == "darwin"
INC = ["vendor/include", "vendor/src"]
if WIN:
    cflags = ["/std:c11", "/W3"]
    defs = [("_CRT_SECURE_NO_WARNINGS", None), ("NQBUILD", None)]
else:
    # -O3 from sysconfig; no debug info in the wheels
    cflags = ["-std=c11", "-fvisibility=hidden", "-g0"]
    defs = [("NQBUILD", None)]

# the module exports PyInit__noqtis only: the library's NQAPI symbols stay
# inside it, so another noqtis in the process cannot interpose on them
if MAC:
    ldx = ["-Wl,-exported_symbol,_PyInit__noqtis"]
elif WIN:
    ldx = []
else:
    ldx = ["-Wl,--version-script=" + os.path.join(HERE, "src", "nq.map")]

setup(
    version=version(),
    libraries=[("nqlib", {"sources": sources(), "include_dirs": INC,
                          "macros": defs, "cflags": cflags})],
    ext_modules=[Extension(
        "noqtis._noqtis",
        sources=["src/ext.c"],
        include_dirs=INC,
        define_macros=[("Py_LIMITED_API", "0x03090000")],
        extra_compile_args=[] if WIN else ["-g0"],
        extra_link_args=ldx,
        libraries=["bcrypt"] if WIN else [],
        py_limited_api=True,
    )],
    options={"bdist_wheel": {"py_limited_api": "cp39"}},
)
