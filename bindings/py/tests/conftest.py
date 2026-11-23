# SPDX-License-Identifier: LGPL-3.0-or-later
"""Shared paths: the repository (NQREPO, else three folders up), its
golden capsule, and the noqtis CLI (NQCLI, else PATH, else a build)."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(os.environ.get("NQREPO") or Path(__file__).resolve().parents[3])
GOLD = REPO / "tests" / "vectors" / "cap" / "sample"
GSEED = bytes(range(32))  # tests/tcap.c: mkkey(&m44, NQMLDSA44, 0, 0)
GTIME = "1793210645"      # 2026-10-28T18:04:05Z, the golden seal's time


def runs(c):
    # a CLI built for another system (a host build seen inside a wheel
    # container, say) does not count
    try:
        p = subprocess.run([c, "version"], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return p.returncode == 0


def cli():
    c = os.environ.get("NQCLI")
    if c:
        return c  # asked for: a broken one should fail, not skip
    want = [shutil.which("noqtis")]
    want += sorted(REPO.glob("build*/bin/noqtis*"))
    want += sorted(REPO.glob("build*/cli/noqtis*"))
    for b in want:
        if b and os.path.isfile(str(b)) and os.access(str(b), os.X_OK) \
                and runs(str(b)):
            return str(b)
    return None


@pytest.fixture
def gold(tmp_path):
    if not (GOLD / "noqtis.sig").is_file():
        pytest.skip("golden capsule not here (run inside the repository)")
    d = tmp_path / "sample"
    shutil.copytree(str(GOLD), str(d))
    return d


def kv(name):
    """The records of a key=value vector file under tests/vectors: a list
    of dicts, one per block between blank lines, comments dropped."""
    out, cur = [], {}
    with open(REPO / "tests" / "vectors" / name, encoding="ascii") as f:
        for ln in f:
            ln = ln.rstrip("\r\n")
            if ln.startswith("#"):
                continue
            if not ln:
                if cur:
                    out.append(cur)
                cur = {}
                continue
            k, v = ln.split("=", 1)
            cur[k] = v
    if cur:
        out.append(cur)
    return out
