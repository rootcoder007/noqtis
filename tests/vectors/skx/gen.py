# SPDX-License-Identifier: LGPL-3.0-or-later
"""Writes kat.txt: known answers of the version 2 secret-key container
(docs/spec/keyfile.md, section 2), computed here from the specification
with Python's hashlib alone. S comes from keys.txt (the RFC 8032 section
7.1 test 1 Ed25519 key and its public key, and an ML-DSA-44 and an
SLH-DSA-SHAKE-128f key of fixed seeds, written by the library, whose
keys the ACVP tests check); X = S || P || T is computed here.

    python3 -I gen.py < keys.txt > kat.txt
"""
import hashlib
import sys


def tag(alg, s, p):
    return hashlib.sha3_256(b"noqtis-sk-2\x00" + alg.encode() + b"\x00" +
                            s + p).digest()


print("# The version 2 secret-key container: known answers written by")
print("# gen.py from docs/spec/keyfile.md with hashlib. alg, S (the key),")
print("# P (the Ed25519 public key, empty otherwise) and X = S || P || T.")
for line in sys.stdin:
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    alg, s, p = (line.split() + [""])[:3]
    if p == "-":
        p = ""
    sb, pb = bytes.fromhex(s), bytes.fromhex(p)
    x = sb + pb + tag(alg, sb, pb)
    print("alg %s" % alg)
    print("S %s" % s)
    print("P %s" % (p or "-"))
    print("X %s" % x.hex())
