# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Writes kat.txt: known answers of capsule format 3 (noqtis-capsule(5),
section 16 of docs/spec/capsule.md), computed here from the specification
alone with Python's hashlib: the salts a fixed salt key gives, each
entry's leaf, the Merkle root, and the whole manifest a seal of these
files at a fixed time writes.

    python3 -I gen.py > kat.txt
"""
import hashlib

KEY = bytes(range(32))
CREATED = "2026-01-01T00:00:00Z"
FILES = [("a.txt", b"a\n"), ("data/b.csv", b"x,y\n1,2\n"),
         ("data/deep/c.bin", bytes(range(7)))]


def salt(path):
    return hashlib.sha3_256(b"noqtis-salt-3\x00" + KEY +
                            path.encode()).digest()


def entry(path, data):
    s = salt(path)
    return ('{"path":"%s","salt":"%s","sha256":"%s","sha3_256":"%s",'
            '"size":%d}' % (path, s.hex(), hashlib.sha256(data).hexdigest(),
                            hashlib.sha3_256(data).hexdigest(), len(data)))


def leaf(path, data):
    return hashlib.sha256(b"\x02" + salt(path) +
                          entry(path, data).encode()).digest()


def node(a, b):
    return hashlib.sha256(b"\x01" + a + b).digest()


def mth(lv):
    if len(lv) == 1:
        return lv[0]
    k = 1
    while k * 2 < len(lv):
        k *= 2
    return node(mth(lv[:k]), mth(lv[k:]))


FILES.sort(key=lambda f: f[0].encode())
lv = [leaf(p, d) for p, d in FILES]
root = mth(lv)
man = ('{"created":"%s","files":[%s],"format":"noqtis-capsule-3",'
       '"merkle":{"alg":"sha256","leaves":%d,"root":"%s"}}'
       % (CREATED, ",".join(entry(p, d) for p, d in FILES), len(FILES),
          root.hex()))
print("# Capsule format 3 known answers, written by gen.py from the")
print("# specification (docs/spec/capsule.md section 16) with hashlib.")
print("# key: the salt key; file: a path and its bytes in hex; salt and")
print("# leaf: per path; root: the Merkle root; manifest: noqtis.json of a")
print("# seal of the files at created, with the key.")
print("key %s" % KEY.hex())
print("created %s" % CREATED)
for p, d in FILES:
    print("file %s %s" % (p, d.hex()))
for p, d in FILES:
    print("salt %s %s" % (p, salt(p).hex()))
for (p, d), l in zip(FILES, lv):
    print("leaf %s %s" % (p, l.hex()))
print("root %s" % root.hex())
print("manifest %s" % man)
