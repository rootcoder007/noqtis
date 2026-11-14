# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Writes kat.txt: BLAKE2b known answers from CPython's hashlib.blake2b,
# an implementation independent of noqtis's.
#   python3 -I gen.py > kat.txt
import hashlib
import sys

print("# BLAKE2b keyed and unkeyed known answers, for tests/tb2b.c.")
print("# Part 1: BLAKE2b-512, key 00 01 .. 3f (64 bytes), message 00 01 ..")
print("# (n-1) for n = 0 to 255: the inputs of the keyed KAT file of the")
print("# BLAKE2 reference implementation (blake2b-kat.txt).")
print("# Part 2: every output length 1 to 64, keys of 0, 1, 32 and 64 bytes")
print("# (i * 3 + 1 mod 256), message of 3 * outlen bytes (i * 5 mod 256).")
print("# Source: CPython %d.%d.%d hashlib.blake2b(msg, key=key, digest_size=n),"
      % sys.version_info[:3])
print("# written by tests/vectors/b2b/gen.py (python3 -I gen.py).")
print()
key = bytes(range(64))
for n in range(256):
    m = bytes(range(n))
    h = hashlib.blake2b(m, key=key, digest_size=64).hexdigest()
    print("in=%s\nkey=%s\nhash=%s\n" % (m.hex(), key.hex(), h))
for ol in range(1, 65):
    for kl in (0, 1, 32, 64):
        k = bytes((i * 3 + 1) % 256 for i in range(kl))
        m = bytes((i * 5) % 256 for i in range(3 * ol))
        h = hashlib.blake2b(m, key=k, digest_size=ol).hexdigest()
        print("in=%s\nkey=%s\nhash=%s\n" % (m.hex(), k.hex(), h))
