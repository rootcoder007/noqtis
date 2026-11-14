# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Recomputes every record of kat.txt without noqtis: the salt is the
# first 16 bytes of SHAKE256(seed) (hashlib), the key and nonce Argon2id
# from OpenSSL's ARGON2ID KDF (openssl kdf), the body ChaCha20-Poly1305
# from Python's cryptography package; prints one line per record and
# exits 1 on any difference.
#   python3 -I xchk.py kat.txt
import hashlib
import struct
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def records(path):
    rec = {}
    for line in open(path):
        line = line.strip()
        if line.startswith("#"):
            continue
        if not line:
            if rec:
                yield rec
            rec = {}
            continue
        k, v = line.split("=", 1)
        rec[k] = v
    if rec:
        yield rec


def argon2id(pw, salt, t, m, p, n):
    out = subprocess.run(
        ["openssl", "kdf", "-keylen", str(n), "-kdfopt", "hexpass:" + pw.hex(),
         "-kdfopt", "hexsalt:" + salt.hex(), "-kdfopt", "iter:%d" % t,
         "-kdfopt", "memcost:%d" % m, "-kdfopt", "lanes:%d" % p,
         "-kdfopt", "threads:1", "ARGON2ID"],
        check=True, capture_output=True, text=True).stdout
    return bytes.fromhex(out.strip().replace(":", ""))


bad = 0
for i, r in enumerate(records(sys.argv[1])):
    m, t, p = int(r["m"]), int(r["t"]), int(r["p"])
    salt = hashlib.shake_256(bytes.fromhex(r["seed"])).digest(16)
    kn = argon2id(bytes.fromhex(r["pw"]), salt, t, m, p, 44)
    hdr = b"NQPW\x01\x01\x01" + struct.pack(">III", m, t, p) + salt
    body = ChaCha20Poly1305(kn[:32]).encrypt(
        kn[32:], bytes.fromhex(r["sk"]), hdr + bytes.fromhex(r["ad"]))
    ok = (hdr + body).hex() == r["out"]
    bad += not ok
    print("record %d (m %d, t %d, p %d): %s" % (i, m, t, p,
                                               "same" if ok else "DIFFERS"))
sys.exit(1 if bad else 0)
