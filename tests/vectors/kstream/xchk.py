# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Opens every ML-KEM-768 and ML-KEM-1024 record of kat.txt without
# noqtis: the key pair from the 64-byte seed d || z and the shared
# secret from Python's cryptography package (which has no ML-KEM-512),
# HKDF-SHA-256 and ChaCha20-Poly1305 from the same package, SHA3-256
# from hashlib, the chunks as noqtis-kstream-1 lays them out; prints one
# line per record and exits 1 when one does not open to its message.
#   python3 -I xchk.py kat.txt
import hashlib
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SETS = {"ML-KEM-768": (mlkem.MLKEM768PrivateKey, 2, 1088),
        "ML-KEM-1024": (mlkem.MLKEM1024PrivateKey, 3, 1568)}


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


bad = n = 0
for r in records(sys.argv[1]):
    if r["alg"] not in SETS:
        continue
    cls, alg, ctlen = SETS[r["alg"]]
    sk = cls.from_seed_bytes(bytes.fromhex(r["kseed"]))
    pk = sk.public_key().public_bytes_raw()
    out = bytes.fromhex(r["out"])
    ctx = bytes.fromhex(r["ctx"])
    hdr = out[:17 + ctlen]
    chunk = struct.unpack(">I", hdr[6:10])[0]
    ok = hdr[:6] == b"NQKF\x01" + bytes([alg])
    ss = sk.decapsulate(hdr[17:])
    info = (b"noqtis-kstream-1" + hashlib.sha3_256(pk).digest() +
            bytes([len(ctx)]) + ctx + hdr)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=info).derive(ss)
    aead = ChaCha20Poly1305(key)
    rest, i, msg = out[len(hdr):], 0, b""
    try:
        while True:
            last = len(rest) <= chunk + 16
            piece = rest if last else rest[:chunk + 16]
            nonce = hdr[10:17] + struct.pack(">I", i) + bytes([last])
            msg += aead.decrypt(nonce, piece, None)
            if last:
                break
            rest, i = rest[chunk + 16:], i + 1
        ok = ok and msg.hex() == r["msg"]
    except Exception:
        ok = False
    bad += not ok
    n += 1
    print("%s, %d bytes in %d chunks: %s" % (r["alg"], len(msg), i + 1,
                                           "opens" if ok else "DIFFERS"))
sys.exit(1 if bad or n == 0 else 0)
