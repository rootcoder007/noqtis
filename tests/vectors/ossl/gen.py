#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# OpenSSL differential set for noqtis tests/tcls.c: keys and signatures
# made by openssl, plus mutated copies, each with openssl's own verdict.
# Usage: python3 -I gen.py <workdir> <out.json>
import json
import os
import random
import subprocess
import sys

work, out = sys.argv[1], sys.argv[2]
os.makedirs(work, exist_ok=True)
rnd = random.Random(20261028)
tests = []

P256N = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
P384N = int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
            "581a0db248b0a77aecec196accc52973", 16)


def run(*args, ok=(0,)):
    r = subprocess.run(args, capture_output=True)
    if r.returncode not in ok:
        sys.exit("failed: %s\n%s" % (" ".join(args), r.stderr.decode()))
    return r


def path(n):
    return os.path.join(work, n)


def wr(n, b):
    with open(path(n), "wb") as f:
        f.write(b)


def rd(n):
    with open(path(n), "rb") as f:
        return f.read()


def spki(key):
    run("openssl", "pkey", "-in", path(key), "-pubout", "-outform", "DER",
        "-out", path(key + ".spki"))
    run("openssl", "pkey", "-in", path(key), "-pubout", "-out",
        path(key + ".pub"))
    return rd(key + ".spki")


def opts(kind, hsh, slen):
    if kind != "pss":
        return []
    return ["-sigopt", "rsa_padding_mode:pss", "-sigopt",
            "rsa_pss_saltlen:%d" % slen, "-sigopt", "rsa_mgf1_md:" + hsh]


def sign(key, kind, hsh, slen, msg):
    wr("m", msg)
    run("openssl", "dgst", "-" + hsh, "-sign", path(key), *opts(kind, hsh, slen),
        "-out", path("s"), path("m"))
    return rd("s")


def verify(key, kind, hsh, slen, msg, sig):
    wr("m", msg)
    wr("s", sig)
    r = run("openssl", "dgst", "-" + hsh, "-verify", path(key + ".pub"),
            *opts(kind, hsh, slen), "-signature", path("s"), path("m"),
            ok=(0, 1))
    return r.returncode == 0


HN = {"sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
      "sha512": "SHA-512", "sha3-256": "SHA3-256", "sha512-256": "SHA-512/256"}


def add(kind, hsh, slen, sp, msg, sig, ok):
    t = {"type": kind, "hash": HN[hsh], "spki": sp.hex(), "msg": msg.hex(),
         "sig": sig.hex(), "ok": ok}
    if kind == "pss":
        t["mgf"] = HN[hsh]
        t["slen"] = slen
    tests.append(t)


def flip(b, i):
    b = bytearray(b)
    b[i // 8] ^= 1 << (i % 8)
    return bytes(b)


def case(key, sp, kind, hsh, slen):
    msg = os.urandom(rnd.choice([0, 1, 31, 64, 200, 1000]))
    sig = sign(key, kind, hsh, slen, msg)
    add(kind, hsh, slen, sp, msg, sig, verify(key, kind, hsh, slen, msg, sig))
    for _ in range(3):
        bad = flip(sig, rnd.randrange(8 * len(sig)))
        add(kind, hsh, slen, sp, msg, bad,
            verify(key, kind, hsh, slen, msg, bad))
    if msg:
        bad = flip(msg, rnd.randrange(8 * len(msg)))
        add(kind, hsh, slen, sp, bad, sig,
            verify(key, kind, hsh, slen, bad, sig))
    if kind == "pss":
        for sl in (slen + 1, max(slen - 1, 0)):
            if sl != slen:
                add(kind, hsh, sl, sp, msg, sig,
                    verify(key, kind, hsh, sl, msg, sig))
    return msg, sig


def der_int(v):
    b = v.to_bytes((v.bit_length() + 8) // 8, "big")
    return b"\x02" + bytes([len(b)]) + b


def der_sig(r, s, pad=False):
    a, b = der_int(r), der_int(s)
    if pad:
        a = b"\x02" + bytes([a[1] + 1]) + b"\x00" + a[2:]
    body = a + b
    return b"\x30" + bytes([len(body)]) + body


def parse_der(sig):
    assert sig[0] == 0x30
    i = 2
    out = []
    for _ in range(2):
        n = sig[i + 1]
        out.append(int.from_bytes(sig[i + 2:i + 2 + n], "big"))
        i += 2 + n
    return out


# ---- RSA ----
rsakeys = [(2048, 65537), (3072, 65537), (4096, 65537), (2048, 3),
           (3072, 3), (2049, 65537), (4095, 65537), (2048, 4294967295)]
for bits, e in rsakeys:
    key = "rsa%d_%d" % (bits, e)
    run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
        "rsa_keygen_bits:%d" % bits, "-pkeyopt",
        "rsa_keygen_pubexp:%d" % e, "-out", path(key))
    sp = spki(key)
    for hsh in ("sha256", "sha384", "sha512", "sha224", "sha3-256",
                "sha512-256"):
        case(key, sp, "pkcs1", hsh, 0)
        hl = {"sha224": 28, "sha256": 32, "sha384": 48, "sha512": 64,
              "sha3-256": 32, "sha512-256": 32}[hsh]
        for slen in (0, 20, hl):
            case(key, sp, "pss", hsh, slen)
    print(key, len(tests), flush=True)

# ---- ECDSA ----
for curve, n, nb in (("P-256", P256N, 32), ("P-384", P384N, 48)):
    key = "ec" + curve
    run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
        "ec_paramgen_curve:" + curve, "-out", path(key))
    sp = spki(key)
    for comp in (0, 1):
        if comp:
            run("openssl", "pkey", "-in", path(key), "-pubout", "-outform",
                "DER", "-ec_conv_form", "compressed", "-out",
                path(key + ".c"))
            sp = rd(key + ".c")
        for hsh in ("sha256", "sha384", "sha512", "sha224", "sha3-256"):
            for _ in range(4):
                msg, sig = case(key, sp, "ecdsa", hsh, 0)
                r, s = parse_der(sig)
                ok = verify(key, "ecdsa", hsh, 0, msg, sig)
                raw = r.to_bytes(nb, "big") + s.to_bytes(nb, "big")
                add("p1363", hsh, 0, sp, msg, raw, ok)
                # high s is valid ECDSA; non-minimal DER is not DER
                for v in (der_sig(r, n - s), der_sig(r, s, pad=True),
                          der_sig(r, s + n) if s + n < 1 << (8 * nb) else
                          der_sig(r + n, s)):
                    add("ecdsa", hsh, 0, sp, msg, v,
                        verify(key, "ecdsa", hsh, 0, msg, v))
    print(key, len(tests), flush=True)

with open(out, "w") as f:
    json.dump({"source": "OpenSSL " + run("openssl", "version").stdout
               .decode().strip(), "tests": tests}, f, indent=0)
print("tests", len(tests), "openssl ok",
      sum(1 for t in tests if t["ok"]))
