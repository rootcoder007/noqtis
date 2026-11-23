# SPDX-License-Identifier: LGPL-3.0-or-later
#
# Makes the seed corpora of farm, fcms, fpgp and fkst with the Python
# package (bindings/py), each file named by its SHA-1 as libFuzzer names
# its own:
#   python3 fuzz/seed.py fuzz/corpus
# The keys are new on each run, so the files differ from run to run;
# the ones in fuzz/corpus are one run's.
import hashlib, pathlib, sys, tempfile
import noqtis
from noqtis import mail, pgp, store, sign, kem
top = pathlib.Path(sys.argv[1])
T0 = 1767225600
def put(t, b):
    if isinstance(b, str): b = b.encode()
    d = top / t; d.mkdir(exist_ok=True)
    (d / hashlib.sha1(b).hexdigest()).write_bytes(b)
msg = b"Content-Type: text/plain\r\n\r\nhello, fuzz\r\n"
# armor
put("farm", mail.armor("CERTIFICATE", b"\x30\x03\x02\x01\x01"))
put("farm", mail.armor("NOQTIS FUZZ", b""))
put("farm", mail.armor("X", bytes(range(100))))
for k in (pgp.MESSAGE, pgp.PUBLICKEY, pgp.PRIVATEKEY, pgp.SIGNATURE):
    put("farm", pgp.armor(k, bytes(range(50))))
put("farm", b"-----BEGIN A-----\n\n-----END A-----\n")
put("farm", b"\x00\x01\x02")
# certificates, CMS, S/MIME (ML-DSA-44 and ML-KEM-512, as the target)
pk, sk = sign.keygen("ML-DSA-44")
kpk, ksk = kem.keygen("ML-KEM-512")
cert = mail.selfcert("ML-DSA-44", sk, pk, "Fuzz Signer", "fuzz@example.org", notbefore=T0, notafter=T0 + 86400 * 365)
kc = mail.kemcert("ML-DSA-44", sk, cert, "ML-KEM-512", kpk, notbefore=T0, notafter=T0 + 86400 * 365)
put("fcms", cert); put("fcms", kc)
put("fcms", mail.cmssign("ML-DSA-44", sk, cert, msg, at=T0 + 60))
put("fcms", mail.cmssign("ML-DSA-44", sk, cert, msg, detached=True, at=T0 + 60))
put("fcms", mail.cmsencrypt([kc], msg))
put("fcms", mail.smimesign("ML-DSA-44", sk, cert, msg, detached=True, at=T0 + 60))
put("fcms", mail.smimesign("ML-DSA-44", sk, cert, msg, at=T0 + 60))
put("fcms", mail.smimeencrypt([kc], msg))
for i in range(4):  # an edit of each good message: which, offset, bytes
    put("fcms", bytes([i, 0, 40, 0xff]))
    put("fcms", bytes([i, 4, 0, 0x30, 0x80]))
# OpenPGP (Ed25519 with X25519, as the target)
m = b"a line\n- with a dash\nand the last\n"
sec, pub = pgp.generate("Fuzz <fuzz@example.org>", pgp.ED25519, pgp.X25519, created=T0)
put("fpgp", pub); put("fpgp", sec)
for mode in (pgp.INLINE, pgp.DETACHED, pgp.CLEAR):
    put("fpgp", pgp.sign(sec, m, mode, at=T0 + 60))
put("fpgp", pgp.encrypt(m, [pub], signer=sec))
for i in range(4):
    put("fpgp", bytes([i, 0, 20, 0xff]))
    put("fpgp", bytes([i, 0, 2, 6, 6]))
# key store bundles and one certification
with tempfile.TemporaryDirectory() as d:
    card = noqtis.idcard(sk, pk, "Fuzz Owner", email="owner@example.org", at=T0)
    me = store.add(d, "ML-DSA-44", pk, card=card)
    own = store.add(d, "ML-KEM-512", kpk, "Fuzz Owner", "owner@example.org")
    store.trust(d, me, store.TRUST_ULTIMATE)
    c = store.certify(d, "ML-DSA-44", sk, pk, own, at=T0)
    put("fkst", store.export(d, me)); put("fkst", c); put("fkst", card)
put("fkst", bytes([0, 10, 0x7b]))
put("fkst", bytes([8, 0]) + b'"alg"')
print("ok")
